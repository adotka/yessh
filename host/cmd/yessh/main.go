// Command yessh requests short-lived SSH user certificates from a phone-held CA.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/adotka/yessh/host/internal/config"
	"github.com/adotka/yessh/host/internal/keys"
	"github.com/adotka/yessh/host/internal/ntfy"
	"github.com/adotka/yessh/host/internal/protocol"
	"github.com/adotka/yessh/host/internal/request"
	"github.com/adotka/yessh/host/internal/sshcert"
)

const (
	exitOK      = 0
	exitErr     = 1
	exitTimeout = 2
	exitDenied  = 3
	exitUsage   = 64
)

const usage = `yessh: SSH certificates approved on your phone

Usage:
  yessh pair '<pairing string>'     store config from the PWA (type it yourself; it holds the PSK)
  yessh ca                          print the CA public key line (for TrustedUserCAKeys)
  yessh request [-p principal]... [-t ttl] [--label L] [--timeout d]
  yessh ensure  [-p principal]... [-t ttl] [--min-remaining d] [--label L] [--timeout d]
  yessh status                      show the current certificate
  yessh forget                      delete the ephemeral key and certificate

Exit codes: 0 ok, 1 error, 2 timeout, 3 denied.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	logf := func(format string, a ...any) { fmt.Fprintf(stderr, format+"\n", a...) }
	var err error
	switch args[0] {
	case "pair":
		err = cmdPair(args[1:], stdout)
	case "ca":
		err = cmdCA(stdout)
	case "request":
		err = cmdRequest(args[1:], false, stdout, logf)
	case "ensure":
		err = cmdRequest(args[1:], true, stdout, logf)
	case "status":
		err = cmdStatus(stdout)
	case "forget":
		err = cmdForget()
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "yessh: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, flag.ErrHelp):
		return exitUsage
	case errors.Is(err, request.ErrTimeout):
		logf("yessh: %v", err)
		return exitTimeout
	case errors.Is(err, request.ErrDenied):
		logf("yessh: %v", err)
		return exitDenied
	default:
		logf("yessh: %v", err)
		return exitErr
	}
}

func cmdPair(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: yessh pair '<pairing string>'")
	}
	p, err := protocol.ParsePairing(args[0])
	if err != nil {
		return err
	}
	cfg := config.FromPairing(p)
	if _, err := cfg.CAKey(); err != nil {
		return err
	}
	path, err := config.Save(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Wrote %s\nntfy: %s\nCA:   %s\nCheck that this CA line matches the one shown on your phone.\n", path, cfg.Ntfy, cfg.CA)
	return nil
}

func cmdCA(stdout io.Writer) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, strings.TrimSpace(cfg.CA))
	return nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// parseTTL accepts Go durations ("4h", "90m") or bare seconds.
func parseTTL(s string) (time.Duration, error) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(s)
}

type durFlag struct{ d *time.Duration }

func (f durFlag) String() string {
	if f.d == nil {
		return ""
	}
	return f.d.String()
}
func (f durFlag) Set(v string) error {
	d, err := parseTTL(v)
	if err != nil {
		return err
	}
	*f.d = d
	return nil
}

var labelJunk = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func defaultLabel() string {
	h, _ := os.Hostname()
	h = labelJunk.ReplaceAllString(strings.SplitN(h, ".", 2)[0], "-")
	if h == "" {
		h = "host"
	}
	if len(h) > 64 {
		h = h[:64]
	}
	return h
}

func defaultWho() string {
	name := "unknown"
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	h, _ := os.Hostname()
	who := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name+"@"+h)
	if len(who) > 128 {
		who = who[:128]
	}
	return who
}

func cmdRequest(args []string, ensure bool, stdout io.Writer, logf func(string, ...any)) error {
	name := "request"
	if ensure {
		name = "ensure"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	var principals multi
	ttl := time.Hour
	timeout := 120 * time.Second
	minRemaining := 10 * time.Minute
	fs.Var(&principals, "p", "principal to request (repeatable; default: $YESSH_PRINCIPALS or root)")
	fs.Var(durFlag{&ttl}, "t", "requested certificate lifetime (e.g. 1h, 30m, or seconds)")
	fs.Var(durFlag{&timeout}, "timeout", "how long to wait for approval")
	label := fs.String("label", defaultLabel(), "label shown on the phone")
	if ensure {
		fs.Var(durFlag{&minRemaining}, "min-remaining", "request a new cert if less than this is left")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if len(principals) == 0 {
		if env := os.Getenv("YESSH_PRINCIPALS"); env != "" {
			principals = strings.Split(env, ",")
		} else {
			principals = multi{"root"}
		}
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	dir, err := keys.Resolve()
	if err != nil {
		return err
	}
	if dir.Fallback {
		logf("yessh: warning: $XDG_RUNTIME_DIR is not set; storing the key in %s (not tmpfs)", dir.Path)
	}
	unlock, err := dir.Lock()
	if err != nil {
		return err
	}
	defer unlock()

	if ensure {
		ca, err := cfg.CAKey()
		if err != nil {
			return err
		}
		if cert, err := keys.Current(dir); err == nil && usable(cert, ca, principals, minRemaining) {
			return nil
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	nt := &ntfy.Client{BaseURL: cfg.Ntfy, Token: cfg.Token, Logf: logf}
	cert, err := request.Run(ctx, cfg, nt, dir, request.Params{
		Principals: principals, TTL: ttl, Label: *label, Who: defaultWho(), Timeout: timeout, Logf: logf,
	})
	if err != nil {
		return err
	}
	logf("yessh: certificate for %v valid until %s", cert.ValidPrincipals,
		time.Unix(int64(cert.ValidBefore), 0).Format(time.RFC3339))
	logf("yessh: %s", dir.CertPath())
	return nil
}

// usable reports whether an installed cert can be reused by `ensure`.
func usable(cert *ssh.Certificate, ca ssh.PublicKey, principals []string, minRemaining time.Duration) bool {
	if string(cert.SignatureKey.Marshal()) != string(ca.Marshal()) {
		return false
	}
	have := map[string]bool{}
	for _, p := range cert.ValidPrincipals {
		have[p] = true
	}
	for _, p := range principals {
		if !have[p] {
			return false
		}
	}
	return sshcert.Remaining(cert, time.Now()) >= minRemaining
}

func cmdStatus(stdout io.Writer) error {
	dir, err := keys.Resolve()
	if err != nil {
		return err
	}
	cert, err := keys.Current(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("no certificate")
	}
	if err != nil {
		return err
	}
	rem := sshcert.Remaining(cert, time.Now())
	state := "valid"
	if rem <= 0 {
		state = "EXPIRED"
	}
	fmt.Fprintf(stdout, "Certificate:  %s (%s)\n", dir.CertPath(), state)
	fmt.Fprintf(stdout, "Key ID:       %s\n", cert.KeyId)
	fmt.Fprintf(stdout, "Serial:       %d\n", cert.Serial)
	fmt.Fprintf(stdout, "Principals:   %s\n", strings.Join(cert.ValidPrincipals, ", "))
	fmt.Fprintf(stdout, "Valid until:  %s", time.Unix(int64(cert.ValidBefore), 0).Format(time.RFC3339))
	if rem > 0 {
		fmt.Fprintf(stdout, " (%s left)", rem.Truncate(time.Second))
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "Key:          %s\n", ssh.FingerprintSHA256(cert.Key))
	fmt.Fprintf(stdout, "CA:           %s\n", ssh.FingerprintSHA256(cert.SignatureKey))
	if rem <= 0 {
		return errors.New("certificate expired")
	}
	return nil
}

func cmdForget() error {
	dir, err := keys.Resolve()
	if err != nil {
		return err
	}
	return keys.Forget(dir)
}
