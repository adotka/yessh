package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/adotka/yessh/host/internal/keys"
	"github.com/adotka/yessh/host/internal/protocol"
)

func sandbox(t *testing.T) (caSigner ssh.Signer, pairing string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("YESSH_CONFIG", filepath.Join(dir, "cfg", "config.json"))
	t.Setenv("YESSH_DIR", filepath.Join(dir, "run"))
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSigner, _ = ssh.NewSignerFromKey(k)
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	pairing, err := protocol.EncodePairing(protocol.Pairing{
		V: 1, Ntfy: "http://127.0.0.1:1", PWA: "https://pwa.example/",
		PSK: base64.RawURLEncoding.EncodeToString(psk),
		CA:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(caSigner.PublicKey()))) + " yessh-ca",
	})
	if err != nil {
		t.Fatal(err)
	}
	return caSigner, pairing
}

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestPairCAStatusForget(t *testing.T) {
	ca, pairing := sandbox(t)
	if code, _, stderr := runCLI("ca"); code != exitErr || !strings.Contains(stderr, "not paired") {
		t.Fatalf("ca before pair: %d %s", code, stderr)
	}
	if code, out, stderr := runCLI("pair", pairing); code != 0 || !strings.Contains(out, "ecdsa-sha2-nistp256") {
		t.Fatalf("pair: %d %s %s", code, out, stderr)
	}
	st, err := os.Stat(os.Getenv("YESSH_CONFIG"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode: %v %v", st.Mode(), err)
	}
	code, out, _ := runCLI("ca")
	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.PublicKey())))
	if code != 0 || !strings.HasPrefix(out, want) {
		t.Fatalf("ca: %d %q", code, out)
	}
	if code, _, stderr := runCLI("status"); code != exitErr || !strings.Contains(stderr, "no certificate") {
		t.Fatalf("status: %d %s", code, stderr)
	}

	// Install a cert by hand, then status and ensure should see it.
	installCert(t, ca, []string{"root"}, time.Hour)
	code, out, stderr := runCLI("status")
	if code != 0 || !strings.Contains(out, "Principals:   root") || !strings.Contains(out, "(valid)") {
		t.Fatalf("status: %d %s %s", code, out, stderr)
	}
	// ensure with a usable cert must not touch the network (ntfy URL is unreachable).
	if code, _, stderr := runCLI("ensure", "-p", "root"); code != 0 {
		t.Fatalf("ensure: %d %s", code, stderr)
	}
	// Asking for more remaining time than the cert has forces a request, which fails fast here.
	if code, _, _ := runCLI("ensure", "-p", "root", "--min-remaining", "2h", "--timeout", "2s"); code == 0 {
		t.Fatal("ensure should have tried to request")
	}
	if code, _, _ := runCLI("forget"); code != 0 {
		t.Fatal("forget")
	}
	if code, _, _ := runCLI("status"); code == 0 {
		t.Fatal("status after forget")
	}
}

func TestUsage(t *testing.T) {
	if code, _, _ := runCLI(); code != exitUsage {
		t.Fatal(code)
	}
	if code, _, _ := runCLI("bogus"); code != exitUsage {
		t.Fatal(code)
	}
	if code, _, _ := runCLI("pair", "yessh1:bad"); code != exitErr {
		t.Fatal(code)
	}
}

func TestParseTTL(t *testing.T) {
	for in, want := range map[string]time.Duration{"3600": time.Hour, "90m": 90 * time.Minute, "4h": 4 * time.Hour} {
		if got, err := parseTTL(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	if !protocol.ValidLabel(defaultLabel()) {
		t.Errorf("default label %q invalid", defaultLabel())
	}
}

func installCert(t *testing.T, ca ssh.Signer, principals []string, ttl time.Duration) {
	t.Helper()
	d, err := keys.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	p, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := &ssh.Certificate{
		Key: p.Public, CertType: ssh.UserCert, KeyId: "yessh:test:x", ValidPrincipals: principals,
		ValidAfter: uint64(now.Unix() - 60), ValidBefore: uint64(now.Add(ttl).Unix()),
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	if err := p.Install(d, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(c)))); err != nil {
		t.Fatal(err)
	}
}
