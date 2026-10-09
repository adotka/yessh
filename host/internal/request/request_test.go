package request

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/adotka/yessh/host/internal/config"
	"github.com/adotka/yessh/host/internal/keys"
	"github.com/adotka/yessh/host/internal/ntfy"
	"github.com/adotka/yessh/host/internal/protocol"
)

// fakeNtfy is a tiny in-memory ntfy: POST /<topic>, GET /<topic>/json?since=<unix|id>.
type fakeNtfy struct {
	mu      sync.Mutex
	msgs    []ntfy.Message
	cond    *sync.Cond
	headers []http.Header
}

func newFakeNtfy() *fakeNtfy {
	f := &fakeNtfy{}
	f.cond = sync.NewCond(&f.mu)
	return f
}

func (f *fakeNtfy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.URL.Path, "/")
	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.msgs = append(f.msgs, ntfy.Message{
			ID: strconv.Itoa(len(f.msgs) + 1), Time: time.Now().Unix(), Event: "message", Topic: path, Message: string(body),
		})
		f.headers = append(f.headers, r.Header.Clone())
		f.cond.Broadcast()
		f.mu.Unlock()
		return
	}
	topic, ok := strings.CutSuffix(path, "/json")
	if !ok {
		http.NotFound(w, r)
		return
	}
	since := r.URL.Query().Get("since")
	flusher := w.(http.Flusher)
	enc := json.NewEncoder(w)
	_ = enc.Encode(ntfy.Message{Event: "open", Topic: topic})
	flusher.Flush()
	go func() { <-r.Context().Done(); f.mu.Lock(); f.cond.Broadcast(); f.mu.Unlock() }()
	next := 0
	f.mu.Lock()
	defer f.mu.Unlock()
	// Resolve `since`: unix time or message id; empty = only new messages.
	if since == "" {
		next = len(f.msgs)
	} else if n, err := strconv.ParseInt(since, 10, 64); err == nil && n > 1_000_000 {
		for next < len(f.msgs) && f.msgs[next].Time < n {
			next++
		}
	} else {
		for i, m := range f.msgs {
			if m.ID == since {
				next = i + 1
			}
		}
	}
	for r.Context().Err() == nil {
		for ; next < len(f.msgs); next++ {
			if f.msgs[next].Topic == topic {
				_ = enc.Encode(f.msgs[next])
			}
		}
		flusher.Flush()
		f.cond.Wait()
	}
}

// phone simulates the phone app with a Go ECDSA CA.
type phone struct {
	t      *testing.T
	keys   protocol.Keys
	ca     ssh.Signer
	nt     *ntfy.Client
	decide func(req protocol.Request) (protocol.Response, bool) // false = don't answer
}

func (p *phone) run(ctx context.Context) {
	sub := p.nt.Subscribe(ctx, p.keys.ReqTopic, "")
	<-sub.Opened
	go func() {
		for m := range sub.Messages {
			pt, err := protocol.Open(p.keys.EncKey, protocol.AADRequest, []byte(m.Message))
			if err != nil {
				continue
			}
			var req protocol.Request
			if err := json.Unmarshal(pt, &req); err != nil {
				p.t.Error(err)
				continue
			}
			resp, ok := p.decide(req)
			if !ok {
				continue
			}
			p.send(ctx, p.keys.EncKey, resp)
		}
	}()
}

func (p *phone) send(ctx context.Context, key []byte, resp protocol.Response) {
	b, _ := json.Marshal(resp)
	env, _ := protocol.Seal(key, protocol.AADResponse, b, nil)
	if err := p.nt.Publish(ctx, p.keys.RespTopic, env, nil); err != nil && ctx.Err() == nil {
		p.t.Error(err)
	}
}

func (p *phone) sign(req protocol.Request, signer ssh.Signer, mut func(c *ssh.Certificate)) string {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PubKey))
	if err != nil {
		p.t.Fatal(err)
	}
	now := time.Now()
	c := &ssh.Certificate{
		Key: pk, Serial: uint64(now.UnixMilli()), CertType: ssh.UserCert,
		KeyId: "yessh:" + req.Label + ":" + req.ID, ValidPrincipals: req.Principals,
		ValidAfter: uint64(now.Unix() - 60), ValidBefore: uint64(now.Unix() + req.TTL),
		Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	if mut != nil {
		mut(c)
	}
	if err := c.SignCert(rand.Reader, signer); err != nil {
		p.t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(c)))
}

func newSigner(t *testing.T) ssh.Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(k)
	return s
}

type env struct {
	cfg   config.Config
	nt    *ntfy.Client
	dir   keys.Dir
	phone *phone
	fake  *fakeNtfy
}

func setup(t *testing.T) *env {
	t.Helper()
	base := os.Getenv("YESSH_TEST_NTFY") // e.g. http://localhost:8080 to run against a real ntfy
	var fake *fakeNtfy
	if base == "" {
		fake = newFakeNtfy()
		srv := httptest.NewServer(fake)
		t.Cleanup(srv.Close)
		base = srv.URL
	}
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	pairing := protocol.Pairing{V: 1, Ntfy: base, PWA: "https://pwa.example/", PSK: base64.RawURLEncoding.EncodeToString(psk)}
	ca := newSigner(t)
	pairing.CA = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.PublicKey())))
	cfg := config.FromPairing(pairing)
	k, err := cfg.Keys()
	if err != nil {
		t.Fatal(err)
	}
	nt := &ntfy.Client{BaseURL: base}
	e := &env{
		cfg: cfg, nt: nt, dir: keys.Dir{Path: t.TempDir()}, fake: fake,
		phone: &phone{t: t, keys: k, ca: ca, nt: nt},
	}
	return e
}

func (e *env) run(t *testing.T, ctx context.Context, p Params) (*ssh.Certificate, error) {
	t.Helper()
	if p.Principals == nil {
		p.Principals = []string{"root"}
	}
	if p.TTL == 0 {
		p.TTL = time.Hour
	}
	if p.Label == "" {
		p.Label = "test"
	}
	p.Who = "tester@test"
	if p.Timeout == 0 {
		p.Timeout = 10 * time.Second
	}
	return Run(ctx, e.cfg, e.nt, e.dir, p)
}

func TestApproved(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var gotReq protocol.Request
	e.phone.decide = func(req protocol.Request) (protocol.Response, bool) {
		gotReq = req
		return protocol.Response{ID: req.ID, TS: time.Now().Unix(), Status: "approved", Cert: e.phone.sign(req, e.phone.ca, nil)}, true
	}
	e.phone.run(ctx)
	cert, err := e.run(t, ctx, Params{Principals: []string{"root", "deploy"}, TTL: 30 * time.Minute, Label: "mgmt-1"})
	if err != nil {
		t.Fatal(err)
	}
	if gotReq.TTL != 1800 || gotReq.Label != "mgmt-1" || len(gotReq.Principals) != 2 || time.Now().Unix()-gotReq.TS > 5 {
		t.Errorf("request = %+v", gotReq)
	}
	installed, err := keys.Current(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	if installed.Serial != cert.Serial {
		t.Error("installed cert differs")
	}
	for _, p := range []string{e.dir.KeyPath(), e.dir.CertPath()} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", p, st.Mode(), err)
		}
	}
	if e.fake != nil {
		h := e.fake.headers[0]
		if h.Get("Priority") != "high" || h.Get("Title") != "yessh request from mgmt-1" ||
			h.Get("Click") != "https://pwa.example/#/r/"+gotReq.ID {
			t.Errorf("headers: %v", h)
		}
		if strings.Contains(e.fake.msgs[0].Message, "root") {
			t.Error("request body is not encrypted")
		}
	}
}

func TestDenied(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.phone.decide = func(req protocol.Request) (protocol.Response, bool) {
		return protocol.Response{ID: req.ID, Status: "denied"}, true
	}
	e.phone.run(ctx)
	if _, err := e.run(t, ctx, Params{}); !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v", err)
	}
	assertNothingInstalled(t, e.dir)
}

func TestTimeout(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.phone.decide = func(req protocol.Request) (protocol.Response, bool) { return protocol.Response{}, false }
	e.phone.run(ctx)
	if _, err := e.run(t, ctx, Params{Timeout: 1500 * time.Millisecond}); !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
	assertNothingInstalled(t, e.dir)
}

func TestIgnoresNoiseThenAccepts(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wrong, _ := protocol.Derive(make([]byte, 32))
	e.phone.decide = func(req protocol.Request) (protocol.Response, bool) {
		// Wrong PSK (forged approval), wrong id, garbage, then the real one.
		e.phone.send(ctx, wrong.EncKey, protocol.Response{ID: req.ID, Status: "approved", Cert: e.phone.sign(req, newSigner(t), nil)})
		e.phone.send(ctx, e.phone.keys.EncKey, protocol.Response{ID: "other", Status: "denied"})
		_ = e.nt.Publish(ctx, e.phone.keys.RespTopic, []byte("hello"), nil)
		return protocol.Response{ID: req.ID, Status: "approved", Cert: e.phone.sign(req, e.phone.ca, nil)}, true
	}
	e.phone.run(ctx)
	if _, err := e.run(t, ctx, Params{}); err != nil {
		t.Fatal(err)
	}
}

func TestTamperedResponsesFailClosed(t *testing.T) {
	for name, mut := range map[string]func(p *phone, req protocol.Request) string{
		"wrong CA": func(p *phone, req protocol.Request) string { return p.sign(req, newSigner(t), nil) },
		"extra principal": func(p *phone, req protocol.Request) string {
			return p.sign(req, p.ca, func(c *ssh.Certificate) { c.ValidPrincipals = append(c.ValidPrincipals, "admin") })
		},
		"excess TTL": func(p *phone, req protocol.Request) string {
			return p.sign(req, p.ca, func(c *ssh.Certificate) { c.ValidBefore += 3600 })
		},
		"other key": func(p *phone, req protocol.Request) string {
			other, _ := keys.Generate()
			req.PubKey = other.AuthorizedKey()
			return p.sign(req, p.ca, nil)
		},
		"garbage": func(p *phone, req protocol.Request) string { return "ssh-ed25519 AAAA" },
	} {
		t.Run(name, func(t *testing.T) {
			e := setup(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			e.phone.decide = func(req protocol.Request) (protocol.Response, bool) {
				return protocol.Response{ID: req.ID, Status: "approved", Cert: mut(e.phone, req)}, true
			}
			e.phone.run(ctx)
			_, err := e.run(t, ctx, Params{})
			if err == nil || !strings.Contains(err.Error(), "rejected response") {
				t.Fatalf("err = %v", err)
			}
			assertNothingInstalled(t, e.dir)
		})
	}
}

func assertNothingInstalled(t *testing.T, d keys.Dir) {
	t.Helper()
	for _, p := range []string{d.KeyPath(), d.CertPath()} {
		if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s exists", p)
		}
	}
}
