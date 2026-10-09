package sshcert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var now = time.Unix(1790000000, 0)

func ecdsaSigner(t *testing.T) ssh.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func edPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type fixture struct {
	ca   ssh.Signer
	key  ssh.PublicKey
	cert *ssh.Certificate
}

func newFixture(t *testing.T) fixture {
	f := fixture{ca: ecdsaSigner(t), key: edPub(t)}
	f.cert = &ssh.Certificate{
		Key:             f.key,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "yessh:test:id",
		ValidPrincipals: []string{"root"},
		ValidAfter:      uint64(now.Add(-Skew).Unix()),
		ValidBefore:     uint64(now.Add(time.Hour).Unix()),
		Permissions:     ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	return f
}

func (f fixture) line(t *testing.T, signer ssh.Signer) string {
	t.Helper()
	if err := f.cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(f.cert))
}

func (f fixture) exp() Expectation {
	return Expectation{CA: f.ca.PublicKey(), Key: f.key, Principals: []string{"root", "deploy"}, TTL: time.Hour, Now: now}
}

func TestVerifyAcceptsGood(t *testing.T) {
	f := newFixture(t)
	cert, err := Verify(f.line(t, f.ca), f.exp())
	if err != nil {
		t.Fatal(err)
	}
	if got := Remaining(cert, now); got != time.Hour {
		t.Errorf("Remaining = %v", got)
	}
}

func TestVerifyRejects(t *testing.T) {
	cases := map[string]func(t *testing.T, f *fixture, e *Expectation) string{
		"wrong CA": func(t *testing.T, f *fixture, e *Expectation) string {
			return f.line(t, ecdsaSigner(t))
		},
		"wrong key": func(t *testing.T, f *fixture, e *Expectation) string {
			e.Key = edPub(t)
			return f.line(t, f.ca)
		},
		"extra principal": func(t *testing.T, f *fixture, e *Expectation) string {
			f.cert.ValidPrincipals = []string{"root", "admin"}
			return f.line(t, f.ca)
		},
		"no principals": func(t *testing.T, f *fixture, e *Expectation) string {
			f.cert.ValidPrincipals = nil
			return f.line(t, f.ca)
		},
		"excess TTL": func(t *testing.T, f *fixture, e *Expectation) string {
			f.cert.ValidBefore = uint64(now.Add(time.Hour + Skew + time.Second).Unix())
			return f.line(t, f.ca)
		},
		"infinite": func(t *testing.T, f *fixture, e *Expectation) string {
			f.cert.ValidBefore = ssh.CertTimeInfinity
			return f.line(t, f.ca)
		},
		"host cert": func(t *testing.T, f *fixture, e *Expectation) string {
			f.cert.CertType = ssh.HostCert
			return f.line(t, f.ca)
		},
		"expired": func(t *testing.T, f *fixture, e *Expectation) string {
			e.Now = now.Add(2 * time.Hour)
			return f.line(t, f.ca)
		},
		"not yet valid": func(t *testing.T, f *fixture, e *Expectation) string {
			f.cert.ValidAfter = uint64(now.Add(10 * time.Minute).Unix())
			return f.line(t, f.ca)
		},
		"unknown critical option": func(t *testing.T, f *fixture, e *Expectation) string {
			f.cert.CriticalOptions = map[string]string{"force-command": "/bin/true"}
			return f.line(t, f.ca)
		},
		"tampered after signing": func(t *testing.T, f *fixture, e *Expectation) string {
			f.line(t, f.ca)
			f.cert.KeyId = "yessh:other:id" // signature no longer covers this
			return string(ssh.MarshalAuthorizedKey(f.cert))
		},
		"plain key": func(t *testing.T, f *fixture, e *Expectation) string {
			return string(ssh.MarshalAuthorizedKey(f.key))
		},
		"garbage": func(t *testing.T, f *fixture, e *Expectation) string { return "ssh-ed25519-cert-v01@openssh.com AAAA" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			e := f.exp()
			line := mut(t, &f, &e)
			if _, err := Verify(line, e); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestSourceAddressAllowed(t *testing.T) {
	f := newFixture(t)
	f.cert.CriticalOptions = map[string]string{"source-address": "10.0.0.0/8"}
	if _, err := Verify(f.line(t, f.ca), f.exp()); err != nil {
		t.Fatal(err)
	}
}

// Certificates built by the phone implementation:
//   - testdata/kotlin-cert.json: android core tests with YESSH_UPDATE_FIXTURES=1
func TestVerifiesForeignCerts(t *testing.T) {
	for _, name := range []string{"kotlin-cert.json"} {
		t.Run(name, func(t *testing.T) { verifyFixture(t, "testdata/"+name) })
	}
}

func verifyFixture(t *testing.T, path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		CA, Key, Cert string
		Principals    []string
		TTL, Now      int64
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	parse := func(s string) ssh.PublicKey {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	exp := Expectation{CA: parse(fx.CA), Key: parse(fx.Key), Principals: fx.Principals, TTL: time.Duration(fx.TTL) * time.Second, Now: time.Unix(fx.Now, 0)}
	cert, err := Verify(fx.Cert, exp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cert.KeyId, "yessh:") {
		t.Errorf("key id %q", cert.KeyId)
	}
	// Flip one base64 char in the signature region: must fail.
	b := []byte(fx.Cert)
	i := strings.LastIndexByte(fx.Cert, ' ') - 10
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	if _, err := Verify(string(b), exp); err == nil {
		t.Fatal("tampered cert accepted")
	}
}
