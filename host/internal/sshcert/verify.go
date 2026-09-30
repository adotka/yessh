// Package sshcert verifies certificates returned by the phone before they are written to disk.
package sshcert

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// Skew is the backdate the phone applies to ValidAfter, and the slack allowed on ValidBefore.
const Skew = 60 * time.Second

// Expectation is what the host asked for.
type Expectation struct {
	CA         ssh.PublicKey // pinned CA key from config
	Key        ssh.PublicKey // ephemeral public key sent in the request
	Principals []string      // requested principals
	TTL        time.Duration // requested TTL
	Now        time.Time
}

// Parse parses an OpenSSH certificate line.
func Parse(line string) (*ssh.Certificate, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not a certificate")
	}
	return cert, nil
}

func sameKey(a, b ssh.PublicKey) bool {
	return a != nil && b != nil && bytes.Equal(a.Marshal(), b.Marshal())
}

// Verify parses the certificate line and checks it against what was requested.
// Any error means the certificate must not be written.
func Verify(line string, exp Expectation) (*ssh.Certificate, error) {
	cert, err := Parse(line)
	if err != nil {
		return nil, err
	}
	if !sameKey(cert.SignatureKey, exp.CA) {
		return nil, errors.New("cert: signed by an unexpected CA")
	}
	if !sameKey(cert.Key, exp.Key) {
		return nil, errors.New("cert: certifies a different public key")
	}
	if cert.CertType != ssh.UserCert {
		return nil, errors.New("cert: not a user certificate")
	}
	if len(cert.ValidPrincipals) == 0 {
		return nil, errors.New("cert: no principals (would be valid for any user)")
	}
	requested := map[string]bool{}
	for _, p := range exp.Principals {
		requested[p] = true
	}
	for _, p := range cert.ValidPrincipals {
		if !requested[p] {
			return nil, fmt.Errorf("cert: principal %q was not requested", p)
		}
	}
	if cert.ValidBefore == ssh.CertTimeInfinity || cert.ValidBefore > uint64(exp.Now.Add(exp.TTL+Skew).Unix()) {
		return nil, errors.New("cert: lifetime exceeds the requested TTL")
	}
	for name := range cert.CriticalOptions {
		if name != "source-address" {
			return nil, fmt.Errorf("cert: unexpected critical option %q", name)
		}
	}

	// Signature, validity window and principal membership.
	checker := ssh.CertChecker{
		IsUserAuthority:          func(auth ssh.PublicKey) bool { return sameKey(auth, exp.CA) },
		SupportedCriticalOptions: []string{"source-address"},
		Clock:                    func() time.Time { return exp.Now },
	}
	if err := checker.CheckCert(cert.ValidPrincipals[0], cert); err != nil {
		return nil, fmt.Errorf("cert: %w", err)
	}
	return cert, nil
}

// Remaining returns how long the certificate stays valid at now (<= 0 if expired or not yet valid).
func Remaining(cert *ssh.Certificate, now time.Time) time.Duration {
	if uint64(now.Unix()) < cert.ValidAfter {
		return 0
	}
	if cert.ValidBefore == ssh.CertTimeInfinity {
		return time.Duration(1<<63 - 1)
	}
	return time.Unix(int64(cert.ValidBefore), 0).Sub(now)
}
