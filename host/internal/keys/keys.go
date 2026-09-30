// Package keys manages the ephemeral key pair and certificate in the runtime directory.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/ssh"
)

const (
	KeyName  = "id_yessh"
	CertName = "id_yessh-cert.pub"
	PubName  = "id_yessh.pub"
	lockName = ".lock"
)

// Dir is the directory holding the ephemeral key material.
type Dir struct {
	Path     string
	Fallback bool // true if not on $XDG_RUNTIME_DIR (not tmpfs); callers should warn
}

// Resolve picks $YESSH_DIR, else $XDG_RUNTIME_DIR/yessh, else ~/.cache/yessh, and creates it 0700.
func Resolve() (Dir, error) {
	var d Dir
	switch {
	case os.Getenv("YESSH_DIR") != "":
		d.Path = os.Getenv("YESSH_DIR")
	case os.Getenv("XDG_RUNTIME_DIR") != "":
		d.Path = filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "yessh")
	default:
		cache, err := os.UserCacheDir()
		if err != nil {
			return d, err
		}
		d.Path, d.Fallback = filepath.Join(cache, "yessh"), true
	}
	if err := os.MkdirAll(d.Path, 0o700); err != nil {
		return d, err
	}
	if err := os.Chmod(d.Path, 0o700); err != nil {
		return d, err
	}
	return d, nil
}

func (d Dir) KeyPath() string  { return filepath.Join(d.Path, KeyName) }
func (d Dir) CertPath() string { return filepath.Join(d.Path, CertName) }
func (d Dir) PubPath() string  { return filepath.Join(d.Path, PubName) }

// Lock takes an exclusive advisory lock so concurrent `yessh ensure` runs (e.g. parallel ssh)
// produce one request, not many. Call the returned func to release.
func (d Dir) Lock() (func(), error) {
	f, err := os.OpenFile(filepath.Join(d.Path, lockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

// Pending is a freshly generated key pair that has not been installed yet.
type Pending struct {
	Public  ssh.PublicKey
	private ed25519.PrivateKey
}

// Generate creates a new ephemeral Ed25519 key pair in memory.
func Generate() (*Pending, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return &Pending{Public: sshPub, private: priv}, nil
}

// AuthorizedKey returns the public key as an OpenSSH line (no trailing newline).
func (p *Pending) AuthorizedKey() string {
	b := ssh.MarshalAuthorizedKey(p.Public)
	return string(b[:len(b)-1])
}

// Install writes the private key, public key and (already verified) certificate, replacing any
// previous ones. Each file is written to a temp file and renamed, so a crash leaves either the old
// or the new material; the key is renamed last-but-one and the cert last.
func (p *Pending) Install(d Dir, certLine string) error {
	block, err := ssh.MarshalPrivateKey(p.private, "yessh ephemeral")
	if err != nil {
		return err
	}
	// Remove the old cert first so a key/cert mismatch is never observable as "valid".
	if err := os.Remove(d.CertPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := writeAtomic(d.KeyPath(), pem.EncodeToMemory(block)); err != nil {
		return err
	}
	if err := writeAtomic(d.PubPath(), []byte(p.AuthorizedKey()+"\n")); err != nil {
		return err
	}
	return writeAtomic(d.CertPath(), []byte(certLine+"\n"))
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Current loads the installed certificate and checks that it certifies the installed private key.
// Returns fs.ErrNotExist (wrapped) if nothing is installed.
func Current(d Dir) (*ssh.Certificate, error) {
	certRaw, err := os.ReadFile(d.CertPath())
	if err != nil {
		return nil, err
	}
	keyRaw, err := os.ReadFile(d.KeyPath())
	if err != nil {
		return nil, err
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(certRaw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", d.CertPath(), err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("%s: not a certificate", d.CertPath())
	}
	signer, err := ssh.ParsePrivateKey(keyRaw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", d.KeyPath(), err)
	}
	if string(signer.PublicKey().Marshal()) != string(cert.Key.Marshal()) {
		return nil, errors.New("installed certificate does not match the installed key")
	}
	return cert, nil
}

// Forget deletes the key material. Missing files are not an error.
func Forget(d Dir) error {
	var errs []error
	for _, p := range []string{d.CertPath(), d.KeyPath(), d.PubPath()} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
