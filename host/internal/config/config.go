// Package config loads and stores ~/.config/yessh/config.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/adotka/yessh/host/internal/protocol"
)

// Config is what `yessh pair` writes. It contains the PSK, so it is stored 0600.
type Config struct {
	V     int    `json:"v"`
	Ntfy  string `json:"ntfy"`
	PWA   string `json:"pwa"`
	PSK   string `json:"psk"`
	CA    string `json:"ca"`
	Token string `json:"token,omitempty"`
}

// FromPairing converts a pairing string payload into a config.
func FromPairing(p protocol.Pairing) Config {
	return Config{V: p.V, Ntfy: p.Ntfy, PWA: p.PWA, PSK: p.PSK, CA: p.CA, Token: p.Token}
}

// Path returns $YESSH_CONFIG, else $XDG_CONFIG_HOME/yessh/config.json, else ~/.config/yessh/config.json.
func Path() (string, error) {
	if p := os.Getenv("YESSH_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "yessh", "config.json"), nil
}

// ErrNotPaired is returned by Load when no config exists.
var ErrNotPaired = errors.New("not paired: run `yessh pair '<pairing string>'` first")

func Load() (Config, error) {
	path, err := Path()
	if err != nil {
		return Config{}, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Config{}, ErrNotPaired
	}
	if err != nil {
		return Config{}, err
	}
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		return Config{}, fmt.Errorf("%s is accessible by other users (mode %o); run chmod 600", path, st.Mode().Perm())
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := c.CAKey(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Save writes the config atomically with mode 0600 (directory 0700).
func Save(c Config) (string, error) {
	path, err := Path()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.json")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	return path, os.Rename(tmp.Name(), path)
}

// Keys derives the protocol keys from the stored PSK.
func (c Config) Keys() (protocol.Keys, error) {
	psk, err := protocol.Pairing{PSK: c.PSK}.PSKBytes()
	if err != nil {
		return protocol.Keys{}, err
	}
	return protocol.Derive(psk)
}

// CAKey parses the pinned CA public key.
func (c Config) CAKey() (ssh.PublicKey, error) {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.CA))
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	if k.Type() != ssh.KeyAlgoECDSA256 {
		return nil, fmt.Errorf("ca: unexpected key type %s", k.Type())
	}
	return k, nil
}
