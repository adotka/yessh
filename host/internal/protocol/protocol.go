// Package protocol implements the yessh wire protocol: PSK-derived keys and topics,
// the AES-256-GCM envelope, request/response messages and the pairing string.
package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	Version = 1

	AADRequest  = "yessh1|req"
	AADResponse = "yessh1|resp"

	infoEnc       = "yessh1 enc"
	infoReqTopic  = "yessh1 req topic"
	infoRespTopic = "yessh1 resp topic"
	topicPrefix   = "yessh-r-"

	PairingPrefix = "yessh1:"

	StatusApproved = "approved"
	StatusDenied   = "denied"
)

var (
	b64url = base64.RawURLEncoding
	b32    = base32.StdEncoding.WithPadding(base32.NoPadding)

	// Labels end up in the certificate key id, so keep them boring.
	labelRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// Keys are the values both sides derive from the pairing PSK.
type Keys struct {
	EncKey    []byte
	ReqTopic  string
	RespTopic string
}

func hkdfBytes(psk []byte, info string, n int) []byte {
	out := make([]byte, n)
	if _, err := io.ReadFull(hkdf.New(sha256.New, psk, nil, []byte(info)), out); err != nil {
		panic(err) // cannot happen for n <= 255*32
	}
	return out
}

// Derive computes the encryption key and topic names from the PSK (HKDF-SHA256, empty salt).
func Derive(psk []byte) (Keys, error) {
	if len(psk) != 32 {
		return Keys{}, fmt.Errorf("psk must be 32 bytes, got %d", len(psk))
	}
	topic := func(info string) string {
		return topicPrefix + strings.ToLower(b32.EncodeToString(hkdfBytes(psk, info, 20)))
	}
	return Keys{
		EncKey:    hkdfBytes(psk, infoEnc, 32),
		ReqTopic:  topic(infoReqTopic),
		RespTopic: topic(infoRespTopic),
	}, nil
}

// Envelope is the ntfy message body.
type Envelope struct {
	V int    `json:"v"`
	N string `json:"n"`
	C string `json:"c"`
}

// Seal encrypts plaintext into a JSON envelope. nonce may be nil (random); fixed nonces are for test vectors.
func Seal(key []byte, aad string, plaintext, nonce []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if nonce == nil {
		nonce = make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("bad nonce size")
	}
	ct := gcm.Seal(nil, nonce, plaintext, []byte(aad))
	return json.Marshal(Envelope{V: Version, N: b64url.EncodeToString(nonce), C: b64url.EncodeToString(ct)})
}

// ErrDrop is returned for anything that is not a valid envelope for this key and direction.
// Callers must drop such messages silently.
var ErrDrop = errors.New("drop")

// Open decrypts a JSON envelope. Any failure yields ErrDrop.
func Open(key []byte, aad string, body []byte) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil || env.V != Version {
		return nil, ErrDrop
	}
	nonce, err1 := b64url.DecodeString(env.N)
	ct, err2 := b64url.DecodeString(env.C)
	if err1 != nil || err2 != nil || len(nonce) != 12 {
		return nil, ErrDrop
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, ErrDrop
	}
	pt, err := gcm.Open(nil, nonce, ct, []byte(aad))
	if err != nil {
		return nil, ErrDrop
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Request is sent host -> phone.
type Request struct {
	ID         string   `json:"id"`
	TS         int64    `json:"ts"`
	Label      string   `json:"label"`
	Who        string   `json:"who"`
	PubKey     string   `json:"pubkey"`
	Principals []string `json:"principals"`
	TTL        int64    `json:"ttl"`
}

// Response is sent phone -> host.
type Response struct {
	ID     string `json:"id"`
	TS     int64  `json:"ts"`
	Status string `json:"status"`
	Cert   string `json:"cert,omitempty"`
}

// NewID returns 16 random bytes, base64url.
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64url.EncodeToString(b), nil
}

// ValidLabel reports whether l is acceptable as a request label.
func ValidLabel(l string) bool { return labelRE.MatchString(l) }

// Pairing is the decoded pairing string.
type Pairing struct {
	V     int    `json:"v"`
	Ntfy  string `json:"ntfy"`
	PWA   string `json:"pwa"`
	PSK   string `json:"psk"`
	CA    string `json:"ca"`
	Token string `json:"token,omitempty"`
}

// PSKBytes decodes the PSK (base64url or standard base64, padding optional).
func (p Pairing) PSKBytes() ([]byte, error) {
	s := strings.TrimRight(p.PSK, "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	b, err := b64url.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("psk: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("psk must be 32 bytes, got %d", len(b))
	}
	return b, nil
}

// ParsePairing decodes "yessh1:<base64url(JSON)>".
func ParsePairing(s string) (Pairing, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, PairingPrefix) {
		return Pairing{}, errors.New("pairing string must start with " + PairingPrefix)
	}
	raw, err := b64url.DecodeString(strings.TrimRight(s[len(PairingPrefix):], "="))
	if err != nil {
		return Pairing{}, fmt.Errorf("pairing string: %w", err)
	}
	var p Pairing
	if err := json.Unmarshal(raw, &p); err != nil {
		return Pairing{}, fmt.Errorf("pairing string: %w", err)
	}
	if p.V != Version {
		return Pairing{}, fmt.Errorf("unsupported pairing version %d", p.V)
	}
	if !strings.HasPrefix(p.Ntfy, "https://") && !strings.HasPrefix(p.Ntfy, "http://") {
		return Pairing{}, errors.New("pairing: ntfy must be an http(s) URL")
	}
	if !strings.HasPrefix(p.CA, "ecdsa-sha2-nistp256 ") {
		return Pairing{}, errors.New("pairing: ca must be an ecdsa-sha2-nistp256 public key line")
	}
	if _, err := p.PSKBytes(); err != nil {
		return Pairing{}, err
	}
	return p, nil
}

// EncodePairing is the inverse of ParsePairing (used by tests and tooling).
func EncodePairing(p Pairing) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return PairingPrefix + b64url.EncodeToString(raw), nil
}
