// Package request runs one certificate request round trip: generate an ephemeral key, publish
// the encrypted request, wait for the phone's response, verify the certificate and install it.
package request

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/adotka/yessh/host/internal/config"
	"github.com/adotka/yessh/host/internal/keys"
	"github.com/adotka/yessh/host/internal/ntfy"
	"github.com/adotka/yessh/host/internal/protocol"
	"github.com/adotka/yessh/host/internal/sshcert"
)

var (
	ErrTimeout = errors.New("timed out waiting for approval")
	ErrDenied  = errors.New("request denied on phone")
)

type Params struct {
	Principals []string
	TTL        time.Duration
	Label      string
	Who        string
	Timeout    time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
	// Logf receives progress messages (optional).
	Logf func(format string, args ...any)
}

func (p Params) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p Params) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf(format, args...)
	}
}

// Run performs the request and installs the verified certificate into dir.
func Run(ctx context.Context, cfg config.Config, nt *ntfy.Client, dir keys.Dir, p Params) (*ssh.Certificate, error) {
	if len(p.Principals) == 0 {
		return nil, errors.New("at least one principal (-p) is required")
	}
	if !protocol.ValidLabel(p.Label) {
		return nil, fmt.Errorf("invalid label %q (allowed: A-Z a-z 0-9 . _ -, max 64)", p.Label)
	}
	if p.TTL < time.Minute {
		return nil, errors.New("ttl must be at least 1m")
	}
	k, err := cfg.Keys()
	if err != nil {
		return nil, err
	}
	ca, err := cfg.CAKey()
	if err != nil {
		return nil, err
	}
	pending, err := keys.Generate()
	if err != nil {
		return nil, err
	}
	id, err := protocol.NewID()
	if err != nil {
		return nil, err
	}
	start := p.now()
	ttlSecs := int64(p.TTL / time.Second)
	reqJSON, err := json.Marshal(protocol.Request{
		ID: id, TS: start.Unix(), Label: p.Label, Who: p.Who,
		PubKey: pending.AuthorizedKey(), Principals: p.Principals, TTL: ttlSecs,
	})
	if err != nil {
		return nil, err
	}
	env, err := protocol.Seal(k.EncKey, protocol.AADRequest, reqJSON, nil)
	if err != nil {
		return nil, err
	}

	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Subscribe before publishing; `since` also covers a response that races the stream opening.
	sub := nt.Subscribe(ctx, k.RespTopic, strconv.FormatInt(start.Unix()-1, 10))
	// Don't return while the subscription goroutine can still run (and log).
	defer func() {
		cancel()
		<-sub.Done
	}()
	select {
	case <-sub.Opened:
	case <-time.After(10 * time.Second):
		p.logf("yessh: response stream not open yet; publishing anyway")
	case <-ctx.Done():
		return nil, ErrTimeout
	}

	headers := map[string]string{
		"Priority": "high",
		"Title":    "yessh request from " + p.Label,
		"Tags":     "key",
	}
	if cfg.PWA != "" {
		headers["Click"] = cfg.PWA + "#/r/" + id
	}
	if err := nt.Publish(ctx, k.ReqTopic, env, headers); err != nil {
		return nil, err
	}
	p.logf("yessh: request sent (%s for %v, ttl %s); approve it on your phone", p.Label, p.Principals, p.TTL)

	for {
		var m ntfy.Message
		var ok bool
		select {
		case <-ctx.Done():
			return nil, ErrTimeout
		case m, ok = <-sub.Messages:
			if !ok {
				return nil, ErrTimeout
			}
		}
		pt, err := protocol.Open(k.EncKey, protocol.AADResponse, []byte(m.Message))
		if err != nil {
			continue // not ours or not authentic: drop silently
		}
		var resp protocol.Response
		if json.Unmarshal(pt, &resp) != nil || resp.ID != id {
			continue
		}
		switch resp.Status {
		case protocol.StatusDenied:
			return nil, ErrDenied
		case protocol.StatusApproved:
		default:
			continue
		}
		cert, err := sshcert.Verify(resp.Cert, sshcert.Expectation{
			CA: ca, Key: pending.Public, Principals: p.Principals, TTL: p.TTL, Now: p.now(),
		})
		if err != nil {
			return nil, fmt.Errorf("rejected response: %w", err)
		}
		if err := pending.Install(dir, resp.Cert); err != nil {
			return nil, err
		}
		return cert, nil
	}
}
