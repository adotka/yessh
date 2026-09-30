// Package ntfy is a minimal client for publishing to and subscribing to ntfy topics.
// The relay is untrusted: callers authenticate every message themselves.
package ntfy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Client struct {
	BaseURL string // e.g. https://ntfy.sh
	Token   string // optional access token
	HTTP    *http.Client
	// Logf receives transient errors while subscribed (optional).
	Logf func(format string, args ...any)
}

type Message struct {
	ID      string `json:"id"`
	Time    int64  `json:"time"`
	Event   string `json:"event"`
	Topic   string `json:"topic"`
	Message string `json:"message"`
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) topicURL(topic string) string {
	return strings.TrimRight(c.BaseURL, "/") + "/" + url.PathEscape(topic)
}

func (c *Client) auth(req *http.Request) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
}

// Publish posts body to topic with the given ntfy headers (Title, Priority, Click, ...).
func (c *Client) Publish(ctx context.Context, topic string, body []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.topicURL(topic), bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c.auth(req)
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("ntfy publish: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("ntfy publish: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// Subscription streams messages from a topic, reconnecting on errors until ctx is cancelled.
type Subscription struct {
	Messages <-chan Message
	// Opened is closed once the first stream connection is established.
	Opened <-chan struct{}
	// Done is closed when the subscription goroutine has exited (after ctx is cancelled).
	Done <-chan struct{}
}

// Subscribe opens a JSON stream on topic. since is passed to ntfy on the first connection
// (unix time, duration like "10m", message id, or "" for new messages only); reconnects resume
// after the last message seen.
func (c *Client) Subscribe(ctx context.Context, topic, since string) *Subscription {
	msgs := make(chan Message, 16)
	opened := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		defer close(msgs)
		backoff := time.Second
		for ctx.Err() == nil {
			last, err := c.stream(ctx, topic, since, msgs, func() { once.Do(func() { close(opened) }) })
			if last != "" {
				since = last
				backoff = time.Second
			}
			if ctx.Err() != nil {
				return
			}
			if err != nil && c.Logf != nil {
				c.Logf("ntfy: %v (reconnecting in %s)", err, backoff)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
	}()
	return &Subscription{Messages: msgs, Opened: opened, Done: done}
}

func (c *Client) stream(ctx context.Context, topic, since string, out chan<- Message, onOpen func()) (last string, err error) {
	u := c.topicURL(topic) + "/json"
	if since != "" {
		u += "?since=" + url.QueryEscape(since)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	c.auth(req)
	resp, err := c.http().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("subscribe: %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		var m Message
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		switch m.Event {
		case "open":
			onOpen()
		case "message":
			last = m.ID
			select {
			case out <- m:
			case <-ctx.Done():
				return last, ctx.Err()
			}
		}
	}
	if err := sc.Err(); err != nil {
		return last, err
	}
	return last, io.ErrUnexpectedEOF
}
