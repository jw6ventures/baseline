// Package notify delivers alert notifications to Matrix rooms and ntfy
// topics (docs/architecture.md §2.1). Messages wait in the database outbox
// and are retried with backoff, so a channel that is down for a while still
// gets them, in order, once it is back.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/store"
)

// Kinds of channel.
const (
	Matrix = "matrix"
	Ntfy   = "ntfy"
)

// Config is a channel's settings, sealed at rest with BASELINE_SECRET_KEY.
type Config struct {
	// Matrix: the homeserver's client API base URL, a room ID
	// (!abc:example.org) or alias (#ops:example.org), and the access token
	// of the account that posts (it must have joined the room).
	Homeserver string `json:"homeserver,omitempty"`
	Room       string `json:"room,omitempty"`
	// ntfy: the server and topic, and an access token if the topic is
	// protected.
	Server string `json:"server,omitempty"`
	Topic  string `json:"topic,omitempty"`
	Token  string `json:"token,omitempty"`
}

// Check validates a channel's settings and returns the summary that is
// safe to show.
func Check(kind string, c Config) (string, error) {
	switch kind {
	case Matrix:
		u, err := url.Parse(c.Homeserver)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "", errors.New("enter the homeserver's URL, e.g. https://matrix.example.org")
		}
		if !strings.HasPrefix(c.Room, "!") && !strings.HasPrefix(c.Room, "#") || !strings.Contains(c.Room, ":") {
			return "", errors.New("enter a room ID (!abc:example.org) or alias (#ops:example.org)")
		}
		if c.Token == "" {
			return "", errors.New("enter the access token of the account that posts")
		}
		return c.Room + " on " + u.Host, nil
	case Ntfy:
		u, err := url.Parse(c.Server)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "", errors.New("enter the ntfy server's URL, e.g. https://ntfy.sh")
		}
		if c.Topic == "" || strings.ContainsAny(c.Topic, "/?# ") {
			return "", errors.New("enter a topic name")
		}
		return strings.TrimRight(c.Server, "/") + "/" + c.Topic, nil
	}
	return "", fmt.Errorf("unknown channel kind %q", kind)
}

// Message is what a notification says.
type Message struct {
	ID       int64  // the outbox row; Matrix uses it to make retries idempotent
	Event    string // firing | reminder | resolved | test
	Severity string // info | warning | critical
	Title    string
	Body     string
	Link     string
}

// Send delivers one message.
func Send(ctx context.Context, c *http.Client, kind string, cfg Config, m Message) error {
	switch kind {
	case Matrix:
		return sendMatrix(ctx, c, cfg, m)
	case Ntfy:
		return sendNtfy(ctx, c, cfg, m)
	}
	return fmt.Errorf("unknown channel kind %q", kind)
}

// sendMatrix posts an m.text message with the client-server API. The
// transaction ID is the outbox row, so a retry after a lost response
// doesn't post twice.
func sendMatrix(ctx context.Context, c *http.Client, cfg Config, m Message) error {
	base := strings.TrimRight(cfg.Homeserver, "/") + "/_matrix/client/v3"
	room := cfg.Room
	if strings.HasPrefix(room, "#") {
		var res struct {
			RoomID string `json:"room_id"`
		}
		if err := matrixDo(ctx, c, http.MethodGet, base+"/directory/room/"+url.PathEscape(room), cfg.Token, nil, &res); err != nil {
			return fmt.Errorf("resolving %s: %w", room, err)
		}
		room = res.RoomID
	}
	plain := m.Title + "\n" + m.Body
	formatted := "<strong>" + html.EscapeString(m.Title) + "</strong><br>" + html.EscapeString(m.Body)
	if m.Link != "" {
		plain += "\n" + m.Link
		formatted += `<br><a href="` + html.EscapeString(m.Link) + `">Open in Baseline</a>`
	}
	body := map[string]string{"msgtype": "m.text", "body": plain, "format": "org.matrix.custom.html", "formatted_body": formatted}
	txn := fmt.Sprintf("baseline-%d", m.ID)
	return matrixDo(ctx, c, http.MethodPut,
		base+"/rooms/"+url.PathEscape(room)+"/send/m.room.message/"+url.PathEscape(txn), cfg.Token, body, nil)
}

func matrixDo(ctx context.Context, c *http.Client, method, u, token string, in, out any) error {
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Code  string `json:"errcode"`
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Code != "" {
			return fmt.Errorf("HTTP %d: %s: %s", resp.StatusCode, e.Code, e.Error)
		}
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// sendNtfy publishes to a topic, with the title, a priority and tags that
// follow the severity, and a click-through link.
func sendNtfy(ctx context.Context, c *http.Client, cfg Config, m Message) error {
	u := strings.TrimRight(cfg.Server, "/") + "/" + url.PathEscape(cfg.Topic)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(m.Body))
	if err != nil {
		return err
	}
	prio, tag := "3", "information_source"
	switch {
	case m.Event == store.EventResolved:
		prio, tag = "2", "white_check_mark"
	case m.Event == store.EventTest:
		tag = "test_tube"
	case m.Severity == "critical":
		prio, tag = "5", "rotating_light"
	case m.Severity == "warning":
		prio, tag = "4", "warning"
	}
	req.Header.Set("Title", m.Title)
	req.Header.Set("Priority", prio)
	req.Header.Set("Tags", tag)
	if m.Link != "" {
		req.Header.Set("Click", m.Link)
	}
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, e.Error)
		}
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	return nil
}

const (
	// every is how often the outbox is checked without a nudge.
	every = 15 * time.Second
	// maxAttempts is how often a message is tried before giving up: with
	// the backoff below, for about 9 hours.
	maxAttempts = 16
	batch       = 50
)

// backoff is the wait after the nth failed try: 30s doubling, at most 1h.
func backoff(n int) time.Duration {
	d := 30 * time.Second << min(n-1, 7)
	return min(d, time.Hour)
}

// Notifier delivers the outbox.
type Notifier struct {
	Store *store.Store
	// Open unseals a channel's settings.
	Open   func(sealed string, into any) error
	Client *http.Client
	Log    *jw6_utils.Utils
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	once sync.Once
	wake chan struct{}
}

func (n *Notifier) init() { n.once.Do(func() { n.wake = make(chan struct{}, 1) }) }

func (n *Notifier) now() time.Time {
	if n.Now != nil {
		return n.Now()
	}
	return time.Now()
}

// Nudge delivers now rather than at the next tick.
func (n *Notifier) Nudge() {
	n.init()
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// Run delivers due messages every 15 seconds, and when nudged, until ctx
// ends.
func (n *Notifier) Run(ctx context.Context) {
	n.init()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := n.Deliver(ctx); err != nil && ctx.Err() == nil {
			n.logf(jw6_utils.Error, "notifications: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-n.wake:
		}
	}
}

// Deliver tries every due message once. A message whose channel failed
// earlier in the pass waits, so one channel's messages stay in order.
func (n *Notifier) Deliver(ctx context.Context) error {
	due, err := n.Store.DueNotifications(ctx, n.now(), batch)
	if err != nil {
		return err
	}
	c := n.Client
	if c == nil {
		c = &http.Client{Timeout: 20 * time.Second}
	}
	down := map[string]bool{}
	for _, m := range due {
		if down[m.ChannelID] {
			continue
		}
		var cfg Config
		err := n.Open(m.ConfigEnc, &cfg)
		if err != nil {
			err = errors.New("can't open the channel's settings (did BASELINE_SECRET_KEY change?)")
		} else {
			err = Send(ctx, c, m.ChannelKind, cfg, Message{ID: m.ID, Event: m.Event, Severity: m.Severity, Title: m.Title,
				Body: m.Body, Link: m.Link})
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			if err := n.Store.NotificationSent(ctx, m.ID); err != nil {
				return err
			}
			continue
		}
		down[m.ChannelID] = true
		attempts := m.Attempts + 1
		next := time.Time{}
		msg := err.Error()
		if attempts < maxAttempts {
			next = n.now().Add(backoff(attempts))
		} else {
			msg = fmt.Sprintf("gave up after %d tries: %s", attempts, msg)
		}
		n.logf(jw6_utils.Warn, "notification %d to %s: %s", m.ID, m.ChannelName, msg)
		if err := n.Store.NotificationFailed(ctx, m.ID, msg, next); err != nil {
			return err
		}
	}
	return nil
}

func (n *Notifier) logf(level jw6_utils.LogLevel, format string, args ...any) {
	if n.Log != nil {
		n.Log.Log("Notify", "deliver", level, fmt.Sprintf(format, args...))
	}
}
