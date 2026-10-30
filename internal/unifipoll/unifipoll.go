// Package unifipoll polls the UniFi consoles set up in Settings → UniFi
// every few minutes, from the server or through the agent of the host
// chosen to reach them, and stores what they report (docs/integrations.md).
package unifipoll

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/unifi"
)

const (
	// Every is how often each console is polled.
	Every = 5 * time.Minute
	// tick is how often the poller looks for consoles that are due.
	tick = time.Minute
	// pollTimeout bounds a scheduled poll; a "Poll now" from the UI gets
	// less, so it answers before the web server gives up on the request.
	pollTimeout = 2 * time.Minute
	nowTimeout  = 40 * time.Second
)

// Agents has a host's agent poll a console (the gateway).
type Agents interface {
	PollIntegration(ctx context.Context, hostID, kind, capability string, config []byte, secret string, timeout time.Duration) ([]byte, error)
}

type Poller struct {
	Store *store.Store
	// Open decrypts a console's API key (the BASELINE_SECRET_KEY codec).
	Open   func(blob string, v any) error
	Agents Agents // nil: consoles set to run on a host aren't polled
	Log    *jw6_utils.Utils
	// Poll reads a console from the server; nil is unifi.Poll. Tests
	// replace it.
	Poll func(ctx context.Context, cfg unifi.Config, apiKey string) (model.UniFi, error)

	once    sync.Once
	trigger chan struct{}
	mu      sync.Mutex
	running map[string]bool // console IDs being polled
}

func (p *Poller) init() {
	p.once.Do(func() {
		p.trigger = make(chan struct{}, 1)
		p.running = map[string]bool{}
	})
}

// Trigger looks for due consoles now (one was added or changed).
func (p *Poller) Trigger() {
	p.init()
	select {
	case p.trigger <- struct{}{}:
	default:
	}
}

// Run polls due consoles until ctx ends.
func (p *Poller) Run(ctx context.Context) {
	p.init()
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		p.Pass(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-p.trigger:
		}
	}
}

// Pass starts a poll of every enabled console that is due: never polled,
// polled Every ago, or changed since (its last poll is cleared on save).
// Polls run side by side, at most one per console.
func (p *Poller) Pass(ctx context.Context, now time.Time) {
	p.init()
	cs, err := p.Store.ListUniFiControllers(ctx)
	if err != nil {
		p.logf(jw6_utils.Error, "list UniFi consoles: %v", err)
		return
	}
	for _, c := range cs {
		if !c.Enabled || (!c.LastPoll.IsZero() && now.Sub(c.LastPoll) < Every) || !p.claim(c.ID) {
			continue
		}
		go func() {
			defer p.release(c.ID)
			if err := p.poll(ctx, c, pollTimeout); err != nil {
				p.logf(jw6_utils.Warn, "UniFi console %s: %v", c.Name, err)
			}
		}()
	}
}

// PollNow polls one console at once and says how it went.
func (p *Poller) PollNow(ctx context.Context, id string) error {
	p.init()
	c, err := p.Store.GetUniFiController(ctx, id)
	if err != nil {
		return err
	}
	if !p.claim(id) {
		return errors.New("a poll of this console is already running")
	}
	defer p.release(id)
	return p.poll(ctx, c, nowTimeout)
}

func (p *Poller) claim(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running[id] {
		return false
	}
	p.running[id] = true
	return true
}

func (p *Poller) release(id string) {
	p.mu.Lock()
	delete(p.running, id)
	p.mu.Unlock()
}

// poll reads a console and stores the result, or the error.
func (p *Poller) poll(ctx context.Context, c store.UniFiController, timeout time.Duration) error {
	start := time.Now()
	snap, err := p.read(ctx, c, timeout)
	if err == nil {
		err = p.Store.IngestUniFi(ctx, c.ID, start, snap)
		if err == nil {
			return nil
		}
		err = fmt.Errorf("storing what it reported: %w", err)
	}
	if ferr := p.Store.UniFiPollFailed(context.WithoutCancel(ctx), c.ID, start, err.Error()); ferr != nil {
		p.logf(jw6_utils.Error, "record UniFi poll failure: %v", ferr)
	}
	return err
}

func (p *Poller) read(ctx context.Context, c store.UniFiController, timeout time.Duration) (model.UniFi, error) {
	var snap model.UniFi
	var key string
	if p.Open == nil || p.Open(c.APIKeyEnc, &key) != nil {
		return snap, errors.New("the API key doesn't open (did BASELINE_SECRET_KEY change?); enter it again")
	}
	if c.RunOn == "" {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		poll := p.Poll
		if poll == nil {
			poll = unifi.Poll
		}
		return poll(ctx, c.Config, key)
	}
	if p.Agents == nil {
		return snap, errors.New("agents can't be reached")
	}
	cfg, err := json.Marshal(c.Config)
	if err != nil {
		return snap, err
	}
	out, err := p.Agents.PollIntegration(ctx, c.RunOn, "unifi", model.CapUniFi, cfg, key, timeout)
	if err != nil {
		return snap, fmt.Errorf("through %s: %w", c.RunOnName, err)
	}
	if err := json.Unmarshal(out, &snap); err != nil {
		return snap, fmt.Errorf("through %s: the agent's answer doesn't read: %w", c.RunOnName, err)
	}
	return snap, nil
}

func (p *Poller) logf(level jw6_utils.LogLevel, format string, args ...any) {
	if p.Log != nil {
		p.Log.Log("UniFi", "poll", level, fmt.Sprintf(format, args...))
	}
}
