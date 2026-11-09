// Package checks runs the server's own checks in the background: what
// container registries serve for the images hosts run (docs/agent.md §3.3),
// and the TLS certificates of agentless CIs' endpoints (§1.3).
package checks

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"sync"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/registry"
	"github.com/jw6ventures/baseline/internal/store"
)

const (
	// ImageTTL is how long a registry answer is trusted (docs/agent.md §3.3).
	ImageTTL = 6 * time.Hour
	// retryAfter is how soon a failed check is tried again.
	retryAfter  = time.Hour
	endpointTTL = 6 * time.Hour
	every       = 10 * time.Minute
	concurrency = 4
)

// Registry is the part of *registry.Client the checker uses.
type Registry interface {
	Digest(ctx context.Context, ref registry.Ref) (string, error)
	Tags(ctx context.Context, ref registry.Ref) ([]string, error)
}

type Checker struct {
	Store *store.Store
	// Registry asks registries; nil builds a client with Credentials.
	Registry Registry
	// Credentials returns the login for a registry host, if one is set.
	Credentials func(ctx context.Context) (map[string][2]string, error)
	Log         *jw6_utils.Utils
	// Dial reaches endpoints; nil uses net.Dialer. Tests replace it.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	trigger      chan struct{}
	once         sync.Once
	lastEndpoint time.Time
}

func (c *Checker) init() {
	c.once.Do(func() { c.trigger = make(chan struct{}, 1) })
}

// Trigger runs a pass now (a "Check now" button, a new rule).
func (c *Checker) Trigger() {
	c.init()
	select {
	case c.trigger <- struct{}{}:
	default:
	}
}

// Run checks every 10 minutes, and when triggered, until ctx ends.
func (c *Checker) Run(ctx context.Context) {
	c.init()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		c.Pass(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-c.trigger:
		}
	}
}

// Pass runs one round: stale image digests, tags for repositories a semver
// rule watches, the digests of the tags those rules would offer, endpoints due for a probe, and missing containers.
func (c *Checker) Pass(ctx context.Context, now time.Time) {
	if n, err := c.Store.MarkMissing(ctx, now); err != nil {
		c.logf(jw6_utils.Error, "mark missing CIs: %v", err)
	} else if n > 0 {
		c.logf(jw6_utils.Info, "%d containers or stacks are gone and now missing", n)
	}
	reg := c.Registry
	if reg == nil {
		creds := map[string][2]string{}
		if c.Credentials != nil {
			var err error
			if creds, err = c.Credentials(ctx); err != nil {
				c.logf(jw6_utils.Error, "registry credentials: %v", err)
			}
		}
		reg = &registry.Client{UserAgent: "Baseline", Credentials: func(host string) (string, string, bool) {
			cr, ok := creds[host]
			return cr[0], cr[1], ok
		}}
	}
	c.images(ctx, reg, now)
	c.tags(ctx, reg, now)
	c.advisedDigests(ctx, reg, now)
	if now.Sub(c.lastEndpoint) >= endpointTTL || c.lastEndpoint.IsZero() {
		c.endpoints(ctx)
		c.lastEndpoint = now
	}
}

func (c *Checker) images(ctx context.Context, reg Registry, now time.Time) {
	refs, err := c.Store.ImageRefsToCheck(ctx, now.Add(-ImageTTL), now.Add(-retryAfter))
	if err != nil {
		c.logf(jw6_utils.Error, "images to check: %v", err)
		return
	}
	parallel(ctx, refs, func(s string) {
		ref, err := registry.ParseRef(s)
		if err != nil {
			c.save(ctx, s, "", "", err)
			return
		}
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		digest, err := reg.Digest(cctx, ref)
		c.save(ctx, s, ref.Registry, digest, err)
	})
	if len(refs) > 0 {
		c.logf(jw6_utils.Debug, "Checked %d image references", len(refs))
	}
}

func (c *Checker) save(ctx context.Context, ref, host, digest string, checkErr error) {
	msg := ""
	if checkErr != nil {
		if ctx.Err() != nil {
			return // shutting down: not the registry's fault
		}
		msg = checkErr.Error()
		c.logf(jw6_utils.Debug, "image check %s: %s", ref, msg)
	}
	if err := c.Store.SaveImageCheck(ctx, ref, host, digest, msg); err != nil && ctx.Err() == nil {
		c.logf(jw6_utils.Error, "save image check: %v", err)
	}
}

// tags lists tags of repositories that semver rules watch. Tags are per
// repository, so several tags of one image share a listing.
func (c *Checker) tags(ctx context.Context, reg Registry, now time.Time) {
	refs, err := c.Store.RuledImageRefs(ctx)
	if err != nil {
		c.logf(jw6_utils.Error, "repositories with semver rules: %v", err)
		return
	}
	repos := map[string]registry.Ref{}
	for _, s := range refs {
		if ref, err := registry.ParseRef(s); err == nil {
			repos[ref.Repo()] = ref
		}
	}
	var due []string
	for repo := range repos {
		at, lastErr, err := c.Store.TagsCheckedAt(ctx, repo)
		ttl := ImageTTL
		if lastErr != "" {
			ttl = retryAfter
		}
		if errors.Is(err, store.ErrNotFound) || (err == nil && now.Sub(at) >= ttl) {
			due = append(due, repo)
		}
	}
	sort.Strings(due)
	parallel(ctx, due, func(repo string) {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		tags, err := reg.Tags(cctx, repos[repo])
		msg := ""
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			msg = err.Error()
		}
		if err := c.Store.SaveTags(ctx, repo, tags, msg); err != nil && ctx.Err() == nil {
			c.logf(jw6_utils.Error, "save tags: %v", err)
		}
	})
}

// maxAdviceRounds bounds how many tags in a row advisedDigests looks at
// for a container whose next tag turns out to be its own image.
const maxAdviceRounds = 3

// advisedDigests checks the digest of each tag a semver rule would offer,
// so a tag that serves the image a container's tag already does (an alias
// such as 2026.8.5 of 2026.8, or a retag) isn't offered as an update. A tag
// found to be one passes the offer to the next, whose digest is checked in
// the next round.
func (c *Checker) advisedDigests(ctx context.Context, reg Registry, now time.Time) {
	hosts, err := c.Store.ListHosts(ctx)
	if err != nil {
		c.logf(jw6_utils.Error, "advised digests: %v", err)
		return
	}
	var ids []string
	for _, h := range hosts {
		if !h.Revoked {
			ids = append(ids, h.ID)
		}
	}
	rows, err := c.Store.ListContainers(ctx, ids)
	if err != nil {
		c.logf(jw6_utils.Error, "advised digests: %v", err)
		return
	}
	stacks, err := c.Store.ListStacks(ctx, ids)
	if err != nil {
		c.logf(jw6_utils.Error, "advised digests: %v", err)
		return
	}
	rules := store.SemverRules(rows, stacks)
	var repos []string
	for i, rule := range rules {
		if rule == nil || rows[i].CheckRef == "" {
			continue
		}
		if ref, err := registry.ParseRef(rows[i].CheckRef); err == nil {
			repos = append(repos, ref.Repo())
		}
	}
	if len(repos) == 0 {
		return
	}
	tags, err := c.Store.RepositoryTags(ctx, repos)
	if err != nil {
		c.logf(jw6_utils.Error, "advised digests: %v", err)
		return
	}
	known, err := c.Store.RepositoryImageChecks(ctx, repos)
	if err != nil {
		c.logf(jw6_utils.Error, "advised digests: %v", err)
		return
	}
	fresh := func(ic store.ImageCheck, ok bool) bool {
		ttl := ImageTTL
		if ic.Error != "" {
			ttl = retryAfter
		}
		return ok && now.Sub(ic.CheckedAt) < ttl
	}
	for range maxAdviceRounds {
		due := map[string]bool{}
		for i, rule := range rules {
			if rule == nil || rows[i].CheckRef == "" {
				continue
			}
			ref, err := registry.ParseRef(rows[i].CheckRef)
			if err != nil {
				continue
			}
			tag, ok := rows[i].Advise(*rule, tags[ref.Repo()], known)
			if !ok {
				continue
			}
			cand := ref.Repo() + ":" + tag
			if ic, ok := known[cand]; !fresh(ic, ok) {
				due[cand] = true
			}
		}
		if len(due) == 0 || ctx.Err() != nil {
			return
		}
		refs := make([]string, 0, len(due))
		for r := range due {
			refs = append(refs, r)
		}
		sort.Strings(refs)
		var mu sync.Mutex
		parallel(ctx, refs, func(s string) {
			ref, err := registry.ParseRef(s)
			if err != nil {
				return
			}
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			digest, err := reg.Digest(cctx, ref)
			c.save(ctx, s, ref.Registry, digest, err)
			mu.Lock()
			defer mu.Unlock()
			ic := known[s] // a failed check keeps the last digest it knew
			ic.CheckedAt, ic.Error = now, ""
			if err != nil {
				ic.Error = err.Error()
			} else {
				ic.Digest = digest
			}
			known[s] = ic
		})
	}
}

// endpoints probes the TLS endpoints configured on agentless CIs.
func (c *Checker) endpoints(ctx context.Context) {
	eps, err := c.Store.TLSEndpoints(ctx)
	if err != nil {
		c.logf(jw6_utils.Error, "TLS endpoints: %v", err)
		return
	}
	var keep []string
	for _, e := range eps {
		keep = append(keep, e.CIID)
	}
	if err := c.Store.ClearProbeCerts(ctx, keep); err != nil {
		c.logf(jw6_utils.Error, "clear probes: %v", err)
	}
	byKey := map[string]store.Endpoint{}
	var keys []string
	for _, e := range eps {
		k := e.CIID + " " + e.Address
		byKey[k] = e
		keys = append(keys, k)
	}
	parallel(ctx, keys, func(k string) {
		e := byKey[k]
		cert, err := c.Probe(ctx, e.Address)
		cert.Location = e.Address
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if err := c.Store.SaveProbeCert(ctx, e.CIID, cert, msg); err != nil && ctx.Err() == nil {
			c.logf(jw6_utils.Error, "save probe: %v", err)
		}
	})
}

// Probe reads the certificate an endpoint serves. It reads, it doesn't
// trust, so verification is off; expiry is what's being watched.
func (c *Checker) Probe(ctx context.Context, address string) (model.Cert, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port = address, "443"
	}
	address = net.JoinHostPort(host, port)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dial := c.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	raw, err := dial(ctx, "tcp", address)
	if err != nil {
		return model.Cert{}, shortNetErr(err)
	}
	defer raw.Close()
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	if net.ParseIP(host) == nil {
		cfg.ServerName = host
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return model.Cert{}, fmt.Errorf("TLS handshake: %w", shortNetErr(err))
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return model.Cert{}, errors.New("no certificate served")
	}
	return certInfo(certs[0]), nil
}

func certInfo(x *x509.Certificate) model.Cert {
	var sans []string
	sans = append(sans, x.DNSNames...)
	for _, ip := range x.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, x.EmailAddresses...)
	slices.Sort(sans)
	sum := sha256.Sum256(x.Raw)
	return model.Cert{
		Subject: x.Subject.String(), SANs: sans, Issuer: x.Issuer.String(),
		NotBefore: x.NotBefore.UTC().Format(time.RFC3339), NotAfter: x.NotAfter.UTC().Format(time.RFC3339),
		Serial: fmt.Sprintf("%x", x.SerialNumber), Fingerprint: hex.EncodeToString(sum[:]),
		SelfSigned: x.Issuer.String() == x.Subject.String() && x.CheckSignatureFrom(x) == nil,
	}
}

// shortNetErr drops the address noise of *net.OpError for the UI.
func shortNetErr(err error) error {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err
	}
	return err
}

// parallel runs fn over items, a few at a time.
func parallel(ctx context.Context, items []string, fn func(string)) {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, it := range items {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			fn(it)
		}()
	}
	wg.Wait()
}

func (c *Checker) logf(level jw6_utils.LogLevel, format string, args ...any) {
	if c.Log != nil {
		c.Log.Log("Checks", "run", level, fmt.Sprintf(format, args...))
	}
}
