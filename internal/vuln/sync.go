package vuln

import (
	"archive/zip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/store"
)

// DefaultURL is the OSV bucket: <dir>/all.zip holds every record of an
// ecosystem directory, <dir>/modified_id.csv lists them newest change
// first, and <dir>/<id>.json is one record.
const DefaultURL = "https://osv-vulnerabilities.storage.googleapis.com"

const (
	// SyncEvery is how often an ecosystem is brought up to date.
	SyncEvery = 24 * time.Hour
	// retryAfter is how soon a failed sync is tried again.
	retryAfter = time.Hour
	// fullEvery forces a full sync now and then, so nothing missed by the
	// incremental ones (a record deleted rather than withdrawn) lingers.
	fullEvery = 30 * 24 * time.Hour
	// maxIncremental is how many changed records are fetched one by one
	// before a full dump is cheaper.
	maxIncremental = 1000
	// cursorSlack re-reads records modified shortly before the newest one a
	// dump held, in case the dump was cut while they changed.
	cursorSlack = time.Hour
	maxDump     = 4 << 30
	tick        = time.Hour
)

// Syncer keeps the OSV data of enrolled hosts' ecosystems current and
// matches hosts' packages against it.
type Syncer struct {
	Store *store.Store
	Log   *jw6_utils.Utils
	// URL is the OSV bucket (DefaultURL, or a mirror); "" turns syncing
	// off, but hosts are still matched against data already stored.
	URL    string
	Client *http.Client
	// TempDir holds dumps while they are read; "" is os.TempDir.
	TempDir string
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Matched is called after a host's matches were saved.
	Matched func(hostID string)

	once    sync.Once
	sync    chan struct{}
	mu      sync.Mutex
	pending map[string]bool
	wake    chan struct{}
	// passing serializes passes: Run's and a test's or handler's.
	passing sync.Mutex
}

func (s *Syncer) init() {
	s.once.Do(func() {
		s.sync = make(chan struct{}, 1)
		s.wake = make(chan struct{}, 1)
		s.pending = map[string]bool{}
	})
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Trigger syncs every ecosystem now, due or not ("Sync now").
func (s *Syncer) Trigger() {
	s.init()
	select {
	case s.sync <- struct{}{}:
	default:
	}
}

// HostChanged queues a host to be matched again: its OS, packages or
// updates changed.
func (s *Syncer) HostChanged(hostID string) {
	s.init()
	s.mu.Lock()
	s.pending[hostID] = true
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run syncs due ecosystems every hour, or when triggered, and matches
// queued hosts, until ctx ends.
func (s *Syncer) Run(ctx context.Context) {
	s.init()
	t := time.NewTicker(tick)
	defer t.Stop()
	force := false
	for {
		if err := s.Pass(ctx, force); err != nil && ctx.Err() == nil {
			s.logf(jw6_utils.Error, "vulnerability sync: %v", err)
		}
		force = false
		s.matchPending(ctx) // a pass just ran
		for waiting := true; waiting; {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				waiting = false
			case <-s.sync:
				force, waiting = true, false
			case <-s.wake:
				// A host may run a release nothing was synced for yet; a
				// pass costs nothing when no ecosystem is due.
				if s.matchPending(ctx) {
					waiting = false
				}
			}
		}
	}
}

// matchPending matches queued hosts and reports whether one runs an
// ecosystem that was never synced and may be tried now.
func (s *Syncer) matchPending(ctx context.Context) bool {
	s.mu.Lock()
	ids := make([]string, 0, len(s.pending))
	for id := range s.pending {
		ids = append(ids, id)
	}
	clear(s.pending)
	s.mu.Unlock()
	slices.Sort(ids)
	for _, id := range ids {
		if err := s.MatchHost(ctx, id); err != nil && ctx.Err() == nil {
			s.logf(jw6_utils.Error, "match host %s: %v", id, err)
		}
	}
	if len(ids) == 0 || s.URL == "" {
		return false
	}
	wanted, err := s.Wanted(ctx)
	if err != nil {
		return false
	}
	sources, err := s.Store.VulnSources(ctx)
	if err != nil {
		return false
	}
	now := s.now()
	for _, e := range wanted {
		i := slices.IndexFunc(sources, func(v store.VulnSource) bool { return v.Ecosystem == e.Name })
		if i < 0 || sources[i].SyncedAt.IsZero() && due(sources[i], now) {
			return true
		}
	}
	return false
}

// due reports whether an ecosystem should be synced: daily, and a failed
// sync an hour after it was tried.
func due(src store.VulnSource, now time.Time) bool {
	if src.Error != "" && now.Sub(src.TriedAt) < retryAfter {
		return false
	}
	return src.SyncedAt.IsZero() || now.Sub(src.SyncedAt) >= SyncEvery
}

// Wanted lists the ecosystems enrolled hosts run.
func (s *Syncer) Wanted(ctx context.Context) ([]Ecosystem, error) {
	hosts, err := s.Store.VulnHosts(ctx)
	if err != nil {
		return nil, err
	}
	var out []Ecosystem
	for _, h := range hosts {
		if e, ok := For(h.OSID, h.OSVersion); ok && !slices.ContainsFunc(out, func(x Ecosystem) bool { return x.Name == e.Name }) {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b Ecosystem) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Pass syncs every wanted ecosystem that is due (or all, with force) and
// matches its hosts again when its data changed.
func (s *Syncer) Pass(ctx context.Context, force bool) error {
	s.passing.Lock()
	defer s.passing.Unlock()
	if s.URL == "" {
		return nil
	}
	wanted, err := s.Wanted(ctx)
	if err != nil {
		return err
	}
	sources, err := s.Store.VulnSources(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	byBase := map[string][]*source{}
	var bases []string
	for _, e := range wanted {
		src := store.VulnSource{Ecosystem: e.Name}
		if i := slices.IndexFunc(sources, func(v store.VulnSource) bool { return v.Ecosystem == e.Name }); i >= 0 {
			src = sources[i]
		}
		if !due(src, now) && !force {
			continue
		}
		if byBase[e.Base] == nil {
			bases = append(bases, e.Base)
		}
		byBase[e.Base] = append(byBase[e.Base], &source{e, src})
	}
	var errs []error
	for _, base := range bases {
		changed, err := s.syncBase(ctx, base, byBase[base])
		if err != nil {
			errs = append(errs, err)
		}
		for _, eco := range changed {
			if err := s.MatchEcosystem(ctx, eco); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// source is an ecosystem being synced and its state.
type source struct {
	e   Ecosystem
	src store.VulnSource
}

// syncBase brings the due ecosystems of one OSV directory ("Ubuntu") up to
// date: incrementally from the directory's change list where it can, and
// the rest from one read of its full dump. OSV's per-release directories
// ("Ubuntu:24.04:LTS") stopped being updated in October 2024, so only the
// distro-wide ones are used. It returns the ecosystems whose data changed.
func (s *Syncer) syncBase(ctx context.Context, base string, due []*source) ([]string, error) {
	now := s.now()
	var changed []string
	var errs []error
	fail := func(x *source, err error) {
		x.src.Error, x.src.TriedAt = err.Error(), now
		if serr := s.Store.SaveVulnSource(ctx, x.src); serr != nil {
			err = serr
		}
		errs = append(errs, fmt.Errorf("%s: %w", x.e.Name, err))
	}
	var list []modified
	var listErr error
	listed := false
	var full []*source
	for _, x := range due {
		if x.src.Cursor.IsZero() || now.Sub(x.src.FullAt) >= fullEvery || x.src.Dump != base {
			full = append(full, x)
			continue
		}
		if !listed {
			list, listErr = s.changes(ctx, base)
			listed = true
		}
		if listErr != nil {
			fail(x, listErr)
			continue
		}
		var ids []string
		newest := x.src.Cursor
		for _, m := range list {
			if !m.at.After(x.src.Cursor) {
				break // newest first
			}
			if !slices.Contains(ids, m.id) {
				ids = append(ids, m.id)
			}
			newest = maxTime(newest, m.at)
		}
		if len(ids) > maxIncremental {
			full = append(full, x)
			continue
		}
		n, err := s.incremental(ctx, x.e, ids)
		if err != nil {
			fail(x, err)
			continue
		}
		x.src.Cursor, x.src.SyncedAt, x.src.TriedAt, x.src.Error = newest, now, now, ""
		if err := s.Store.SaveVulnSource(ctx, x.src); err != nil {
			return changed, err
		}
		if n > 0 {
			s.logf(jw6_utils.Info, "OSV %s: %d changed records", x.e.Name, n)
			changed = append(changed, x.e.Name)
		}
	}
	if len(full) > 0 {
		names, err := s.full(ctx, base, full)
		if err != nil {
			for _, x := range full {
				fail(x, err)
			}
		}
		changed = append(changed, names...)
	}
	return changed, errors.Join(errs...)
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// full reads a directory's whole dump once for every ecosystem in due.
func (s *Syncer) full(ctx context.Context, base string, due []*source) ([]string, error) {
	now := s.now()
	// The ETag only helps when every ecosystem was read from the same dump.
	etag := due[0].src.ETag
	for _, x := range due {
		if x.src.Dump != base || x.src.ETag != etag {
			etag = ""
		}
	}
	f, tag, status, err := s.download(ctx, base+"/all.zip", etag)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusNotFound:
		return nil, fmt.Errorf("OSV has no %s/all.zip", base)
	case http.StatusNotModified:
		for _, x := range due {
			x.src.FullAt, x.src.SyncedAt, x.src.TriedAt, x.src.Error = now, now, now, ""
			if err := s.Store.SaveVulnSource(ctx, x.src); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	ecos := map[string]bool{}
	writers := map[string]*store.VulnWriter{}
	rollback := func() {
		for _, w := range writers {
			w.Rollback()
		}
	}
	for _, x := range due {
		ecos[x.e.Name] = true
		w, err := s.Store.ReplaceVulnsStream(ctx, x.e.Name)
		if err != nil {
			rollback()
			f.Close()
			os.Remove(f.Name())
			return nil, err
		}
		writers[x.e.Name] = w
	}
	newest, err := readDump(f, ecos, func(eco string, v store.Vuln, aff []store.VulnAffected) error {
		return writers[eco].Add(v, aff)
	})
	f.Close()
	os.Remove(f.Name())
	if err != nil {
		rollback()
		return nil, fmt.Errorf("%s/all.zip: %w", base, err)
	}
	var changed []string
	for _, x := range due {
		w := writers[x.e.Name]
		delete(writers, x.e.Name)
		if err := w.Commit(); err != nil {
			rollback()
			return changed, err
		}
		x.src.Dump, x.src.ETag, x.src.Cursor = base, tag, newest.Add(-cursorSlack)
		x.src.FullAt, x.src.SyncedAt, x.src.TriedAt, x.src.Error = now, now, now, ""
		if err := s.Store.SaveVulnSource(ctx, x.src); err != nil {
			rollback()
			return changed, err
		}
		s.logf(jw6_utils.Info, "OSV %s: %d vulnerabilities from %s/all.zip", x.e.Name, w.Count, base)
		changed = append(changed, x.e.Name)
	}
	return changed, nil
}

const fetchers = 8

// incremental fetches changed records, a few at a time.
func (s *Syncer) incremental(ctx context.Context, e Ecosystem, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	eco := map[string]bool{e.Name: true}
	type result struct {
		found bool
		vuln  store.Vuln
		aff   []store.VulnAffected
		ok    bool
		err   error
	}
	results := make([]result, len(ids))
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(fetchers, len(ids)) {
		wg.Go(func() {
			for i := range next {
				body, status, err := s.get(ctx, e.Base+"/"+ids[i]+".json")
				r := &results[i]
				switch {
				case err != nil:
					r.err = err
				case status == http.StatusNotFound:
					// Listed but not there (yet): records are withdrawn,
					// not deleted, so what is stored stays.
				default:
					r.found = true
					if r.vuln, r.aff, r.ok, r.err = parse(body, eco); r.err != nil {
						r.err = fmt.Errorf("%s: %w", ids[i], r.err)
					}
				}
			}
		})
	}
feed:
	for i := range ids {
		select {
		case next <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var fetched []string
	var vulns []store.Vuln
	var affected []store.VulnAffected
	for i, r := range results {
		if r.err != nil {
			return 0, r.err
		}
		if !r.found {
			continue
		}
		fetched = append(fetched, ids[i])
		if r.ok {
			vulns = append(vulns, r.vuln)
			affected = append(affected, r.aff...)
		}
	}
	if len(fetched) == 0 {
		return 0, nil
	}
	return len(fetched), s.Store.UpdateVulns(ctx, e.Name, fetched, vulns, affected)
}

type modified struct {
	at time.Time
	id string
}

// changes reads a directory's modified_id.csv: "<RFC 3339 time>,<id>"
// lines, newest first.
func (s *Syncer) changes(ctx context.Context, dir string) ([]modified, error) {
	body, status, err := s.get(ctx, dir+"/modified_id.csv")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s/modified_id.csv: HTTP %d", dir, status)
	}
	r := csv.NewReader(strings.NewReader(string(body)))
	r.FieldsPerRecord = 2
	var out []modified
	for {
		rec, err := r.Read()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s/modified_id.csv: %w", dir, err)
		}
		at, err := time.Parse(time.RFC3339Nano, rec[0])
		if err != nil {
			return nil, fmt.Errorf("%s/modified_id.csv: %w", dir, err)
		}
		// Records of other directories are listed by path ("Ubuntu/X").
		id := rec[1]
		if i := strings.LastIndexByte(id, '/'); i >= 0 {
			id = id[i+1:]
		}
		out = append(out, modified{at, id})
	}
}

// readDump reads every record in a dump and hands what affects each
// ecosystem in eco to add, one record at a time. It returns the newest
// modification time of any record.
func readDump(f *os.File, eco map[string]bool, add func(eco string, v store.Vuln, aff []store.VulnAffected) error) (time.Time, error) {
	var newest time.Time
	st, err := f.Stat()
	if err != nil {
		return newest, err
	}
	z, err := zip.NewReader(f, st.Size())
	if err != nil {
		return newest, err
	}
	for _, zf := range z.File {
		if !strings.HasSuffix(zf.Name, ".json") {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return newest, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 64<<20))
		rc.Close()
		var r record
		if err == nil {
			err = json.Unmarshal(b, &r)
		}
		if err != nil {
			return newest, fmt.Errorf("%s: %w", zf.Name, err)
		}
		newest = maxTime(newest, r.Modified)
		v, aff, ok, err := convert(r, eco)
		if err != nil {
			return newest, fmt.Errorf("%s: %w", zf.Name, err)
		}
		if !ok {
			continue
		}
		// Split by ecosystem, keeping the order entries came in.
		var ecos []string
		by := map[string][]store.VulnAffected{}
		for _, a := range aff {
			if by[a.Ecosystem] == nil {
				ecos = append(ecos, a.Ecosystem)
			}
			by[a.Ecosystem] = append(by[a.Ecosystem], a)
		}
		for _, e := range ecos {
			if err := add(e, v, by[e]); err != nil {
				return newest, err
			}
		}
	}
	return newest, nil
}

// download saves a file to a temporary file. A 404 or 304 returns no file.
func (s *Syncer) download(ctx context.Context, path, etag string) (*os.File, string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	resp, err := s.request(ctx, path, etag)
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusNotModified:
		return nil, "", resp.StatusCode, nil
	default:
		return nil, "", resp.StatusCode, fmt.Errorf("%s: HTTP %s", path, resp.Status)
	}
	f, err := os.CreateTemp(s.TempDir, "osv-*.zip")
	if err != nil {
		return nil, "", 0, err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxDump+1))
	if err == nil && n > maxDump {
		err = fmt.Errorf("%s is larger than %d bytes", path, int64(maxDump))
	}
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, "", 0, err
	}
	return f, resp.Header.Get("ETag"), resp.StatusCode, nil
}

// get fetches a small file whole.
func (s *Syncer) get(ctx context.Context, path string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	resp, err := s.request(ctx, path, "")
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, resp.StatusCode, nil
	default:
		return nil, resp.StatusCode, fmt.Errorf("%s: HTTP %s", path, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	return b, resp.StatusCode, err
}

func (s *Syncer) request(ctx context.Context, path, etag string) (*http.Response, error) {
	var segs []string
	for _, p := range strings.Split(path, "/") {
		segs = append(segs, url.PathEscape(p))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.URL, "/")+"/"+strings.Join(segs, "/"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Baseline")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	c := s.Client
	if c == nil {
		c = http.DefaultClient
	}
	return c.Do(req)
}

// MatchEcosystem matches every host of an ecosystem again.
func (s *Syncer) MatchEcosystem(ctx context.Context, eco string) error {
	hosts, err := s.Store.VulnHosts(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, h := range hosts {
		if e, ok := For(h.OSID, h.OSVersion); ok && e.Name == eco {
			if err := s.MatchHost(ctx, h.ID); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// MatchHost matches one host's packages against its ecosystem's data.
func (s *Syncer) MatchHost(ctx context.Context, hostID string) error {
	hosts, err := s.Store.VulnHosts(ctx)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(hosts, func(h store.VulnHostRef) bool { return h.ID == hostID })
	if i < 0 {
		return nil // revoked or gone
	}
	e, ok := For(hosts[i].OSID, hosts[i].OSVersion)
	if !ok {
		return s.save(ctx, hostID, "", nil)
	}
	pkgs, ups, err := s.Store.MatchInput(ctx, hostID)
	if err != nil {
		return err
	}
	var names []string
	for _, p := range pkgs {
		n := p.Source
		if n == "" {
			n = p.Name
		}
		if slices.Contains(e.Managers, p.Manager) && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	affected, err := s.Store.AffectedFor(ctx, e.Name, names)
	if err != nil {
		return err
	}
	cands := map[string]string{}
	for _, u := range ups {
		cands[CandidateKey(u.Manager, u.Name, u.Arch)] = u.Candidate
	}
	return s.save(ctx, hostID, e.Name, Match(e, pkgs, cands, affected))
}

func (s *Syncer) save(ctx context.Context, hostID, eco string, matches []store.HostVuln) error {
	if err := s.Store.SaveHostVulns(ctx, hostID, eco, matches); err != nil {
		return err
	}
	if s.Matched != nil {
		s.Matched(hostID)
	}
	return nil
}

func (s *Syncer) logf(level jw6_utils.LogLevel, format string, args ...any) {
	if s.Log != nil {
		s.Log.Log("Vuln", "sync", level, fmt.Sprintf(format, args...))
	}
}
