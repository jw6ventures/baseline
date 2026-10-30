// Package change runs the change lifecycle around the jobs dispatcher
// (docs/change-management.md): it starts approved changes when their
// maintenance window opens and no freeze covers their hosts, carries hosts
// over when a window closes, runs patch groups on their schedules (block
// checks, soak, promotion of validated versions) and updates Compose
// stacks that are set to update themselves.
package change

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/scheduler"
	"github.com/jw6ventures/baseline/internal/store"
)

// Every is how often the scheduler looks at patch groups, cycles and
// stacks.
const Every = 30 * time.Second

type Manager struct {
	St  *store.Store
	Log *jw6_utils.Utils
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Nudge asks the dispatcher for a pass, after the scheduler made a
	// change that may start now.
	Nudge func()
}

func New(st *store.Store, log *jw6_utils.Utils) *Manager { return &Manager{St: st, Log: log} }

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Run does the scheduled work every Every until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(Every)
	defer t.Stop()
	for {
		m.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick finishes cycles whose change ended, starts patch groups that are
// due and updates stacks that drifted.
func (m *Manager) Tick(ctx context.Context) {
	now := m.now()
	if err := m.FinishCycles(ctx); err != nil {
		m.errorf(ctx, "finish patch cycles: %v", err)
	}
	created := false
	n, err := m.RunPatchGroups(ctx, now)
	if err != nil {
		m.errorf(ctx, "patch groups: %v", err)
	}
	created = created || n > 0
	n, err = m.AutoUpdate(ctx, now)
	if err != nil {
		m.errorf(ctx, "compose auto-update: %v", err)
	}
	created = created || n > 0
	if created && m.Nudge != nil {
		m.Nudge()
	}
}

// Windows -----------------------------------------------------------------------

// Window is a maintenance window or freeze with its schedule read.
type Window struct {
	store.MaintenanceWindow
	Sched scheduler.Window
}

// Compile reads a window's schedule and time zone.
func Compile(w store.MaintenanceWindow) (Window, error) {
	s, err := scheduler.Parse(w.Cron)
	if err != nil {
		return Window{}, err
	}
	loc, err := time.LoadLocation(w.TZ)
	if err != nil {
		return Window{}, fmt.Errorf("time zone %q: %w", w.TZ, err)
	}
	return Window{MaintenanceWindow: w, Sched: scheduler.Window{Schedule: s, Duration: w.Duration, Location: loc}}, nil
}

// Calendar is every window and freeze, and the hosts' groups, as one
// scheduling pass sees them.
type Calendar struct {
	Windows map[string]Window // by ID, windows and freezes
	Freezes []Window          // active ones
	Groups  map[string][]string
	Hosts   map[string]store.Host
}

// LoadCalendar reads windows, freezes and hosts. Windows whose schedule
// can't be read are left out (they were checked when saved).
func (m *Manager) LoadCalendar(ctx context.Context) (*Calendar, error) {
	ws, err := m.St.ListWindows(ctx)
	if err != nil {
		return nil, err
	}
	hosts, err := m.St.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	c := &Calendar{Windows: map[string]Window{}, Groups: map[string][]string{}, Hosts: map[string]store.Host{}}
	for _, w := range ws {
		cw, err := Compile(w)
		if err != nil {
			m.logf(jw6_utils.Warn, "Window %s: %v", w.Name, err)
			continue
		}
		c.Windows[w.ID] = cw
		if w.Kind == store.WindowKindFreeze && w.Active {
			c.Freezes = append(c.Freezes, cw)
		}
	}
	for _, h := range hosts {
		c.Groups[h.ID] = h.GroupIDs
		c.Hosts[h.ID] = h
	}
	return c, nil
}

// FreezeAt returns a freeze in effect at t on any of the hosts, and its
// opening.
func (c *Calendar) FreezeAt(t time.Time, hostIDs []string) (Window, scheduler.Opening, bool) {
	for _, f := range c.Freezes {
		if !slices.ContainsFunc(hostIDs, func(h string) bool { return f.Covers(c.Groups[h]) }) {
			continue
		}
		if o, ok := f.Sched.At(t); ok {
			return f, o, true
		}
	}
	return Window{}, scheduler.Opening{}, false
}

// FrozenHosts maps the hosts a freeze covers right now to its name.
func (c *Calendar) FrozenHosts(t time.Time) map[string]string {
	out := map[string]string{}
	for id := range c.Hosts {
		if f, _, ok := c.FreezeAt(t, []string{id}); ok {
			out[id] = f.Name
		}
	}
	return out
}

// WindowFor is the first active window (not freeze) that covers the host,
// by its next opening, for stacks without a window of their own.
func (c *Calendar) WindowFor(hostID string, t time.Time) (Window, bool) {
	var best Window
	var bestStart time.Time
	for _, w := range c.Windows {
		if w.Kind != store.WindowKindWindow || !w.Active || !w.Covers(c.Groups[hostID]) {
			continue
		}
		o := w.Sched.NextOpening(t)
		if o.IsZero() {
			continue
		}
		if bestStart.IsZero() || o.Start.Before(bestStart) || (o.Start.Equal(bestStart) && w.Name < best.Name) {
			best, bestStart = w, o.Start
		}
	}
	return best, !bestStart.IsZero()
}

// maxSteps bounds the search for a start time that is inside the window
// and outside every freeze.
const maxSteps = 200

// Plan finds when a change can start, from t on: inside its window's next
// opening (end is that opening's end), outside any freeze on its hosts
// unless it is an Emergency change, and not before its planned start. note
// says why it waits, if it does.
func (c *Calendar) Plan(ch store.Change, t time.Time) (start, end time.Time, note string, err error) {
	from := t
	if ch.PlannedStart.After(t) {
		t = ch.PlannedStart
	}
	var win *Window
	if ch.WindowID != "" {
		w, ok := c.Windows[ch.WindowID]
		if !ok {
			return t, end, note, errors.New("its maintenance window can't be read")
		}
		if !w.Active {
			return t, end, note, fmt.Errorf("its maintenance window %s is turned off", w.Name)
		}
		win = &w
	}
	for range maxSteps {
		end = time.Time{}
		if win != nil {
			o := win.Sched.NextOpening(t)
			if o.IsZero() {
				return t, end, note, fmt.Errorf("its maintenance window %s never opens", win.Name)
			}
			if o.Start.After(t) {
				t = o.Start
				note = "waiting for maintenance window " + win.Name
			}
			end = o.End
		}
		if ch.Kind != store.KindEmergency {
			if f, o, ok := c.FreezeAt(t, ch.HostIDs); ok {
				if o.Endless() {
					return t, end, note, fmt.Errorf("freeze %s never lifts", f.Name)
				}
				t = o.End
				note = "held by freeze " + f.Name
				continue
			}
		}
		if !t.After(from) {
			note = ""
		}
		return t, end, note, nil
	}
	return t, end, note, errors.New("no time inside its window is free of freezes")
}

// Gate is what the dispatcher must respect on a pass.
type Gate struct {
	// Frozen maps hosts under a freeze now to the freeze's name: only
	// Emergency changes' jobs start on them.
	Frozen map[string]string
}

// Advance starts approved and scheduled changes whose time has come,
// schedules the others, and handles changes whose window closed. The
// dispatcher calls it before each pass.
func (m *Manager) Advance(ctx context.Context) (Gate, error) {
	now := m.now()
	cal, err := m.LoadCalendar(ctx)
	if err != nil {
		return Gate{}, err
	}
	gate := Gate{Frozen: cal.FrozenHosts(now)}
	waiting, err := m.St.ListChanges(ctx, store.ChangeFilter{States: []string{store.ChangeApproved, store.ChangeScheduled}, Limit: 1000})
	if err != nil {
		return gate, err
	}
	for _, ch := range waiting {
		if ch.State == store.ChangeScheduled && ch.PlannedStart.After(now) {
			continue
		}
		start, end, note, err := cal.Plan(ch, now)
		switch {
		case err != nil:
			if ch.ScheduleNote != "can't be scheduled: "+err.Error() {
				m.logf(jw6_utils.Warn, "%s can't be scheduled: %v", ch.Ref(), err)
			}
			err = m.St.NoteSchedule(ctx, ch.ID, "can't be scheduled: "+err.Error())
		case !start.After(now):
			if err = m.St.StartChange(ctx, ch.ID, end); err == nil {
				m.logf(jw6_utils.Info, "%s is in progress", ch.Ref())
			}
		default:
			err = m.St.ScheduleChange(ctx, ch.ID, start, end, note)
		}
		if err != nil && !errors.Is(err, store.ErrState) {
			m.errorf(ctx, "%s: %v", ch.Ref(), err)
		}
	}

	running, err := m.St.ListChanges(ctx, store.ChangeFilter{States: []string{store.ChangeInProgress}, Limit: 1000})
	if err != nil {
		return gate, err
	}
	for _, ch := range running {
		if ch.WindowEndsAt.IsZero() || ch.WindowEndsAt.After(now) {
			continue
		}
		var next, nextEnd time.Time
		if ch.OnWindowEnd == store.WindowCarryOver {
			ch.PlannedStart = time.Time{}
			if next, nextEnd, _, err = cal.Plan(ch, now); err != nil {
				next, nextEnd = time.Time{}, time.Time{}
				m.logf(jw6_utils.Warn, "%s can't carry over: %v", ch.Ref(), err)
			}
		}
		if err := m.St.WindowClosed(ctx, ch.ID, next, nextEnd); err != nil {
			m.errorf(ctx, "%s: window closed: %v", ch.Ref(), err)
		}
	}
	return gate, nil
}

// CheckStart is what the UI asks before creating a change planned for t:
// an error if a freeze covers the hosts then and the change isn't an
// Emergency one, or the window never opens.
func (m *Manager) CheckStart(ctx context.Context, ch store.Change, t time.Time) error {
	cal, err := m.LoadCalendar(ctx)
	if err != nil {
		return err
	}
	if !ch.PlannedStart.IsZero() && ch.Kind != store.KindEmergency {
		if f, o, ok := cal.FreezeAt(ch.PlannedStart, ch.HostIDs); ok {
			return fmt.Errorf("freeze %s covers that time (until %s); pick another time, or make it an Emergency change",
				f.Name, o.End.UTC().Format("2006-01-02 15:04 MST"))
		}
	}
	if ch.WindowID != "" {
		w, ok := cal.Windows[ch.WindowID]
		if !ok {
			return errors.New("no such maintenance window")
		}
		if !w.Active {
			return fmt.Errorf("maintenance window %s is turned off", w.Name)
		}
		for _, h := range ch.HostIDs {
			if !w.Covers(cal.Groups[h]) {
				return fmt.Errorf("maintenance window %s doesn't cover %s", w.Name, cal.Hosts[h].DisplayName())
			}
		}
		if w.Sched.NextOpening(t).IsZero() {
			return fmt.Errorf("maintenance window %s never opens", w.Name)
		}
	}
	return nil
}

func (m *Manager) logf(level jw6_utils.LogLevel, format string, args ...any) {
	if m.Log != nil {
		m.Log.Log("Changes", "schedule", level, fmt.Sprintf(format, args...))
	}
}

func (m *Manager) errorf(ctx context.Context, format string, args ...any) {
	if ctx.Err() == nil {
		m.logf(jw6_utils.Error, format, args...)
	}
}

// joinNames lists names for a message: "a, b and c".
func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}
