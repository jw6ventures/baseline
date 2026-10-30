// Package alert evaluates alert rules (docs/data-model.md §7): every minute
// each enabled rule's kind finds what is wrong now, alerts open, fire,
// remind and resolve, silences mute them, and notifications go to the
// rule's channels through the outbox (internal/notify).
package alert

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/store"
)

// Param is one setting of a rule kind, as the rule form shows it.
type Param struct {
	Key   string // AlertParams JSON name
	Label string
	Type  string // number | bool | severity | list
	Help  string
}

// Kind is a condition rules can watch.
type Kind struct {
	Key      string
	Label    string
	Help     string
	Params   []Param
	Defaults store.AlertParams
}

// Kinds lists every rule kind in the order the UI offers them.
var Kinds = []Kind{
	{Key: "host_offline", Label: "Host offline", Help: "The agent hasn't been connected for a while.",
		Params: []Param{{"minutes", "Offline for at least (minutes)", "number", ""}}, Defaults: store.AlertParams{Minutes: 10}},
	{Key: "disk_full", Label: "Filesystem almost full", Help: "A filesystem's latest usage reading, as df shows it.",
		Params: []Param{{"percent", "Used at least (%)", "number", ""}}, Defaults: store.AlertParams{Percent: 90}},
	{Key: "inodes_full", Label: "Inodes almost used up", Help: "A filesystem's latest inode usage reading.",
		Params: []Param{{"percent", "Used at least (%)", "number", ""}}, Defaults: store.AlertParams{Percent: 90}},
	{Key: "smart", Label: "Drive failing or degrading", Help: "A drive fails its SMART self-assessment (always critical), or shows early signs: its bad sector count (reallocated, pending or uncorrectable sectors, media errors) rising, NVMe warnings or wear. A few bad sectors that stay put don't alert.",
		Params: []Param{{"degrading", "Also alert on early signs", "bool", ""},
			{"days", "Bad sectors rose within (days)", "number", "A drive whose count stopped rising this long ago stops alerting."},
			{"sectors", "Or at least this many bad sectors", "number", "Alert on a count this high even when it holds steady; 0 for never."}},
		Defaults: store.AlertParams{Degrading: true, Days: 7, Sectors: 100}},
	{Key: "failed_units", Label: "Failed systemd units", Help: "A service unit is in the failed state.",
		Params: []Param{{"exclude", "Ignore units", "list", "Unit names or patterns, comma-separated, e.g. fwupd-refresh.service, snap.*"}}},
	{Key: "cert_expiry", Label: "Certificate expiring", Help: "A certificate on a host or an agentless endpoint expires soon (expired ones are critical).",
		Params: []Param{{"days", "Expires within (days)", "number", ""}}, Defaults: store.AlertParams{Days: 14}},
	{Key: "reboot_pending", Label: "Reboot pending", Help: "A host has needed a reboot for a while.",
		Params: []Param{{"days", "Pending for at least (days)", "number", ""}}, Defaults: store.AlertParams{Days: 7}},
	{Key: "cve_fixable", Label: "Fixable CVEs", Help: "A host has vulnerabilities that its pending updates fix.",
		Params: []Param{{"min_severity", "Rated at least", "severity", ""}}, Defaults: store.AlertParams{MinSeverity: "high"}},
	{Key: "patch_cycle", Label: "Patch cycle failed or blocked", Help: "A patch group's latest cycle failed or was blocked.",
		Params: []Param{{"partial", "Also when only some hosts were patched", "bool", ""}}, Defaults: store.AlertParams{Partial: true}},
	{Key: "unplanned_change", Label: "Unplanned change", Help: "A host's packages, services, ports, containers or hardware changed without a change record (drift). Hosts that patch themselves trigger it daily.",
		Params: []Param{{"hours", "Within the last (hours)", "number", ""}}, Defaults: store.AlertParams{Hours: 24}},
	{Key: "hardware_change", Label: "Hardware change on a high security host", Help: "On a host marked high security, without a change record: a disk, DIMM, physical NIC, PCI or USB device was added, removed or swapped, a network link went up or down, or a display was connected or disconnected. Each change stays firing until someone acknowledges it."},
	{Key: "compose_drift", Label: "Compose file changed on the host", Help: "The Compose file of a stack Baseline deployed or edited no longer matches what Baseline last wrote: someone changed it on the host. Closing it puts that version away; a further change alerts again. Deploying or editing the stack through Baseline resolves it."},
	{Key: "unifi_offline", Label: "UniFi device offline", Help: "A device or Protect camera a UniFi console reports has been offline for a while, or the console itself couldn't be read for that long.",
		Params: []Param{{"minutes", "Offline for at least (minutes)", "number", ""}}, Defaults: store.AlertParams{Minutes: 10}},
	{Key: "unifi_firmware", Label: "UniFi firmware update", Help: "A UniFi console offers a firmware update for one of its devices."},
	{Key: "change_approval", Label: "Change awaiting approval", Help: "A submitted change hasn't been approved or rejected yet.",
		Params: []Param{{"hours", "Waiting for at least (hours)", "number", ""}}, Defaults: store.AlertParams{Hours: 4}},
}

// KindByKey finds a kind.
func KindByKey(key string) (Kind, bool) {
	i := slices.IndexFunc(Kinds, func(k Kind) bool { return k.Key == key })
	if i < 0 {
		return Kind{}, false
	}
	return Kinds[i], true
}

// Severities of alerts, least severe first.
var Severities = []string{"info", "warning", "critical"}

// VulnSeverities are the ratings cve_fixable can start from.
var VulnSeverities = []string{"low", "medium", "high", "critical"}

func rank(sev string) int { return slices.Index(Severities, sev) }

// Check validates a rule's settings and keeps only those its kind reads.
func Check(r store.AlertRule) (store.AlertRule, error) {
	k, ok := KindByKey(r.Kind)
	if !ok {
		return r, fmt.Errorf("unknown kind %q", r.Kind)
	}
	if strings.TrimSpace(r.Name) == "" {
		return r, errors.New("enter a name")
	}
	if rank(r.Severity) < 0 {
		return r, errors.New("pick a severity")
	}
	if r.For < 0 || r.Repeat < 0 || (r.Repeat > 0 && r.Repeat < 5*time.Minute) {
		return r, errors.New("reminders can't be more often than every 5 minutes")
	}
	in, out := r.Params, store.AlertParams{}
	for _, p := range k.Params {
		switch p.Key {
		case "minutes":
			if in.Minutes < 1 {
				return r, errors.New("minutes must be at least 1")
			}
			out.Minutes = in.Minutes
		case "percent":
			if in.Percent < 1 || in.Percent > 100 {
				return r, errors.New("the percentage must be between 1 and 100")
			}
			out.Percent = in.Percent
		case "days":
			if in.Days < 1 {
				return r, errors.New("days must be at least 1")
			}
			out.Days = in.Days
		case "hours":
			if in.Hours < 0 || (in.Hours == 0 && k.Key == "unplanned_change") {
				return r, errors.New("enter a number of hours")
			}
			out.Hours = in.Hours
		case "degrading":
			out.Degrading = in.Degrading
		case "sectors":
			if in.Sectors < 0 {
				return r, errors.New("the bad sector count can't be negative")
			}
			out.Sectors = in.Sectors
		case "partial":
			out.Partial = in.Partial
		case "min_severity":
			if !slices.Contains(VulnSeverities, in.MinSeverity) {
				return r, errors.New("pick a CVE severity")
			}
			out.MinSeverity = in.MinSeverity
		case "exclude":
			for _, x := range in.Exclude {
				if x = strings.TrimSpace(x); x != "" {
					out.Exclude = append(out.Exclude, x)
				}
			}
		}
	}
	r.Params = out
	return r, nil
}

// Conditions asks the store what a rule's kind finds now.
func Conditions(ctx context.Context, st *store.Store, r store.AlertRule) ([]store.Condition, error) {
	p := r.Params
	switch r.Kind {
	case "host_offline":
		return st.OfflineHosts(ctx, time.Duration(p.Minutes)*time.Minute)
	case "disk_full":
		return st.FullFilesystems(ctx, "used_pct", p.Percent)
	case "inodes_full":
		return st.FullFilesystems(ctx, "inodes_used_pct", p.Percent)
	case "smart":
		return st.SmartProblems(ctx, p.Degrading, time.Duration(p.Days)*24*time.Hour, int64(p.Sectors))
	case "failed_units":
		return st.FailedUnits(ctx, p.Exclude)
	case "cert_expiry":
		return st.ExpiringCertificates(ctx, time.Duration(p.Days)*24*time.Hour)
	case "reboot_pending":
		return st.RebootsPending(ctx, time.Duration(p.Days)*24*time.Hour)
	case "cve_fixable":
		return st.FixableVulns(ctx, p.MinSeverity)
	case "patch_cycle":
		return st.FailedPatchCycles(ctx, p.Partial)
	case "unplanned_change":
		return st.UnplannedChanges(ctx, time.Duration(p.Hours)*time.Hour)
	case "hardware_change":
		return st.HardwareChanges(ctx, r.ID, keepAlerts)
	case "compose_drift":
		return st.ComposeFileDrift(ctx)
	case "unifi_offline":
		return st.UniFiDevicesOffline(ctx, time.Duration(p.Minutes)*time.Minute)
	case "unifi_firmware":
		return st.UniFiFirmware(ctx)
	case "change_approval":
		return st.ChangesAwaitingApproval(ctx, time.Duration(p.Hours)*time.Hour)
	}
	return nil, fmt.Errorf("unknown kind %q", r.Kind)
}

const (
	// Every is how often rules are evaluated.
	Every = time.Minute
	// Resolved alerts are kept this long, delivered notifications less.
	keepAlerts        = 90 * 24 * time.Hour
	keepNotifications = 30 * 24 * time.Hour
)

type Evaluator struct {
	Store *store.Store
	Log   *jw6_utils.Utils
	// PublicURL is the UI's absolute URL, for links in notifications.
	PublicURL string
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Nudge tells the notifier there is something to send.
	Nudge func()

	lastPurge time.Time
}

func (e *Evaluator) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Run evaluates every minute until ctx ends.
func (e *Evaluator) Run(ctx context.Context) {
	t := time.NewTicker(Every)
	defer t.Stop()
	for {
		if err := e.Pass(ctx); err != nil && ctx.Err() == nil {
			e.logf(jw6_utils.Error, "alerts: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Pass evaluates every enabled rule once and writes the outcome.
func (e *Evaluator) Pass(ctx context.Context) error {
	// Postgres keeps microseconds: compare times as they will read back.
	now := e.now().Truncate(time.Microsecond)
	rules, err := e.Store.ListAlertRules(ctx)
	if err != nil {
		return err
	}
	open, err := e.Store.ListAlerts(ctx, store.AlertFilter{Tracked: true, Limit: 100000})
	if err != nil {
		return err
	}
	all, err := e.Store.ListSilences(ctx, now)
	if err != nil {
		return err
	}
	var silences []store.Silence
	for _, sl := range all {
		if sl.Active(now) {
			silences = append(silences, sl)
		}
	}
	channels, err := e.Store.ListChannels(ctx)
	if err != nil {
		return err
	}
	enabledCh := map[string]bool{}
	for _, c := range channels {
		enabledCh[c.ID] = c.Enabled
	}

	byKey := map[string]store.Alert{}
	for _, a := range open {
		byKey[a.RuleID+"|"+a.CIID+"|"+a.Key] = a
	}
	byRule := map[string]store.AlertRule{}
	failed := map[string]bool{}
	seen := map[string]bool{}
	var ch store.AlertChanges
	var errs []error
	notify := func(r store.AlertRule, a store.Alert, event string) bool {
		sent := false
		for _, id := range r.Channels {
			if enabledCh[id] {
				ch.Notify = append(ch.Notify, e.message(id, event, r, a, now))
				sent = true
			}
		}
		return sent
	}

	for _, r := range rules {
		byRule[r.ID] = r
		if !r.Enabled {
			continue
		}
		conds, err := Conditions(ctx, e.Store, r)
		if err != nil {
			// Keep its alerts as they are rather than resolve them.
			failed[r.ID] = true
			errs = append(errs, fmt.Errorf("rule %q: %w", r.Name, err))
			continue
		}
		for _, c := range conds {
			if !r.Covers(c.GroupIDs) {
				continue
			}
			sev := r.Severity
			if rank(c.Severity) > rank(sev) {
				sev = c.Severity
			}
			a, ok := byKey[r.ID+"|"+c.CIID+"|"+c.Key]
			if ok && a.State == store.AlertClosed && !seen[a.ID] {
				seen[a.ID] = true
				if c.Level <= a.ClosedLevel && rank(sev) <= rank(a.ClosedSeverity) {
					// Closed and no worse: keep it current, out of sight.
					a.Subject, a.Link, a.GroupIDs, a.Summary, a.Details, a.LastAt = c.Subject, c.Link, c.GroupIDs, c.Summary, c.Details, now
					a.Severity, a.Level = sev, c.Level
					ch.Update = append(ch.Update, a)
					continue
				}
				// Worse than when it was closed: that one is done, and
				// this is a new alert.
				ch.Resolve = append(ch.Resolve, a.ID)
				ok = false
			}
			if !ok {
				a = store.Alert{ID: store.NewAlertID(), RuleID: r.ID, CIID: c.CIID, Key: c.Key, State: store.AlertPending,
					FirstAt: now}
			}
			if seen[a.ID] {
				continue // a kind listed one subject twice
			}
			seen[a.ID] = true
			a.Subject, a.Link, a.GroupIDs, a.Summary, a.Details, a.LastAt = c.Subject, c.Link, c.GroupIDs, c.Summary, c.Details, now
			a.Severity, a.Level = sev, c.Level
			if a.State == store.AlertPending && now.Sub(a.FirstAt) >= r.For {
				a.State, a.FiredAt = store.AlertFiring, now
			}
			a.SilenceID = ""
			if i := slices.IndexFunc(silences, func(sl store.Silence) bool { return sl.Matches(a) }); i >= 0 {
				a.SilenceID = silences[i].ID
			}
			if a.State == store.AlertFiring && !a.Silenced() {
				switch {
				case a.NotifiedAt.IsZero():
					if notify(r, a, store.EventFiring) {
						a.NotifiedAt = now
					}
				case r.Repeat > 0 && !a.Acked() && now.Sub(a.NotifiedAt) >= r.Repeat:
					if notify(r, a, store.EventReminder) {
						a.NotifiedAt = now
					}
				}
			}
			if ok {
				ch.Update = append(ch.Update, a)
			} else {
				ch.Insert = append(ch.Insert, a)
			}
		}
	}
	for _, a := range open {
		if seen[a.ID] || failed[a.RuleID] {
			continue
		}
		if a.State == store.AlertPending {
			ch.Delete = append(ch.Delete, a.ID)
			continue
		}
		ch.Resolve = append(ch.Resolve, a.ID)
		if a.State == store.AlertClosed {
			continue // its notifications ended when it was closed
		}
		// A rule that was disabled resolves its alerts quietly.
		if r, ok := byRule[a.RuleID]; ok && r.Enabled && r.NotifyResolved && !a.NotifiedAt.IsZero() && !a.Silenced() {
			a.ResolvedAt = now
			notify(r, a, store.EventResolved)
		}
	}
	if !ch.Empty() {
		if err := e.Store.ApplyAlerts(ctx, ch); err != nil {
			return err
		}
		if len(ch.Notify) > 0 && e.Nudge != nil {
			e.Nudge()
		}
	}
	if now.Sub(e.lastPurge) >= time.Hour {
		if err := e.Store.PurgeAlerts(ctx, now.Add(-keepAlerts), now.Add(-keepNotifications)); err != nil {
			errs = append(errs, err)
		} else {
			e.lastPurge = now
		}
	}
	return errors.Join(errs...)
}

// message renders a notification for one channel.
func (e *Evaluator) message(channelID, event string, r store.AlertRule, a store.Alert, now time.Time) store.Notification {
	tag := strings.ToUpper(a.Severity)
	title := fmt.Sprintf("[%s] %s", tag, r.Name)
	body := a.Summary
	switch event {
	case store.EventReminder:
		title = fmt.Sprintf("[%s] Still firing: %s", tag, r.Name)
		body += fmt.Sprintf(" (firing for %s)", since(now.Sub(a.FiredAt)))
	case store.EventResolved:
		title = "[RESOLVED] " + r.Name
		body += fmt.Sprintf(" (resolved after %s)", since(now.Sub(a.FiredAt)))
	}
	return store.Notification{ChannelID: channelID, AlertID: a.ID, Event: event, Severity: a.Severity, Title: title,
		Body: body, Link: strings.TrimRight(e.PublicURL, "/") + "/alerts/" + a.ID, NextAt: now}
}

// since is a short duration: "45s", "12m", "3h20m", "2d4h".
func since(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
}

func (e *Evaluator) logf(level jw6_utils.LogLevel, format string, args ...any) {
	if e.Log != nil {
		e.Log.Log("Alert", "evaluate", level, fmt.Sprintf(format, args...))
	}
}
