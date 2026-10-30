package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/inventory"
)

// Condition is something a rule kind found wrong now: the subject (a CI,
// or an object without one), the key within it, and what to say.
type Condition struct {
	CIID     string
	Subject  string
	Key      string
	Link     string
	GroupIDs []string
	Summary  string
	Details  map[string]any
	// Severity overrides the rule's when the finding is worse than the
	// rule's kind usually is (a drive failing, a certificate expired).
	Severity string
	// Level measures how bad it is where a kind can count that (a drive's
	// bad sectors): a closed alert comes back when it rises.
	Level int64
}

// hostGroupsSQL lists a host's group IDs; h is the host table's alias.
const hostGroupsSQL = `ARRAY(SELECT m.group_id::text FROM host_group_member m WHERE m.ci_id = h.ci_id)`

func hostName(hostname, id string) string {
	if hostname != "" {
		return hostname
	}
	return "host " + id[:8]
}

func when(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 MST") }

// OfflineHosts: hosts that haven't been heard from for d.
func (s *Store) OfflineHosts(ctx context.Context, d time.Duration) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.ci_id, h.hostname, `+hostGroupsSQL+`, COALESCE(h.last_seen, h.enrolled_at)
		FROM host h WHERE NOT h.revoked AND NOT h.connected AND COALESCE(h.last_seen, h.enrolled_at) < now() - $1 * interval '1 second'`,
		d.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
	for rows.Next() {
		var c Condition
		var hostname string
		var seen time.Time
		if err := rows.Scan(&c.CIID, &hostname, pq.Array(&c.GroupIDs), &seen); err != nil {
			return nil, err
		}
		c.Subject, c.Link = hostName(hostname, c.CIID), "/hosts/"+c.CIID
		c.Summary = fmt.Sprintf("%s is offline, last seen %s", c.Subject, when(seen))
		c.Details = map[string]any{"last_seen": seen}
		out = append(out, c)
	}
	return out, rows.Err()
}

// FullFilesystems: filesystems whose latest reading (from the last 15
// minutes) of the metric name is at least percent: "used_pct" or
// "inodes_used_pct".
func (s *Store) FullFilesystems(ctx context.Context, name string, percent int) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.ci_id, h.hostname, `+hostGroupsSQL+`, l.instance, l.value
		FROM (SELECT DISTINCT ON (ms.id) ms.host, ms.instance, r.value
		      FROM metric_series ms JOIN metric_raw r ON r.series_id = ms.id
		      WHERE ms.kind = 'fs' AND ms.name = $1 AND r.ts > now() - interval '15 minutes'
		      ORDER BY ms.id, r.ts DESC) l
		JOIN host h ON h.ci_id = l.host
		WHERE NOT h.revoked AND l.value >= $2
		ORDER BY h.ci_id, l.instance`, name, percent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	what := "full"
	if name != "used_pct" {
		what = "of its inodes used"
	}
	var out []Condition
	for rows.Next() {
		var c Condition
		var hostname string
		var value float64
		if err := rows.Scan(&c.CIID, &hostname, pq.Array(&c.GroupIDs), &c.Key, &value); err != nil {
			return nil, err
		}
		c.Subject, c.Link = hostName(hostname, c.CIID), "/hosts/"+c.CIID+"?tab=metrics"
		c.Summary = fmt.Sprintf("%s: %s is %.0f%% %s", c.Subject, c.Key, value, what)
		c.Details = map[string]any{"mountpoint": c.Key, "percent": value}
		out = append(out, c)
	}
	return out, rows.Err()
}

// smartBadSQL is model.SmartDevice.BadSectors over a host_smart row d.
const smartBadSQL = `(COALESCE((d.attrs->>'reallocated')::bigint, 0) + COALESCE((d.attrs->>'pending')::bigint, 0) +
	COALESCE((d.attrs->>'uncorrectable')::bigint, 0) + COALESCE((d.attrs->>'media_errors')::bigint, 0))`

// SmartProblems: drives failing their self-assessment (critical), and with
// degrading, drives showing early signs. Bad sectors count only while the
// count rose in the last `within`, or once it reaches `sectors` (0: never):
// a few that stay put aren't worth a page. NVMe warnings and wear always
// count. The condition's level is the bad sector count, so a closed alert
// comes back when it rises.
func (s *Store) SmartProblems(ctx context.Context, degrading bool, within time.Duration, sectors int64) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.ci_id, h.hostname, `+hostGroupsSQL+`, d.device, d.model, d.serial, d.passed IS FALSE,
		       COALESCE((d.attrs->>'reallocated')::bigint, 0), COALESCE((d.attrs->>'pending')::bigint, 0),
		       COALESCE((d.attrs->>'uncorrectable')::bigint, 0), COALESCE((d.attrs->>'media_errors')::bigint, 0),
		       COALESCE((d.attrs->>'percent_used')::bigint, 0), COALESCE(d.rose_at > now() - $2 * interval '1 second', false)
		FROM host_smart d JOIN host h ON h.ci_id = d.host
		WHERE NOT h.revoked AND (d.passed = false OR ($1 AND d.degrading AND (
		      d.rose_at > now() - $2 * interval '1 second' OR ($3 > 0 AND `+smartBadSQL+` >= $3)
		      OR COALESCE((d.attrs->>'critical_warning')::bigint, 0) <> 0 OR COALESCE((d.attrs->>'percent_used')::bigint, 0) >= 90)))
		ORDER BY h.ci_id, d.device`, degrading, within.Seconds(), sectors)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
	for rows.Next() {
		var c Condition
		var hostname, model, serial string
		var failing, rising bool
		var realloc, pending, uncorr, media, used int64
		if err := rows.Scan(&c.CIID, &hostname, pq.Array(&c.GroupIDs), &c.Key, &model, &serial, &failing,
			&realloc, &pending, &uncorr, &media, &used, &rising); err != nil {
			return nil, err
		}
		c.Level = realloc + pending + uncorr + media
		c.Subject, c.Link = hostName(hostname, c.CIID), "/hosts/"+c.CIID+"?tab=hardware#drive-health"
		drive := c.Key
		if model != "" {
			drive += " (" + model + ")"
		}
		if failing {
			c.Severity = "critical"
			c.Summary = fmt.Sprintf("%s: drive %s is failing its SMART self-assessment", c.Subject, drive)
		} else {
			var signs []string
			for _, x := range []struct {
				n    int64
				what string
			}{{realloc, "reallocated sectors"}, {pending, "pending sectors"}, {uncorr, "uncorrectable errors"},
				{media, "media errors"}} {
				if x.n > 0 {
					signs = append(signs, fmt.Sprintf("%d %s", x.n, x.what))
				}
			}
			if used >= 90 {
				signs = append(signs, fmt.Sprintf("%d%% of its endurance used", used))
			}
			if len(signs) == 0 {
				signs = append(signs, "a critical warning")
			}
			c.Summary = fmt.Sprintf("%s: drive %s is degrading: %s", c.Subject, drive, strings.Join(signs, ", "))
			if rising {
				c.Summary += " (rising)"
			}
		}
		c.Details = map[string]any{"device": c.Key, "model": model, "serial": serial, "failing": failing,
			"reallocated": realloc, "pending": pending, "uncorrectable": uncorr, "media_errors": media, "percent_used": used, "rising": rising}
		out = append(out, c)
	}
	return out, rows.Err()
}

// FailedUnits: systemd units in the failed state, but those matching an
// exclude pattern (path.Match syntax, e.g. "fwupd*").
func (s *Store) FailedUnits(ctx context.Context, exclude []string) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.ci_id, h.hostname, `+hostGroupsSQL+`, v.unit, v.description, v.sub
		FROM host_service v JOIN host h ON h.ci_id = v.host
		WHERE NOT h.revoked AND v.active = 'failed' ORDER BY h.ci_id, v.unit`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
next:
	for rows.Next() {
		var c Condition
		var hostname, desc, sub string
		if err := rows.Scan(&c.CIID, &hostname, pq.Array(&c.GroupIDs), &c.Key, &desc, &sub); err != nil {
			return nil, err
		}
		for _, p := range exclude {
			if ok, _ := path.Match(p, c.Key); ok || p == c.Key {
				continue next
			}
		}
		c.Subject, c.Link = hostName(hostname, c.CIID), "/hosts/"+c.CIID+"?tab=services"
		c.Summary = fmt.Sprintf("%s: %s failed", c.Subject, c.Key)
		if desc != "" {
			c.Summary += " (" + desc + ")"
		}
		c.Details = map[string]any{"unit": c.Key, "description": desc, "sub": sub}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ExpiringCertificates: certificates on any CI that expire within d;
// expired ones are critical.
func (s *Store) ExpiringCertificates(ctx context.Context, d time.Duration) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.id, c.type, COALESCE(NULLIF(h.hostname, ''), c.name),
		       ARRAY(SELECT m.group_id::text FROM host_group_member m WHERE m.ci_id = c.id),
		       x.location, x.subject, x.not_after
		FROM ci_cert x JOIN ci c ON c.id = x.ci_id LEFT JOIN host h ON h.ci_id = c.id
		WHERE x.not_after IS NOT NULL AND x.not_after < now() + $1 * interval '1 second'
		  AND COALESCE(NOT h.revoked, true) AND c.status <> 'retired'
		ORDER BY c.id, x.location`, d.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
	now := time.Now()
	for rows.Next() {
		var c Condition
		var typ, subj string
		var notAfter time.Time
		if err := rows.Scan(&c.CIID, &typ, &c.Subject, pq.Array(&c.GroupIDs), &c.Key, &subj, &notAfter); err != nil {
			return nil, err
		}
		c.Link = "/cis/" + c.CIID
		if typ == "host" {
			c.Link = "/hosts/" + c.CIID + "?tab=certificates"
		}
		name := subj
		if name == "" {
			name = "the certificate"
		}
		if notAfter.Before(now) {
			c.Severity = "critical"
			c.Summary = fmt.Sprintf("%s: %s at %s expired on %s", c.Subject, name, c.Key, notAfter.UTC().Format("2006-01-02"))
		} else {
			c.Summary = fmt.Sprintf("%s: %s at %s expires on %s", c.Subject, name, c.Key, notAfter.UTC().Format("2006-01-02"))
		}
		c.Details = map[string]any{"location": c.Key, "subject": subj, "not_after": notAfter}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RebootsPending: hosts that have needed a reboot for at least d.
func (s *Store) RebootsPending(ctx context.Context, d time.Duration) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.ci_id, h.hostname, `+hostGroupsSQL+`, h.reboot_required_since, h.reboot_reasons
		FROM host h WHERE NOT h.revoked AND h.reboot_required
		  AND h.reboot_required_since < now() - $1 * interval '1 second'
		ORDER BY h.ci_id`, d.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
	for rows.Next() {
		var c Condition
		var hostname string
		var since time.Time
		var reasons []string
		if err := rows.Scan(&c.CIID, &hostname, pq.Array(&c.GroupIDs), &since, pq.Array(&reasons)); err != nil {
			return nil, err
		}
		c.Subject, c.Link = hostName(hostname, c.CIID), "/hosts/"+c.CIID
		c.Summary = fmt.Sprintf("%s has needed a reboot since %s", c.Subject, since.UTC().Format("2006-01-02"))
		if len(reasons) > 0 {
			c.Summary += ": " + strings.Join(reasons, "; ")
		}
		c.Details = map[string]any{"since": since, "reasons": reasons}
		out = append(out, c)
	}
	return out, rows.Err()
}

// FixableVulns: hosts with vulnerabilities of at least minSeverity that
// their pending updates fix.
func (s *Store) FixableVulns(ctx context.Context, minSeverity string) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.ci_id, h.hostname, `+hostGroupsSQL+`, count(DISTINCT v.vuln_id),
		       count(DISTINCT v.vuln_id) FILTER (WHERE v.severity = 'critical'),
		       (array_agg(DISTINCT v.vuln_id))[1:10]
		FROM host_vuln v JOIN host h ON h.ci_id = v.host
		WHERE NOT h.revoked AND v.fix_available AND `+sevRank("v.severity")+` >= `+sevRank("$1")+`
		GROUP BY h.ci_id ORDER BY h.ci_id`, minSeverity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
	for rows.Next() {
		var c Condition
		var hostname string
		var n, critical int
		var ids []string
		if err := rows.Scan(&c.CIID, &hostname, pq.Array(&c.GroupIDs), &n, &critical, pq.Array(&ids)); err != nil {
			return nil, err
		}
		c.Subject, c.Link = hostName(hostname, c.CIID), "/hosts/"+c.CIID+"?tab=vulnerabilities"
		noun, verb := "vulnerabilities", "are"
		if n == 1 {
			noun, verb = "vulnerability", "is"
		}
		c.Summary = fmt.Sprintf("%s: %d %s rated %s or worse %s fixed by pending updates", c.Subject, n, noun, minSeverity, verb)
		if critical > 0 {
			c.Summary += fmt.Sprintf(" (%d critical)", critical)
		}
		c.Details = map[string]any{"count": n, "critical": critical, "examples": ids}
		out = append(out, c)
	}
	return out, rows.Err()
}

// FailedPatchCycles: enabled patch groups whose latest cycle that ran
// (skipped ones aside) failed or was blocked, or with partial, succeeded on
// only some hosts.
func (s *Store) FailedPatchCycles(ctx context.Context, partial bool) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.id, g.name, g.host_group_id, l.result, l.reason, l.hosts, l.succeeded, COALESCE(l.number, 0),
		       COALESCE(l.finished_at, l.started_at)
		FROM patch_group g
		JOIN LATERAL (SELECT c.result, c.reason, c.hosts, c.succeeded, c.finished_at, c.started_at, ch.number
		              FROM patch_cycle c LEFT JOIN change ch ON ch.id = c.change_id
		              WHERE c.patch_group_id = g.id AND c.result NOT IN ('running', 'skipped')
		              ORDER BY c.started_at DESC LIMIT 1) l ON true
		WHERE g.enabled AND (l.result IN ('failed', 'blocked') OR ($1 AND l.result = 'partial'))
		ORDER BY g.name`, partial)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
	for rows.Next() {
		var c Condition
		var group, result, reason string
		var hosts, ok int
		var number int64
		var at time.Time
		if err := rows.Scan(&c.Key, &c.Subject, &group, &result, &reason, &hosts, &ok, &number, &at); err != nil {
			return nil, err
		}
		c.Subject = "Patch group " + c.Subject
		c.Link, c.GroupIDs = "/patch-groups/"+c.Key, []string{group}
		switch result {
		case "blocked":
			c.Summary = fmt.Sprintf("%s is blocked: %s", c.Subject, reason)
		case "partial":
			c.Summary = fmt.Sprintf("%s patched %d of %d hosts", c.Subject, ok, hosts)
		default:
			c.Summary = fmt.Sprintf("%s failed: %d of %d hosts patched", c.Subject, ok, hosts)
		}
		if number > 0 {
			c.Summary += " (" + ChangeRef(number) + ")"
		}
		c.Details = map[string]any{"result": result, "reason": reason, "hosts": hosts, "succeeded": ok, "at": at}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UnplannedChanges: hosts whose inventory changed in the last d without a
// change behind it (docs/data-model.md §3). Agent upgrades and first
// inventories don't count.
func (s *Store) UnplannedChanges(ctx context.Context, d time.Duration) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.ci_id, h.hostname, `+hostGroupsSQL+`, count(*), array_agg(DISTINCT x.section ORDER BY x.section), max(x.at)
		FROM ci_history x JOIN host h ON h.ci_id = x.ci_id
		WHERE NOT h.revoked AND x.change_id IS NULL AND x.actor LIKE 'agent:%' AND x.section <> 'agent'
		  AND NOT x.diff ? 'initial' AND x.at > now() - $1 * interval '1 second'
		GROUP BY h.ci_id ORDER BY h.ci_id`, d.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
	for rows.Next() {
		var c Condition
		var hostname string
		var n int
		var sections []string
		var last time.Time
		if err := rows.Scan(&c.CIID, &hostname, pq.Array(&c.GroupIDs), &n, pq.Array(&sections), &last); err != nil {
			return nil, err
		}
		c.Subject, c.Link = hostName(hostname, c.CIID), "/hosts/"+c.CIID+"?tab=history"
		noun := "changes"
		if n == 1 {
			noun = "change"
		}
		c.Summary = fmt.Sprintf("%s: %d unplanned %s (%s)", c.Subject, n, noun, strings.Join(sections, ", "))
		c.Details = map[string]any{"count": n, "sections": sections, "last": last}
		out = append(out, c)
	}
	return out, rows.Err()
}

// HardwareChanges: unplanned hardware history entries on high security
// hosts that add, remove or swap a component (inventory.HardwareComponents),
// one per entry, made since the host was flagged. Each holds until an alert
// of ruleID for it is acknowledged or closed; entries older than keep only
// while their alert is still open, since acknowledged alerts are purged
// after that long.
func (s *Store) HardwareChanges(ctx context.Context, ruleID string, keep time.Duration) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.ci_id, h.hostname, `+hostGroupsSQL+`, x.id, x.at, x.diff::text, COALESCE(i.data::text, '{}')
		FROM ci_history x JOIN host h ON h.ci_id = x.ci_id
		LEFT JOIN host_inventory i ON i.host = h.ci_id AND i.section = 'hardware'
		WHERE h.high_security AND NOT h.revoked AND x.section = 'hardware' AND x.at >= h.high_security_since
		  AND x.change_id IS NULL AND x.actor LIKE 'agent:%' AND NOT x.diff ? 'initial'
		  AND NOT EXISTS (SELECT 1 FROM alert a WHERE a.rule_id = $1 AND a.ci_id = x.ci_id
		                  AND a.key = 'hardware:' || x.id AND (a.acked_at IS NOT NULL OR a.closed_at IS NOT NULL))
		  AND (x.at > now() - $2 * interval '1 second'
		       OR EXISTS (SELECT 1 FROM alert a WHERE a.rule_id = $1 AND a.ci_id = x.ci_id
		                  AND a.key = 'hardware:' || x.id AND a.state <> 'resolved'))
		ORDER BY x.id`, ruleID, keep.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
	for rows.Next() {
		var c Condition
		var hostname, diff, current string
		var id int64
		var at time.Time
		if err := rows.Scan(&c.CIID, &hostname, pq.Array(&c.GroupIDs), &id, &at, &diff, &current); err != nil {
			return nil, err
		}
		var d inventory.Diff
		if err := json.Unmarshal([]byte(diff), &d); err != nil {
			return nil, fmt.Errorf("history %d: %w", id, err)
		}
		changes := inventory.HardwareComponents(d, []byte(current))
		if len(changes) == 0 {
			continue
		}
		var parts []string
		for _, ch := range changes {
			parts = append(parts, ch.String())
		}
		c.Subject, c.Link, c.Key = hostName(hostname, c.CIID), "/hosts/"+c.CIID+"?tab=history", fmt.Sprintf("hardware:%d", id)
		c.Summary = fmt.Sprintf("%s: hardware changed at %s: %s", c.Subject, when(at), strings.Join(parts, "; "))
		c.Details = map[string]any{"history_id": id, "at": at, "changes": strings.Join(parts, "; ")}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ChangesAwaitingApproval: changes submitted at least d ago and not yet
// decided.
func (s *Store) ChangesAwaitingApproval(ctx context.Context, d time.Duration) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.id, c.number, c.title, COALESCE(c.submitted_at, c.created_at), c.required_approvals,
		       (SELECT count(*) FROM change_approval a WHERE a.change_id = c.id AND a.decision = 'approve'),
		       ARRAY(SELECT DISTINCT m.group_id::text FROM change_ci x JOIN host_group_member m ON m.ci_id = x.ci_id
		             WHERE x.change_id = c.id)
		FROM change c
		WHERE c.state = 'submitted' AND COALESCE(c.submitted_at, c.created_at) < now() - $1 * interval '1 second'
		ORDER BY c.number`, d.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
	for rows.Next() {
		var c Condition
		var id, title string
		var number int64
		var since time.Time
		var need, have int
		if err := rows.Scan(&id, &number, &title, &since, &need, &have, pq.Array(&c.GroupIDs)); err != nil {
			return nil, err
		}
		c.Key, c.Subject, c.Link = ChangeRef(number), ChangeRef(number), "/changes/"+id
		c.Summary = fmt.Sprintf("%s %q has waited for approval since %s (%d of %d approvals)", c.Key, title, when(since), have, need)
		c.Details = map[string]any{"change_id": id, "title": title, "submitted_at": since, "approvals": have, "required": need}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ComposeFileDrift: stacks whose Compose file on the host isn't the one
// Baseline last wrote to it (the latest compose.deploy or compose.edit that
// changed it and succeeded), as the stack page shows. Only stacks with one
// Compose file count. A write the host hasn't reported its containers since
// doesn't count yet, so the alert neither flickers nor clears early while
// that report is on its way. The key carries the file's hash on the host, so
// a closed alert comes back when the file is changed again.
func (s *Store) ComposeFileDrift(ctx context.Context) ([]Condition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.ci_id, h.hostname, `+hostGroupsSQL+`, cs.ci_id, cs.engine, cs.project,
		       f->>'path', f->>'sha256', r.compose_sha256, COALESCE(c.number, 0), r.finished_at
		FROM compose_stack cs JOIN host h ON h.ci_id = cs.host
		JOIN host_inventory i ON i.host = cs.host AND i.section = 'containers'
		JOIN LATERAL (SELECT r.compose_sha256, r.change_id, j.finished_at
		              FROM compose_revision r JOIN job j ON j.change_id = r.change_id AND j.params->>'revision' = r.id::text
		              WHERE r.host = cs.host AND r.engine = cs.engine AND r.project = cs.project
		                AND r.compose IS NOT NULL AND j.state = 'succeeded' AND j.finished_at < i.received_at
		              ORDER BY j.finished_at DESC LIMIT 1) r ON true
		LEFT JOIN change c ON c.id = r.change_id
		JOIN LATERAL (SELECT x->'config_files' AS files FROM jsonb_array_elements(i.data->'stacks') x
		              WHERE x->>'engine' = cs.engine AND x->>'project' = cs.project LIMIT 1) x ON true
		CROSS JOIN LATERAL (SELECT x.files->0 AS f) one
		WHERE NOT h.revoked AND cs.present AND jsonb_array_length(x.files) = 1
		  AND COALESCE(f->>'sha256', '') NOT IN ('', r.compose_sha256)
		ORDER BY h.ci_id, cs.engine, cs.project`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Condition
	for rows.Next() {
		var c Condition
		var hostname, stack, engine, project, file, onHost, stored string
		var number int64
		var wrote time.Time
		if err := rows.Scan(&c.CIID, &hostname, pq.Array(&c.GroupIDs), &stack, &engine, &project, &file, &onHost, &stored,
			&number, &wrote); err != nil {
			return nil, err
		}
		c.Subject, c.Link = hostName(hostname, c.CIID), "/stacks/"+stack
		c.Key = "compose:" + engine + "/" + project + "@" + onHost[:min(12, len(onHost))]
		c.Summary = fmt.Sprintf("%s: the Compose file of stack %s (%s) was changed on the host since Baseline wrote it", c.Subject, project, file)
		if number > 0 {
			c.Summary += " in " + ChangeRef(number)
		}
		c.Details = map[string]any{"stack": project, "engine": engine, "path": file, "sha256": onHost, "baseline_sha256": stored,
			"written_at": wrote}
		if number > 0 {
			c.Details["change"] = ChangeRef(number)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
