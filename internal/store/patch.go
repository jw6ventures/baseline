package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

// Patch cycle results (docs/change-management.md §4).
const (
	CycleRunning   = "running"
	CycleSuccess   = "success"
	CyclePartial   = "partial"
	CycleFailed    = "failed"
	CycleBlocked   = "blocked"
	CycleSkipped   = "skipped"
	CycleCancelled = "cancelled"
)

// ErrCycle rejects a patch group whose blocked_by would form a loop.
var ErrCycle = errors.New("patch groups can't block each other in a loop")

// PatchGroup is a host group patched on a schedule under a Standard change
// model, possibly after other groups have succeeded. A Compose group (its
// model is compose.update) updates a list of stacks instead.
type PatchGroup struct {
	ID               string
	Name             string
	Description      string
	HostGroupID      string // "" for a Compose group
	HostGroupName    string
	Stacks           []string // Compose groups: the stacks' CI IDs, those that still exist
	StackNames       []string // "project on host"
	Cron             string
	TZ               string
	WindowID         string
	WindowName       string
	ModelID          string
	ModelName        string
	ModelState       string
	ModelAction      string
	BlockedBy        []string // patch group IDs
	BlockedByNames   []string
	Soak             time.Duration
	SuccessThreshold int // % of a blocking group's hosts that must succeed
	PromoteValidated bool
	Concurrency      int
	StopOnFailure    bool
	Enabled          bool
	LastRunAt        time.Time // the scheduled time last handled
	CreatedAt        time.Time
	Hosts            int // in the host group, not revoked

	Last *PatchCycle // the latest cycle, if any (lists only)
}

// Compose reports whether the group updates Compose stacks.
func (g PatchGroup) Compose() bool { return strings.HasPrefix(g.ModelAction, "compose.") }

// Targets is what the group patches, for lists: its host group or how many
// stacks.
func (g PatchGroup) Targets() string {
	if g.Compose() {
		if len(g.Stacks) == 1 {
			return "1 Compose stack"
		}
		return strconv.Itoa(len(g.Stacks)) + " Compose stacks"
	}
	return g.HostGroupName
}

const patchGroupCols = `g.id, g.name, g.description, COALESCE(g.host_group_id::text, ''), COALESCE(hg.name, ''),
	ARRAY(SELECT s.ci_id::text FROM compose_stack s JOIN host h ON h.ci_id = s.host WHERE s.ci_id = ANY(g.stacks)
	      ORDER BY s.project, lower(h.hostname)),
	ARRAY(SELECT s.project || ' on ' || h.hostname FROM compose_stack s JOIN host h ON h.ci_id = s.host
	      WHERE s.ci_id = ANY(g.stacks) ORDER BY s.project, lower(h.hostname)),
	g.schedule_cron, g.tz,
	COALESCE(g.window_id::text, ''), COALESCE(w.name, ''), g.change_model_id, m.name, m.state, m.action,
	ARRAY(SELECT b.id::text FROM patch_group b WHERE b.id = ANY(g.blocked_by) ORDER BY lower(b.name)),
	ARRAY(SELECT b.name FROM patch_group b WHERE b.id = ANY(g.blocked_by) ORDER BY lower(b.name)),
	g.soak_s, g.success_threshold, g.promote_validated, g.concurrency, g.stop_on_failure, g.enabled,
	COALESCE(g.last_run_at, 'epoch'), g.created_at,
	(SELECT count(*) FROM host_group_member hm JOIN host h ON h.ci_id = hm.ci_id WHERE hm.group_id = g.host_group_id AND NOT h.revoked)
	FROM patch_group g LEFT JOIN host_group hg ON hg.id = g.host_group_id JOIN change_model m ON m.id = g.change_model_id
	LEFT JOIN maintenance_window w ON w.id = g.window_id `

func scanPatchGroup(row interface{ Scan(...any) error }) (PatchGroup, error) {
	var g PatchGroup
	var soak int
	err := row.Scan(&g.ID, &g.Name, &g.Description, &g.HostGroupID, &g.HostGroupName, pq.Array(&g.Stacks),
		pq.Array(&g.StackNames), &g.Cron, &g.TZ, &g.WindowID, &g.WindowName, &g.ModelID, &g.ModelName, &g.ModelState,
		&g.ModelAction, pq.Array(&g.BlockedBy), pq.Array(&g.BlockedByNames),
		&soak, &g.SuccessThreshold, &g.PromoteValidated, &g.Concurrency, &g.StopOnFailure, &g.Enabled, &g.LastRunAt,
		&g.CreatedAt, &g.Hosts)
	g.Soak = time.Duration(soak) * time.Second
	if g.LastRunAt.Unix() == 0 {
		g.LastRunAt = time.Time{}
	}
	return g, err
}

// ListPatchGroups lists every patch group with its latest cycle.
func (s *Store) ListPatchGroups(ctx context.Context) ([]PatchGroup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+patchGroupCols+`ORDER BY lower(g.name)`)
	if err != nil {
		return nil, err
	}
	var out []PatchGroup
	for rows.Next() {
		g, err := scanPatchGroup(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		cs, err := s.ListPatchCycles(ctx, out[i].ID, 1)
		if err != nil {
			return nil, err
		}
		if len(cs) > 0 {
			out[i].Last = &cs[0]
		}
	}
	return out, nil
}

func (s *Store) GetPatchGroup(ctx context.Context, id string) (PatchGroup, error) {
	g, err := scanPatchGroup(s.db.QueryRowContext(ctx, `SELECT `+patchGroupCols+`WHERE g.id = $1`, id))
	return g, mapErr(err)
}

// SavePatchGroup creates (ID "") or updates a patch group. Its schedule
// must have been checked, and it has a host group or, for a Compose group,
// stacks. Blocking loops are refused with ErrCycle.
func (s *Store) SavePatchGroup(ctx context.Context, actor Actor, g PatchGroup) (string, error) {
	id := g.ID
	err := s.tx(ctx, func(tx *sql.Tx) error {
		// One saver at a time, so two edits can't make a loop between them.
		if _, err := tx.ExecContext(ctx, `LOCK TABLE patch_group IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
		ev := "patch_group.create"
		args := []any{g.Name, g.Description, nullString(g.HostGroupID), g.Cron, g.TZ, nullString(g.WindowID), g.ModelID,
			pq.Array(nonNil(g.BlockedBy)), int(g.Soak / time.Second), g.SuccessThreshold, g.PromoteValidated,
			max(g.Concurrency, 1), g.StopOnFailure, g.Enabled, pq.Array(nonNil(g.Stacks))}
		if id == "" {
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO patch_group (name, description, host_group_id, schedule_cron, tz, window_id, change_model_id,
				    blocked_by, soak_s, success_threshold, promote_validated, concurrency, stop_on_failure, enabled,
				    stacks, last_run_at, created_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, now(), $16) RETURNING id`,
				append(args, actor.userID())...).Scan(&id); err != nil {
				return mapErr(err)
			}
		} else {
			ev = "patch_group.update"
			// A new schedule counts from now: it doesn't run the times it
			// would have run before.
			res, err := tx.ExecContext(ctx, `
				UPDATE patch_group SET name = $1, description = $2, host_group_id = $3, schedule_cron = $4, tz = $5,
				       window_id = $6, change_model_id = $7, blocked_by = $8, soak_s = $9, success_threshold = $10,
				       promote_validated = $11, concurrency = $12, stop_on_failure = $13, enabled = $14, stacks = $15,
				       last_run_at = CASE WHEN schedule_cron <> $4 OR tz <> $5 OR NOT enabled THEN now() ELSE last_run_at END,
				       updated_at = now()
				WHERE id = $16`, append(args, id)...)
			if err != nil {
				return mapErr(err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
		}
		if slices.Contains(g.BlockedBy, id) {
			return ErrCycle
		}
		rows, err := tx.QueryContext(ctx, `SELECT id, blocked_by::text[] FROM patch_group`)
		if err != nil {
			return err
		}
		edges := map[string][]string{}
		for rows.Next() {
			var from string
			var to []string
			if err := rows.Scan(&from, pq.Array(&to)); err != nil {
				rows.Close()
				return err
			}
			edges[from] = to
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if loops(edges, id) {
			return ErrCycle
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: ev, ObjectType: "patch_group", ObjectID: id,
			Details: map[string]any{"name": g.Name, "host_group": g.HostGroupID, "stacks": g.Stacks, "schedule": g.Cron, "tz": g.TZ,
				"window": g.WindowID, "model": g.ModelID, "blocked_by": g.BlockedBy, "soak": g.Soak.String(),
				"success_threshold": g.SuccessThreshold, "promote_validated": g.PromoteValidated,
				"concurrency": g.Concurrency, "stop_on_failure": g.StopOnFailure, "enabled": g.Enabled}})
	})
	return id, err
}

// loops reports whether following blocked_by from start comes back to it.
func loops(edges map[string][]string, start string) bool {
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(n string) bool {
		for _, m := range edges[n] {
			if m == start {
				return true
			}
			if !seen[m] {
				seen[m] = true
				if walk(m) {
					return true
				}
			}
		}
		return false
	}
	return walk(start)
}

// DeletePatchGroup removes a group and its cycles; groups it blocked stop
// waiting for it.
func (s *Store) DeletePatchGroup(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `DELETE FROM patch_group WHERE id = $1 RETURNING name`, id).Scan(&name); err != nil {
			return mapErr(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE patch_group SET blocked_by = array_remove(blocked_by, $1::uuid)`, id); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "patch_group.delete", ObjectType: "patch_group", ObjectID: id,
			Details: map[string]any{"name": name}})
	})
}

// ClaimPatchRun records that the scheduler handles the group's run
// scheduled at due. It is false if another pass already did.
func (s *Store) ClaimPatchRun(ctx context.Context, id string, due time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE patch_group SET last_run_at = $2 WHERE id = $1 AND (last_run_at IS NULL OR last_run_at < $2)`, id, due)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// PatchCycle is one run of a patch group.
type PatchCycle struct {
	ID           string
	GroupID      string
	GroupName    string
	ChangeID     string
	ChangeNumber int64
	ChangeState  string
	ScheduledFor time.Time
	StartedAt    time.Time
	FinishedAt   time.Time
	Result       string
	Reason       string
	Hosts        int
	Succeeded    int
	Planned      []PlannedHost
	Validated    []ValidatedPackage
}

// ChangeRef is the cycle's change, CHG-000123.
func (c PatchCycle) ChangeRef() string { return ChangeRef(c.ChangeNumber) }

// Rate is the share of hosts that succeeded, in percent.
func (c PatchCycle) Rate() int {
	if c.Hosts == 0 {
		return 100
	}
	return c.Succeeded * 100 / c.Hosts
}

// PlannedHost is what a cycle set out to do on one host, or, in a Compose
// group, on one stack.
type PlannedHost struct {
	HostID   string `json:"host"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	// Compose groups: the stack, the services to update (none: all of them),
	// and the copy of the app whose images promotion checked against.
	StackID   string            `json:"stack,omitempty"`
	Project   string            `json:"project,omitempty"`
	Services  []string          `json:"services,omitempty"`
	Validator string            `json:"validator,omitempty"`
	Packages  []string          `json:"packages,omitempty"` // promotion: what was validated and pending
	Versions  map[string]string `json:"versions,omitempty"`
	Deferred  int               `json:"deferred,omitempty"` // pending updates not validated yet
	// Image and ImageVersion: the OS image an image-based host is to
	// deploy, validated when its job succeeds.
	Image        string `json:"image,omitempty"`
	ImageVersion string `json:"image_version,omitempty"`
	Note         string `json:"note,omitempty"`
	Job          bool   `json:"job"` // false: nothing to do
}

// ValidatedPackage is a package version a cycle installed successfully,
// on hosts of one OS release ("ubuntu:24.04").
type ValidatedPackage struct {
	OS      string `json:"os"`
	Manager string `json:"manager"`
	Name    string `json:"name"`
	Arch    string `json:"arch,omitempty"`
	Version string `json:"version"`
}

const cycleCols = `p.id, p.patch_group_id, g.name, COALESCE(p.change_id::text, ''), COALESCE(c.number, 0), COALESCE(c.state, ''),
	p.scheduled_for, p.started_at, COALESCE(p.finished_at, 'epoch'), p.result, p.reason, p.hosts, p.succeeded,
	p.planned::text, p.validated_set::text
	FROM patch_cycle p JOIN patch_group g ON g.id = p.patch_group_id LEFT JOIN change c ON c.id = p.change_id `

func scanCycle(row interface{ Scan(...any) error }) (PatchCycle, error) {
	var c PatchCycle
	var planned, validated string
	err := row.Scan(&c.ID, &c.GroupID, &c.GroupName, &c.ChangeID, &c.ChangeNumber, &c.ChangeState, &c.ScheduledFor,
		&c.StartedAt, &c.FinishedAt, &c.Result, &c.Reason, &c.Hosts, &c.Succeeded, &planned, &validated)
	if err != nil {
		return c, err
	}
	if c.FinishedAt.Unix() == 0 {
		c.FinishedAt = time.Time{}
	}
	if err := json.Unmarshal([]byte(planned), &c.Planned); err != nil {
		return c, err
	}
	return c, json.Unmarshal([]byte(validated), &c.Validated)
}

func (s *Store) queryCycles(ctx context.Context, where string, args ...any) ([]PatchCycle, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cycleCols+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PatchCycle
	for rows.Next() {
		c, err := scanCycle(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListPatchCycles lists a group's cycles, newest first.
func (s *Store) ListPatchCycles(ctx context.Context, groupID string, limit int) ([]PatchCycle, error) {
	return s.queryCycles(ctx, `WHERE p.patch_group_id = $1 ORDER BY p.started_at DESC LIMIT $2`, groupID, limit)
}

// LastRanCycle is a group's latest cycle that ran (not blocked or skipped),
// or nil.
func (s *Store) LastRanCycle(ctx context.Context, groupID string) (*PatchCycle, error) {
	cs, err := s.queryCycles(ctx, `WHERE p.patch_group_id = $1 AND p.result NOT IN ('blocked', 'skipped')
		ORDER BY p.started_at DESC LIMIT 1`, groupID)
	if err != nil || len(cs) == 0 {
		return nil, err
	}
	return &cs[0], nil
}

// ChangeCycle is the cycle a change runs, or nil.
func (s *Store) ChangeCycle(ctx context.Context, changeID string) (*PatchCycle, error) {
	cs, err := s.queryCycles(ctx, `WHERE p.change_id = $1`, changeID)
	if err != nil || len(cs) == 0 {
		return nil, err
	}
	return &cs[0], nil
}

// EndedCycles lists running cycles whose change has ended, or is gone, and so
// can be finished.
func (s *Store) EndedCycles(ctx context.Context) ([]PatchCycle, error) {
	return s.queryCycles(ctx, `WHERE p.result = 'running' AND (c.id IS NULL OR c.state NOT IN
		('draft', 'submitted', 'approved', 'scheduled', 'in_progress')) ORDER BY p.started_at`)
}

// RecordCycle records a cycle as it starts, running the change changeID,
// or as it is blocked or skipped (result and reason, no change).
func (s *Store) RecordCycle(ctx context.Context, c PatchCycle) (string, error) {
	planned, err := json.Marshal(nonNilSlice(c.Planned))
	if err != nil {
		return "", err
	}
	var id string
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO patch_cycle (patch_group_id, change_id, scheduled_for, result, reason, hosts, planned, finished_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $4 <> 'running' THEN now() END) RETURNING id`,
			c.GroupID, nullString(c.ChangeID), c.ScheduledFor, c.Result, c.Reason, c.Hosts, string(planned)).Scan(&id); err != nil {
			return mapErr(err)
		}
		details := map[string]any{"group": c.GroupName, "scheduled_for": c.ScheduledFor.UTC().Format(time.RFC3339),
			"result": c.Result}
		if c.Reason != "" {
			details["reason"] = c.Reason
		}
		if c.ChangeID != "" {
			details["change"] = c.ChangeID
			details["hosts"] = c.Hosts
		}
		return appendAudit(ctx, tx, System, AuditEvent{Action: "patch_cycle." + c.Result, ObjectType: "patch_cycle",
			ObjectID: id, Details: details})
	})
	return id, err
}

// FinishCycle records how a cycle ended and what it validated.
func (s *Store) FinishCycle(ctx context.Context, id, result, reason string, hosts, succeeded int, validated []ValidatedPackage) error {
	v, err := json.Marshal(nonNilSlice(validated))
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var group string
		err := tx.QueryRowContext(ctx, `
			UPDATE patch_cycle p SET result = $2, reason = $3, hosts = $4, succeeded = $5, validated_set = $6, finished_at = now()
			FROM patch_group g WHERE p.id = $1 AND g.id = p.patch_group_id AND p.result = 'running' RETURNING g.name`,
			id, result, reason, hosts, succeeded, string(v)).Scan(&group)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return appendAudit(ctx, tx, System, AuditEvent{Action: "patch_cycle.finish", ObjectType: "patch_cycle", ObjectID: id,
			Details: map[string]any{"group": group, "result": result, "hosts": hosts, "succeeded": succeeded,
				"validated": len(validated), "reason": reason}})
	})
}

func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// HostGroupMembers lists the hosts in a host group, revoked ones left out.
func (s *Store) HostGroupMembers(ctx context.Context, groupID string) ([]Host, error) {
	all, err := s.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	var out []Host
	for _, h := range all {
		if !h.Revoked && slices.Contains(h.GroupIDs, groupID) {
			out = append(out, h)
		}
	}
	return out, nil
}
