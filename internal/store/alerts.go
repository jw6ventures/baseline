package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

// Notification channels ----------------------------------------------------------

// NotifyChannel is a Matrix room or an ntfy topic. ConfigEnc holds its
// settings, tokens included, sealed with BASELINE_SECRET_KEY; Summary is the
// part that is safe to show.
type NotifyChannel struct {
	ID         string
	Kind       string // matrix | ntfy
	Name       string
	Summary    string
	ConfigEnc  string
	Enabled    bool
	LastSentAt time.Time
	LastError  string
	CreatedAt  time.Time
}

const channelCols = `id, kind, name, summary, config_enc, enabled, COALESCE(last_sent_at, 'epoch'), last_error, created_at
	FROM notify_channel `

func scanChannel(row interface{ Scan(...any) error }) (NotifyChannel, error) {
	var c NotifyChannel
	err := row.Scan(&c.ID, &c.Kind, &c.Name, &c.Summary, &c.ConfigEnc, &c.Enabled, &c.LastSentAt, &c.LastError, &c.CreatedAt)
	if c.LastSentAt.Unix() == 0 {
		c.LastSentAt = time.Time{}
	}
	return c, err
}

func (s *Store) ListChannels(ctx context.Context) ([]NotifyChannel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+channelCols+`ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NotifyChannel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetChannel(ctx context.Context, id string) (NotifyChannel, error) {
	c, err := scanChannel(s.db.QueryRowContext(ctx, `SELECT `+channelCols+`WHERE id = $1`, id))
	return c, mapErr(err)
}

// SaveChannel creates (ID "") or updates a channel. An update with an empty
// ConfigEnc keeps the stored settings.
func (s *Store) SaveChannel(ctx context.Context, actor Actor, c NotifyChannel) (string, error) {
	id := c.ID
	err := s.tx(ctx, func(tx *sql.Tx) error {
		ev := "notify_channel.create"
		if id == "" {
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO notify_channel (kind, name, summary, config_enc, enabled, created_by)
				VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
				c.Kind, c.Name, c.Summary, c.ConfigEnc, c.Enabled, actor.userID()).Scan(&id); err != nil {
				return mapErr(err)
			}
		} else {
			ev = "notify_channel.update"
			res, err := tx.ExecContext(ctx, `
				UPDATE notify_channel SET name = $2, summary = CASE WHEN $4 = '' THEN summary ELSE $3 END,
				       config_enc = CASE WHEN $4 = '' THEN config_enc ELSE $4 END, enabled = $5, updated_at = now()
				WHERE id = $1`, id, c.Name, c.Summary, c.ConfigEnc, c.Enabled)
			if err != nil {
				return mapErr(err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
			if !c.Enabled {
				// What it hasn't sent yet would be stale by the time it is
				// turned back on.
				if _, err := tx.ExecContext(ctx, `
					UPDATE notification SET next_at = NULL, error = 'channel turned off'
					WHERE channel_id = $1 AND sent_at IS NULL`, id); err != nil {
					return err
				}
			}
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: ev, ObjectType: "notify_channel", ObjectID: id,
			Details: map[string]any{"name": c.Name, "kind": c.Kind, "summary": c.Summary, "enabled": c.Enabled,
				"settings_changed": c.ConfigEnc != ""}})
	})
	return id, err
}

// DeleteChannel removes a channel; rules stop notifying it.
func (s *Store) DeleteChannel(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `DELETE FROM notify_channel WHERE id = $1 RETURNING name`, id).Scan(&name); err != nil {
			return mapErr(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE alert_rule SET channels = array_remove(channels, $1)`, id); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "notify_channel.delete", ObjectType: "notify_channel",
			ObjectID: id, Details: map[string]any{"name": name}})
	})
}

// Notifications ----------------------------------------------------------------

// Notification events.
const (
	EventFiring   = "firing"
	EventReminder = "reminder"
	EventResolved = "resolved"
	EventTest     = "test"
)

// Notification is one message to one channel, in the outbox until sent.
type Notification struct {
	ID        int64
	ChannelID string
	AlertID   string // "" for a test message
	Event     string
	Severity  string
	Title     string
	Body      string
	Link      string
	CreatedAt time.Time
	Attempts  int
	NextAt    time.Time // zero: gave up
	SentAt    time.Time
	Error     string

	// Filled when read for delivery or listing.
	ChannelKind string
	ChannelName string
	ConfigEnc   string
}

// QueueNotifications adds messages to the outbox.
func (s *Store) QueueNotifications(ctx context.Context, ns []Notification) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return queueNotifications(ctx, tx, ns) })
}

func queueNotifications(ctx context.Context, tx *sql.Tx, ns []Notification) error {
	for _, n := range ns {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO notification (channel_id, alert_id, event, severity, title, body, link, next_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, now()))`,
			n.ChannelID, nullString(n.AlertID), n.Event, n.Severity, n.Title, n.Body, n.Link, nullTime(n.NextAt)); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

// DueNotifications returns messages to try now, oldest first, with their
// channel's settings. Messages queued behind one of their channel's that
// waits for a retry wait too, so each channel gets them in order.
func (s *Store) DueNotifications(ctx context.Context, now time.Time, limit int) ([]Notification, error) {
	return s.queryNotifications(ctx, `
		WHERE n.sent_at IS NULL AND n.next_at <= $1 AND c.enabled
		AND NOT EXISTS (SELECT 1 FROM notification o WHERE o.channel_id = n.channel_id AND o.id < n.id
		                AND o.sent_at IS NULL AND o.next_at > $1)
		ORDER BY n.id LIMIT $2`, now, limit)
}

// AlertNotifications lists the messages sent (or tried) for an alert.
func (s *Store) AlertNotifications(ctx context.Context, alertID string) ([]Notification, error) {
	return s.queryNotifications(ctx, `WHERE n.alert_id = $1 ORDER BY n.id`, alertID)
}

// RecentNotifications lists the newest messages of every channel.
func (s *Store) RecentNotifications(ctx context.Context, limit int) ([]Notification, error) {
	return s.queryNotifications(ctx, `ORDER BY n.id DESC LIMIT $1`, limit)
}

func (s *Store) queryNotifications(ctx context.Context, where string, args ...any) ([]Notification, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT n.id, n.channel_id, COALESCE(n.alert_id::text, ''), n.event, n.severity, n.title, n.body, n.link,
		       n.created_at, n.attempts, COALESCE(n.next_at, 'epoch'), COALESCE(n.sent_at, 'epoch'), n.error,
		       c.kind, c.name, c.config_enc
		FROM notification n JOIN notify_channel c ON c.id = n.channel_id `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		if err := rows.Scan(&n.ID, &n.ChannelID, &n.AlertID, &n.Event, &n.Severity, &n.Title, &n.Body, &n.Link,
			&n.CreatedAt, &n.Attempts, &n.NextAt, &n.SentAt, &n.Error, &n.ChannelKind, &n.ChannelName, &n.ConfigEnc); err != nil {
			return nil, err
		}
		for _, t := range []*time.Time{&n.NextAt, &n.SentAt} {
			if t.Unix() == 0 {
				*t = time.Time{}
			}
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// NotificationSent marks a message delivered.
func (s *Store) NotificationSent(ctx context.Context, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var ch string
		if err := tx.QueryRowContext(ctx, `
			UPDATE notification SET sent_at = now(), attempts = attempts + 1, error = '' WHERE id = $1
			RETURNING channel_id`, id).Scan(&ch); err != nil {
			return mapErr(err)
		}
		_, err := tx.ExecContext(ctx, `UPDATE notify_channel SET last_sent_at = now(), last_error = '' WHERE id = $1`, ch)
		return err
	})
}

// NotificationFailed records a failed try; a zero next gives up.
func (s *Store) NotificationFailed(ctx context.Context, id int64, msg string, next time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var ch string
		if err := tx.QueryRowContext(ctx, `
			UPDATE notification SET attempts = attempts + 1, error = $2, next_at = $3 WHERE id = $1
			RETURNING channel_id`, id, msg, nullTime(next)).Scan(&ch); err != nil {
			return mapErr(err)
		}
		_, err := tx.ExecContext(ctx, `UPDATE notify_channel SET last_error = $2 WHERE id = $1`, ch, msg)
		return err
	})
}

// Rules ------------------------------------------------------------------------

// AlertParams are a rule's settings; each kind reads some of them
// (internal/alert).
type AlertParams struct {
	Minutes     int      `json:"minutes,omitempty"`
	Percent     int      `json:"percent,omitempty"`
	Days        int      `json:"days,omitempty"`
	Hours       int      `json:"hours,omitempty"`
	Degrading   bool     `json:"degrading,omitempty"`
	Sectors     int      `json:"sectors,omitempty"`
	Partial     bool     `json:"partial,omitempty"`
	MinSeverity string   `json:"min_severity,omitempty"`
	Exclude     []string `json:"exclude,omitempty"`
}

type AlertRule struct {
	ID             string
	Name           string
	Kind           string
	Params         AlertParams
	ScopeGroups    []string // host groups; empty: everything
	ScopeNames     []string
	Severity       string // info | warning | critical
	Channels       []string
	ChannelNames   []string
	For            time.Duration // the condition must hold this long
	Repeat         time.Duration // notify again while firing; 0: once
	NotifyResolved bool
	Enabled        bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Firing         int // open alerts, for listings
}

// Global reports whether the rule watches every host.
func (r AlertRule) Global() bool { return len(r.ScopeGroups) == 0 }

// Covers reports whether the rule watches something in these groups.
func (r AlertRule) Covers(groups []string) bool {
	return r.Global() || slices.ContainsFunc(r.ScopeGroups, func(g string) bool { return slices.Contains(groups, g) })
}

const ruleCols = `r.id, r.name, r.kind, r.params::text,
	ARRAY(SELECT g.id::text FROM host_group g WHERE g.id = ANY(r.scope_groups) ORDER BY lower(g.name)),
	ARRAY(SELECT g.name FROM host_group g WHERE g.id = ANY(r.scope_groups) ORDER BY lower(g.name)),
	r.severity,
	ARRAY(SELECT c.id::text FROM notify_channel c WHERE c.id = ANY(r.channels) ORDER BY lower(c.name)),
	ARRAY(SELECT c.name FROM notify_channel c WHERE c.id = ANY(r.channels) ORDER BY lower(c.name)),
	r.for_s, r.repeat_s, r.notify_resolved, r.enabled, r.created_at, r.updated_at,
	(SELECT count(*) FROM alert a WHERE a.rule_id = r.id AND a.state = 'firing')
	FROM alert_rule r `

func scanRule(row interface{ Scan(...any) error }) (AlertRule, error) {
	var r AlertRule
	var params string
	var forS, repeatS int
	err := row.Scan(&r.ID, &r.Name, &r.Kind, &params, pq.Array(&r.ScopeGroups), pq.Array(&r.ScopeNames), &r.Severity,
		pq.Array(&r.Channels), pq.Array(&r.ChannelNames), &forS, &repeatS, &r.NotifyResolved, &r.Enabled,
		&r.CreatedAt, &r.UpdatedAt, &r.Firing)
	if err == nil {
		err = json.Unmarshal([]byte(params), &r.Params)
	}
	r.For, r.Repeat = time.Duration(forS)*time.Second, time.Duration(repeatS)*time.Second
	return r, err
}

func (s *Store) ListAlertRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+ruleCols+`ORDER BY lower(r.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetAlertRule(ctx context.Context, id string) (AlertRule, error) {
	r, err := scanRule(s.db.QueryRowContext(ctx, `SELECT `+ruleCols+`WHERE r.id = $1`, id))
	return r, mapErr(err)
}

// SaveAlertRule creates (ID "") or updates a rule. The kind can't change.
func (s *Store) SaveAlertRule(ctx context.Context, actor Actor, r AlertRule) (string, error) {
	id := r.ID
	params, err := json.Marshal(r.Params)
	if err != nil {
		return "", err
	}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		ev := "alert_rule.create"
		forS, repeatS := int(r.For/time.Second), int(r.Repeat/time.Second)
		if id == "" {
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO alert_rule (name, kind, params, scope_groups, severity, channels, for_s, repeat_s,
				                        notify_resolved, enabled, created_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
				r.Name, r.Kind, string(params), pq.Array(nonNil(r.ScopeGroups)), r.Severity, pq.Array(nonNil(r.Channels)),
				forS, repeatS, r.NotifyResolved, r.Enabled, actor.userID()).Scan(&id); err != nil {
				return mapErr(err)
			}
		} else {
			ev = "alert_rule.update"
			res, err := tx.ExecContext(ctx, `
				UPDATE alert_rule SET name = $2, params = $3, scope_groups = $4, severity = $5, channels = $6,
				       for_s = $7, repeat_s = $8, notify_resolved = $9, enabled = $10, updated_at = now()
				WHERE id = $1`,
				id, r.Name, string(params), pq.Array(nonNil(r.ScopeGroups)), r.Severity, pq.Array(nonNil(r.Channels)),
				forS, repeatS, r.NotifyResolved, r.Enabled)
			if err != nil {
				return mapErr(err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: ev, ObjectType: "alert_rule", ObjectID: id,
			Details: map[string]any{"name": r.Name, "kind": r.Kind, "params": r.Params, "scope_groups": r.ScopeGroups,
				"severity": r.Severity, "channels": r.Channels, "for": r.For.String(), "repeat": r.Repeat.String(),
				"notify_resolved": r.NotifyResolved, "enabled": r.Enabled}})
	})
	return id, err
}

// DeleteAlertRule removes a rule with its alerts and silences.
func (s *Store) DeleteAlertRule(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name, kind string
		if err := tx.QueryRowContext(ctx, `DELETE FROM alert_rule WHERE id = $1 RETURNING name, kind`, id).
			Scan(&name, &kind); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "alert_rule.delete", ObjectType: "alert_rule", ObjectID: id,
			Details: map[string]any{"name": name, "kind": kind}})
	})
}

// Alerts -----------------------------------------------------------------------

const (
	AlertPending  = "pending"
	AlertFiring   = "firing"
	AlertClosed   = "closed" // closed by hand while the condition holds
	AlertResolved = "resolved"
)

// Alert is one occurrence of a rule's condition on a subject: a CI (CIID),
// or an object without one (a change, a patch group), named by Subject.
// Key tells occurrences on one subject apart (a mount point, a unit).
type Alert struct {
	ID          string
	RuleID      string
	RuleName    string
	RuleKind    string
	CIID        string
	Subject     string
	Key         string
	Link        string   // the subject's page, under the public URL
	GroupIDs    []string // the subject's host groups
	Severity    string
	State       string
	Summary     string
	Details     map[string]any
	FirstAt     time.Time
	FiredAt     time.Time
	LastAt      time.Time
	ResolvedAt  time.Time
	NotifiedAt  time.Time
	SilenceID   string
	SilenceEnds time.Time
	AckedBy     string
	AckedByName string
	AckedAt     time.Time
	AckComment  string
	// Level is the condition's (store.Condition.Level). Closing records
	// it and the severity: the alert stays closed until either rises.
	Level          int64
	ClosedBy       string
	ClosedByName   string
	ClosedAt       time.Time
	ClosedLevel    int64
	ClosedSeverity string
	CloseComment   string
}

// Silenced reports whether a silence mutes the alert.
func (a Alert) Silenced() bool { return a.SilenceID != "" }

// Acked reports whether someone acknowledged the alert.
func (a Alert) Acked() bool { return !a.AckedAt.IsZero() }

// Closed reports whether someone closed the alert, whatever happened to
// its condition since.
func (a Alert) Closed() bool { return !a.ClosedAt.IsZero() }

const alertCols = `a.id, a.rule_id, r.name, r.kind, COALESCE(a.ci_id::text, ''), a.subject, a.key, a.link,
	a.group_ids::text[], a.severity, a.state, a.summary, a.details::text, a.first_at, COALESCE(a.fired_at, 'epoch'),
	a.last_at, COALESCE(a.resolved_at, 'epoch'), COALESCE(a.notified_at, 'epoch'), COALESCE(a.silence_id::text, ''),
	COALESCE(sl.ends_at, 'epoch'), COALESCE(a.acked_by::text, ''), COALESCE(u.name, ''), COALESCE(a.acked_at, 'epoch'),
	a.ack_comment, a.level, COALESCE(a.closed_by::text, ''), COALESCE(NULLIF(cu.name, ''), cu.email, ''),
	COALESCE(a.closed_at, 'epoch'), a.closed_level, a.closed_severity, a.close_comment
	FROM alert a JOIN alert_rule r ON r.id = a.rule_id LEFT JOIN silence sl ON sl.id = a.silence_id
	LEFT JOIN app_user u ON u.id = a.acked_by LEFT JOIN app_user cu ON cu.id = a.closed_by `

func scanAlert(row interface{ Scan(...any) error }) (Alert, error) {
	var a Alert
	var details string
	err := row.Scan(&a.ID, &a.RuleID, &a.RuleName, &a.RuleKind, &a.CIID, &a.Subject, &a.Key, &a.Link, pq.Array(&a.GroupIDs),
		&a.Severity, &a.State, &a.Summary, &details, &a.FirstAt, &a.FiredAt, &a.LastAt, &a.ResolvedAt, &a.NotifiedAt,
		&a.SilenceID, &a.SilenceEnds, &a.AckedBy, &a.AckedByName, &a.AckedAt, &a.AckComment, &a.Level, &a.ClosedBy,
		&a.ClosedByName, &a.ClosedAt, &a.ClosedLevel, &a.ClosedSeverity, &a.CloseComment)
	if err == nil {
		err = json.Unmarshal([]byte(details), &a.Details)
	}
	for _, t := range []*time.Time{&a.FiredAt, &a.ResolvedAt, &a.NotifiedAt, &a.SilenceEnds, &a.AckedAt, &a.ClosedAt} {
		if t.Unix() == 0 {
			*t = time.Time{}
		}
	}
	return a, err
}

// AlertFilter selects alerts for listings.
type AlertFilter struct {
	Open     bool      // pending and firing
	Tracked  bool      // pending, firing and closed: what the evaluator follows
	Resolved time.Time // resolved since then, unless closed by hand
	RuleID   string
	CIID     string
	Limit    int
}

func (s *Store) ListAlerts(ctx context.Context, f AlertFilter) ([]Alert, error) {
	var conds []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	switch {
	case f.Open:
		conds = append(conds, "a.state IN ('pending', 'firing')")
	case f.Tracked:
		conds = append(conds, "a.state <> 'resolved'")
	case !f.Resolved.IsZero():
		conds = append(conds, "a.state = 'resolved' AND a.closed_at IS NULL AND a.resolved_at >= "+arg(f.Resolved))
	}
	if f.RuleID != "" {
		conds = append(conds, "a.rule_id = "+arg(f.RuleID))
	}
	if f.CIID != "" {
		conds = append(conds, "a.ci_id = "+arg(f.CIID))
	}
	if f.Limit <= 0 {
		f.Limit = 500
	}
	q := `SELECT ` + alertCols
	if len(conds) > 0 {
		q += "WHERE " + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY a.state = 'resolved', array_position(ARRAY['critical','warning','info'], a.severity),
	       COALESCE(a.resolved_at, a.fired_at, a.first_at) DESC LIMIT ` + arg(f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetAlert(ctx context.Context, id string) (Alert, error) {
	a, err := scanAlert(s.db.QueryRowContext(ctx, `SELECT `+alertCols+`WHERE a.id = $1`, id))
	return a, mapErr(err)
}

// AlertChanges is what one evaluation pass writes, in one transaction.
type AlertChanges struct {
	Insert  []Alert // with IDs from NewAlertID
	Update  []Alert
	Resolve []string // firing and closed alerts whose condition ended, closed ones that got worse
	Delete  []string // pending alerts whose condition ended before firing
	Notify  []Notification
}

func (c AlertChanges) Empty() bool {
	return len(c.Insert)+len(c.Update)+len(c.Resolve)+len(c.Delete)+len(c.Notify) == 0
}

// NewAlertID returns an ID for an alert about to be inserted, so its
// notifications can refer to it in the same pass.
func NewAlertID() string { return newUUID() }

// ApplyAlerts writes an evaluation pass.
func (s *Store) ApplyAlerts(ctx context.Context, c AlertChanges) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		// Resolve first: a closed alert that got worse makes way for the
		// new one (one open alert per rule, CI and key).
		if len(c.Resolve) > 0 {
			if _, err := tx.ExecContext(ctx, `
				UPDATE alert SET state = 'resolved', resolved_at = now() WHERE id = ANY($1::uuid[]) AND state <> 'resolved'`,
				pq.Array(c.Resolve)); err != nil {
				return err
			}
		}
		if len(c.Delete) > 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM alert WHERE id = ANY($1::uuid[]) AND state = 'pending'`,
				pq.Array(c.Delete)); err != nil {
				return err
			}
		}
		for _, a := range c.Insert {
			d, err := json.Marshal(nonNilAny(a.Details))
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO alert (id, rule_id, ci_id, subject, key, link, group_ids, severity, state, summary, details,
				                   first_at, fired_at, last_at, notified_at, silence_id, level)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
				a.ID, a.RuleID, nullString(a.CIID), a.Subject, a.Key, a.Link, pq.Array(nonNil(a.GroupIDs)), a.Severity,
				a.State, a.Summary, string(d), a.FirstAt, nullTime(a.FiredAt), a.LastAt, nullTime(a.NotifiedAt),
				nullString(a.SilenceID), a.Level); err != nil {
				return mapErr(err)
			}
		}
		for _, a := range c.Update {
			d, err := json.Marshal(nonNilAny(a.Details))
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE alert SET subject = $2, link = $3, group_ids = $4, severity = $5, state = $6, summary = $7,
				       details = $8, fired_at = $9, last_at = $10, notified_at = $11, silence_id = $12, level = $13
				WHERE id = $1 AND state <> 'resolved'`,
				a.ID, a.Subject, a.Link, pq.Array(nonNil(a.GroupIDs)), a.Severity, a.State, a.Summary, string(d),
				nullTime(a.FiredAt), a.LastAt, nullTime(a.NotifiedAt), nullString(a.SilenceID), a.Level); err != nil {
				return mapErr(err)
			}
		}
		return queueNotifications(ctx, tx, c.Notify)
	})
}

func nonNilAny(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// AckAlert records that someone is on it: reminders stop.
func (s *Store) AckAlert(ctx context.Context, actor Actor, id, comment string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var summary string
		if err := tx.QueryRowContext(ctx, `
			UPDATE alert SET acked_by = $2, acked_at = now(), ack_comment = $3
			WHERE id = $1 AND state IN ('pending', 'firing') AND acked_at IS NULL RETURNING summary`,
			id, actor.userID(), comment).Scan(&summary); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "alert.ack", ObjectType: "alert", ObjectID: id,
			Details: map[string]any{"summary": summary, "comment": comment}})
	})
}

// CloseAlert takes an open alert out of sight for good: it stops
// notifying and shows nowhere. It stays closed while its condition holds,
// resolves when it ends, and only a worse condition (a higher level or
// severity) fires again, as a new alert.
func (s *Store) CloseAlert(ctx context.Context, actor Actor, id, comment string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var summary string
		if err := tx.QueryRowContext(ctx, `
			UPDATE alert SET state = 'closed', closed_by = $2, closed_at = now(), closed_level = level,
			       closed_severity = severity, close_comment = $3
			WHERE id = $1 AND state IN ('pending', 'firing') RETURNING summary`,
			id, actor.userID(), comment).Scan(&summary); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "alert.close", ObjectType: "alert", ObjectID: id,
			Details: map[string]any{"summary": summary, "comment": comment}})
	})
}

// PurgeAlerts deletes alerts resolved before, and sent or abandoned
// notifications created before, the given times.
func (s *Store) PurgeAlerts(ctx context.Context, alertsBefore, notificationsBefore time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM alert WHERE state = 'resolved' AND resolved_at < $1`, alertsBefore); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM notification WHERE created_at < $1 AND (sent_at IS NOT NULL OR next_at IS NULL)`, notificationsBefore)
	return err
}

// Silences ---------------------------------------------------------------------

// Silence mutes notifications for the alerts it matches between Starts and
// Ends. Empty matchers match anything.
type Silence struct {
	ID          string
	RuleID      string
	RuleName    string
	CIID        string
	CIName      string
	HostGroupID string
	GroupName   string
	Key         string
	Starts      time.Time
	Ends        time.Time
	Comment     string
	CreatedBy   string
	CreatorName string
	CreatedAt   time.Time
	Muting      int // open alerts it mutes
}

// Active reports whether the silence applies at t.
func (sl Silence) Active(t time.Time) bool { return !t.Before(sl.Starts) && t.Before(sl.Ends) }

// Matches reports whether the silence covers an alert (at any time).
func (sl Silence) Matches(a Alert) bool {
	return (sl.RuleID == "" || sl.RuleID == a.RuleID) && (sl.CIID == "" || sl.CIID == a.CIID) &&
		(sl.HostGroupID == "" || slices.Contains(a.GroupIDs, sl.HostGroupID)) && (sl.Key == "" || sl.Key == a.Key)
}

// Global reports whether the silence can mute alerts on any host.
func (sl Silence) Global() bool { return sl.CIID == "" && sl.HostGroupID == "" }

// ListSilences lists silences that end after since, soonest end first.
func (s *Store) ListSilences(ctx context.Context, since time.Time) ([]Silence, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sl.id, COALESCE(sl.rule_id::text, ''), COALESCE(r.name, ''), COALESCE(sl.ci_id::text, ''),
		       COALESCE(c.name, ''), COALESCE(sl.host_group_id::text, ''), COALESCE(g.name, ''), sl.key,
		       sl.starts_at, sl.ends_at, sl.comment, COALESCE(sl.created_by::text, ''), COALESCE(u.name, ''), sl.created_at,
		       (SELECT count(*) FROM alert a WHERE a.silence_id = sl.id AND a.state IN ('pending', 'firing'))
		FROM silence sl LEFT JOIN alert_rule r ON r.id = sl.rule_id LEFT JOIN ci c ON c.id = sl.ci_id
		LEFT JOIN host_group g ON g.id = sl.host_group_id LEFT JOIN app_user u ON u.id = sl.created_by
		WHERE sl.ends_at > $1 ORDER BY sl.ends_at, sl.created_at`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Silence
	for rows.Next() {
		var sl Silence
		if err := rows.Scan(&sl.ID, &sl.RuleID, &sl.RuleName, &sl.CIID, &sl.CIName, &sl.HostGroupID, &sl.GroupName,
			&sl.Key, &sl.Starts, &sl.Ends, &sl.Comment, &sl.CreatedBy, &sl.CreatorName, &sl.CreatedAt, &sl.Muting); err != nil {
			return nil, err
		}
		out = append(out, sl)
	}
	return out, rows.Err()
}

func (s *Store) GetSilence(ctx context.Context, id string) (Silence, error) {
	all, err := s.ListSilences(ctx, time.Time{})
	if err != nil {
		return Silence{}, err
	}
	for _, sl := range all {
		if sl.ID == id {
			return sl, nil
		}
	}
	return Silence{}, ErrNotFound
}

// CreateSilence adds a silence. It takes effect on the next evaluation.
func (s *Store) CreateSilence(ctx context.Context, actor Actor, sl Silence) (string, error) {
	var id string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO silence (rule_id, ci_id, host_group_id, key, starts_at, ends_at, comment, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
			nullString(sl.RuleID), nullString(sl.CIID), nullString(sl.HostGroupID), sl.Key, sl.Starts, sl.Ends,
			sl.Comment, actor.userID()).Scan(&id); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "silence.create", ObjectType: "silence", ObjectID: id,
			Details: map[string]any{"rule_id": sl.RuleID, "ci_id": sl.CIID, "host_group_id": sl.HostGroupID, "key": sl.Key,
				"starts": sl.Starts, "ends": sl.Ends, "comment": sl.Comment}})
	})
	return id, err
}

// EndSilence ends a silence now, or drops one that hasn't started; alerts
// it muted notify on the next pass if they still fire.
func (s *Store) EndSilence(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM silence WHERE id = $1 AND starts_at > now()`, id)
		if err != nil {
			return mapErr(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			if res, err = tx.ExecContext(ctx, `
				UPDATE silence SET ends_at = greatest(now(), starts_at + interval '1 microsecond')
				WHERE id = $1 AND ends_at > now()`, id); err != nil {
				return mapErr(err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
		}
		return appendAudit(ctx, tx, actor, AuditEvent{Action: "silence.end", ObjectType: "silence", ObjectID: id})
	})
}
