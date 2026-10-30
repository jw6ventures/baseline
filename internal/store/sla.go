package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/lib/pq"
)

// SLA policies and the clocks they start on work items
// (docs/data-model.md §13). Triggers start and stop the clocks; this file
// manages the policies and reads the clocks.

// SLA metrics.
const (
	SLAResponse   = "response"
	SLAResolution = "resolution"
)

var SLAMetrics = []string{SLAResponse, SLAResolution}

// ErrSLAScopeTaken: another policy already covers the same project and
// ticket type.
var ErrSLAScopeTaken = errors.New("store: an SLA policy already covers that scope")

// SLATargets are a policy's targets in minutes by priority, then metric.
type SLATargets map[string]map[string]int

// Target is the target in minutes for a priority and metric, 0 for none.
func (t SLATargets) Target(priority, metric string) int { return t[priority][metric] }

// SLAPolicy sets the targets for a project, a ticket type, both or every
// item.
type SLAPolicy struct {
	ID         string
	Name       string
	ProjectID  string // "" for every project
	ProjectKey string
	TypeID     string // "" for every type
	TypeName   string
	Targets    SLATargets
	Enabled    bool
	CreatedAt  time.Time
	Running    int // clocks running under it
}

const slaPolicyCols = `p.id, p.name, COALESCE(p.project_id::text, ''), COALESCE(pr.key, ''),
	COALESCE(p.ticket_type_id::text, ''), COALESCE(t.name, ''), p.targets::text, p.enabled, p.created_at,
	(SELECT count(*) FROM sla_clock c WHERE c.policy_id = p.id AND c.met_at IS NULL)`

const slaPolicyFrom = ` FROM sla_policy p LEFT JOIN project pr ON pr.id = p.project_id
	LEFT JOIN ticket_type t ON t.id = p.ticket_type_id`

func scanSLAPolicy(row interface{ Scan(...any) error }) (SLAPolicy, error) {
	var p SLAPolicy
	var targets string
	if err := row.Scan(&p.ID, &p.Name, &p.ProjectID, &p.ProjectKey, &p.TypeID, &p.TypeName, &targets, &p.Enabled,
		&p.CreatedAt, &p.Running); err != nil {
		return p, err
	}
	if err := json.Unmarshal([]byte(targets), &p.Targets); err != nil {
		return p, err
	}
	return p, nil
}

// ListSLAPolicies lists the policies, the most specific first.
func (s *Store) ListSLAPolicies(ctx context.Context) ([]SLAPolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+slaPolicyCols+slaPolicyFrom+`
		ORDER BY p.project_id IS NULL, p.ticket_type_id IS NULL, pr.key, t.name, lower(p.name)`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []SLAPolicy
	for rows.Next() {
		p, err := scanSLAPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetSLAPolicy(ctx context.Context, id string) (SLAPolicy, error) {
	p, err := scanSLAPolicy(s.db.QueryRowContext(ctx, `SELECT `+slaPolicyCols+slaPolicyFrom+` WHERE p.id::text = $1`, id))
	return p, mapErr(err)
}

// SaveSLAPolicy creates a policy (id "") or updates one. Clocks already
// running keep their targets.
func (s *Store) SaveSLAPolicy(ctx context.Context, actor Actor, id string, in SLAPolicy) (string, error) {
	targets := SLATargets{}
	for prio, m := range in.Targets {
		for metric, min := range m {
			if min > 0 {
				if targets[prio] == nil {
					targets[prio] = map[string]int{}
				}
				targets[prio][metric] = min
			}
		}
	}
	b, err := json.Marshal(targets)
	if err != nil {
		return "", err
	}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		action := "sla_policy.update"
		var err error
		if id == "" {
			action = "sla_policy.create"
			err = tx.QueryRowContext(ctx, `
				INSERT INTO sla_policy (name, project_id, ticket_type_id, targets, enabled)
				VALUES ($1, NULLIF($2, '')::uuid, NULLIF($3, '')::uuid, $4, $5) RETURNING id`,
				in.Name, in.ProjectID, in.TypeID, string(b), in.Enabled).Scan(&id)
		} else {
			err = tx.QueryRowContext(ctx, `
				UPDATE sla_policy SET name = $2, project_id = NULLIF($3, '')::uuid, ticket_type_id = NULLIF($4, '')::uuid,
				       targets = $5, enabled = $6
				WHERE id = $1 RETURNING id`, id, in.Name, in.ProjectID, in.TypeID, string(b), in.Enabled).Scan(&id)
		}
		if err != nil {
			return slaErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: action, ObjectType: "sla_policy", ObjectID: id,
			Details: map[string]any{"name": in.Name, "project": in.ProjectID, "ticket_type": in.TypeID, "targets": targets,
				"enabled": in.Enabled},
		})
	})
	return id, err
}

func slaErr(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" && pqErr.Constraint == "sla_policy_scope_idx" {
		return ErrSLAScopeTaken
	}
	return mapErr(err)
}

// DeleteSLAPolicy removes a policy. Its clocks keep running with the
// targets they started with.
func (s *Store) DeleteSLAPolicy(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name string
		if err := tx.QueryRowContext(ctx, `DELETE FROM sla_policy WHERE id = $1 RETURNING name`, id).Scan(&name); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "sla_policy.delete", ObjectType: "sla_policy", ObjectID: id, Details: map[string]any{"name": name},
		})
	})
}

// SLAClock is one SLA clock on a work item.
type SLAClock struct {
	Metric        string
	PolicyID      string // "" once the policy is deleted
	PolicyName    string
	TargetMinutes int
	StartedAt     time.Time
	TargetAt      time.Time
	MetAt         time.Time // zero while running
}

func (c SLAClock) Running() bool { return c.MetAt.IsZero() }

// Breached reports whether the clock passed its target by now, or was met
// late.
func (c SLAClock) Breached(now time.Time) bool {
	if c.Running() {
		return now.After(c.TargetAt)
	}
	return c.MetAt.After(c.TargetAt)
}

// WorkItemSLAs lists an item's clocks, response first.
func (s *Store) WorkItemSLAs(ctx context.Context, itemID string) ([]SLAClock, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT metric, COALESCE(policy_id::text, ''), policy_name, target_minutes, started_at, target_at, met_at
		FROM sla_clock WHERE work_item_id = $1 ORDER BY metric = 'resolution', metric`, itemID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []SLAClock
	for rows.Next() {
		var c SLAClock
		var met sql.NullTime
		if err := rows.Scan(&c.Metric, &c.PolicyID, &c.PolicyName, &c.TargetMinutes, &c.StartedAt, &c.TargetAt, &met); err != nil {
			return nil, err
		}
		c.MetAt = met.Time
		out = append(out, c)
	}
	return out, rows.Err()
}
