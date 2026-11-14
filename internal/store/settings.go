package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// SettingRetireMissingStacks is how many days a Compose stack can be
// missing before it is retired; 0 (or unset) leaves it missing.
const SettingRetireMissingStacks = "stacks.retire_missing_days"

// MaxRetireMissingDays bounds the setting: ten years.
const MaxRetireMissingDays = 3650

// RetireMissingStacksDays returns the setting, 0 when it is off.
func (s *Store) RetireMissingStacksDays(ctx context.Context) (int, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM app_setting WHERE key = $1`, SettingRetireMissingStacks).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var days int
	if err := json.Unmarshal(raw, &days); err != nil {
		return 0, err
	}
	return days, nil
}

// SetRetireMissingStacksDays sets it; 0 turns it off.
func (s *Store) SetRetireMissingStacksDays(ctx context.Context, actor Actor, days int) error {
	if days < 0 || days > MaxRetireMissingDays {
		return errors.New("days out of range")
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var prev int
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT value FROM app_setting WHERE key = $1 FOR UPDATE`,
			SettingRetireMissingStacks).Scan(&raw); err == nil {
			_ = json.Unmarshal(raw, &prev)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if prev == days {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_setting (key, value) VALUES ($1, to_jsonb($2::int))
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
			SettingRetireMissingStacks, days); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "setting.update", ObjectType: "setting", ObjectID: SettingRetireMissingStacks,
			Details: map[string]any{"from": prev, "to": days},
		})
	})
}

// RetireMissingStacks retires Compose stacks that have been missing for
// longer than the setting, and reports how many. Missing stacks went away
// at their CI's last_seen. A retired stack keeps its row and settings, drops
// off the stack lists, and turns active again if its host reports it.
func (s *Store) RetireMissingStacks(ctx context.Context, now time.Time) (int, error) {
	days, err := s.RetireMissingStacksDays(ctx)
	if err != nil || days <= 0 {
		return 0, err
	}
	n := 0
	err = s.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			UPDATE ci SET status = 'retired', updated_at = now()
			FROM compose_stack s JOIN host h ON h.ci_id = s.host
			WHERE ci.id = s.ci_id AND ci.type = 'compose_stack' AND ci.status = 'missing'
			  AND NOT s.present AND ci.last_seen < $1
			RETURNING ci.id, s.project, h.hostname, ci.last_seen`, now.Add(-time.Duration(days)*24*time.Hour))
		if err != nil {
			return err
		}
		type gone struct {
			id, project, host string
			since             time.Time
		}
		var all []gone
		for rows.Next() {
			var g gone
			if err := rows.Scan(&g.id, &g.project, &g.host, &g.since); err != nil {
				rows.Close()
				return err
			}
			all = append(all, g)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, g := range all {
			if err := appendAudit(ctx, tx, System, AuditEvent{
				Action: "stack.retire", ObjectType: "compose_stack", ObjectID: g.id,
				Details: map[string]any{"project": g.project, "host": g.host, "missing_since": g.since.UTC().Format(time.RFC3339),
					"after_days": days},
			}); err != nil {
				return err
			}
		}
		n = len(all)
		return nil
	})
	return n, err
}
