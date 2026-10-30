package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/model"
)

// Release is a signed agent binary for one architecture.
type Release struct {
	Version     string
	Arch        string
	SHA256      string
	Signature   []byte
	Size        int64
	Path        string
	PublishedAt time.Time
}

// PublishRelease records a release, replacing one with the same version and
// arch (a development build reuses its version string).
func (s *Store) PublishRelease(ctx context.Context, r Release) (changed bool, err error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO agent_release (version, arch, sha256, signature, size, path)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (version, arch) DO UPDATE
		SET sha256 = EXCLUDED.sha256, signature = EXCLUDED.signature, size = EXCLUDED.size,
		    path = EXCLUDED.path, published_at = now()
		WHERE agent_release.sha256 <> EXCLUDED.sha256 OR agent_release.path <> EXCLUDED.path`,
		r.Version, r.Arch, r.SHA256, r.Signature, r.Size, r.Path)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) GetRelease(ctx context.Context, version, arch string) (Release, error) {
	var r Release
	err := s.db.QueryRowContext(ctx, `
		SELECT version, arch, sha256, signature, size, path, published_at FROM agent_release
		WHERE version = $1 AND arch = $2`, version, arch).
		Scan(&r.Version, &r.Arch, &r.SHA256, &r.Signature, &r.Size, &r.Path, &r.PublishedAt)
	return r, mapErr(err)
}

// ReleaseVersion is a published version with the architectures it has.
type ReleaseVersion struct {
	Version     string
	Arches      []string
	PublishedAt time.Time
}

// ListReleases returns published versions, newest first.
func (s *Store) ListReleases(ctx context.Context) ([]ReleaseVersion, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT version, array_agg(arch ORDER BY arch), max(published_at) FROM agent_release
		GROUP BY version ORDER BY max(published_at) DESC, version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReleaseVersion
	for rows.Next() {
		var v ReleaseVersion
		if err := rows.Scan(&v.Version, pq.Array(&v.Arches), &v.PublishedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// PruneReleases forgets all but the newest keep versions, except versions
// some host is still asked to move to. It returns the removed releases so
// their files can be deleted.
func (s *Store) PruneReleases(ctx context.Context, keep int) ([]Release, error) {
	rows, err := s.db.QueryContext(ctx, `
		WITH ranked AS (
		    SELECT version, rank() OVER (ORDER BY max(published_at) DESC, version) AS n
		    FROM agent_release GROUP BY version)
		DELETE FROM agent_release r USING ranked
		WHERE r.version = ranked.version AND ranked.n > $1
		  AND NOT EXISTS (SELECT 1 FROM host h WHERE h.agent_update_target = r.version AND NOT h.revoked)
		RETURNING r.version, r.arch, r.path`, keep)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Release
	for rows.Next() {
		var r Release
		if err := rows.Scan(&r.Version, &r.Arch, &r.Path); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RequestAgentUpdate sets the version the given hosts' agents should run.
// Hosts already on it, revoked hosts, hosts whose agent.conf has
// self_update = off, and hosts whose architecture has no such release are
// left alone. It returns the hosts it changed.
func (s *Store) RequestAgentUpdate(ctx context.Context, actor Actor, hostIDs []string, version string) ([]AgentHost, error) {
	var out []AgentHost
	err := s.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			UPDATE host h SET agent_update_target = $2, agent_update_at = now(), agent_update_error = ''
			WHERE h.ci_id::text = ANY($1) AND NOT h.revoked AND h.agent_version <> $2
			  AND NOT $3 = ANY(h.capabilities) -- cluster agents are updated through their image
			  AND NOT COALESCE((h.local_policy->>'self_update_off')::boolean, false)
			  AND EXISTS (SELECT 1 FROM agent_release r WHERE r.version = $2 AND r.arch = h.agent_arch)
			RETURNING h.ci_id, h.agent_id, h.hostname, h.agent_version`, pq.Array(nonNil(hostIDs)), version, model.CapK8sCluster)
		if err != nil {
			return err
		}
		type change struct {
			host AgentHost
			from string
		}
		var changes []change
		for rows.Next() {
			var c change
			if err := rows.Scan(&c.host.HostID, &c.host.AgentID, &c.host.Hostname, &c.from); err != nil {
				rows.Close()
				return err
			}
			changes = append(changes, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, c := range changes {
			out = append(out, c.host)
			if err := appendAudit(ctx, tx, actor, AuditEvent{
				Action: "host.agent_update", ObjectType: "host", ObjectID: c.host.HostID,
				Details: map[string]any{"hostname": c.host.Hostname, "from": c.from, "to": version},
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// AgentUpdateTarget is the version a host's agent should move to, if any.
func (s *Store) AgentUpdateTarget(ctx context.Context, hostID string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT agent_update_target FROM host WHERE ci_id = $1 AND NOT revoked`, hostID).Scan(&v)
	return v, mapErr(err)
}

// AgentUpdateFailed records why a self-update failed and drops the target,
// so a broken release isn't retried on every reconnect; an admin retries.
func (s *Store) AgentUpdateFailed(ctx context.Context, hostID, agentID, version, reason string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			UPDATE host SET agent_update_target = '', agent_update_error = $2 WHERE ci_id = $1`, hostID, reason); err != nil {
			return err
		}
		return appendAudit(ctx, tx, Actor{ID: "agent:" + agentID}, AuditEvent{
			Action: "host.agent_update_failed", ObjectType: "host", ObjectID: hostID,
			Details: map[string]any{"version": version, "error": reason},
		})
	})
}
