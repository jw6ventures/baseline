package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/model"
)

// ImageRefsToCheck lists the image references running containers use whose
// registry check is older than staleBefore (failed checks: retryBefore).
func (s *Store) ImageRefsToCheck(ctx context.Context, staleBefore, retryBefore time.Time) ([]string, error) {
	return s.strings(ctx, `
		SELECT DISTINCT c.check_ref FROM container c JOIN host h ON h.ci_id = c.host
		LEFT JOIN image_check ic ON ic.image_ref = c.check_ref
		WHERE c.check_ref <> '' AND NOT h.revoked
		  AND (ic.image_ref IS NULL OR (ic.error = '' AND ic.checked_at < $1) OR (ic.error <> '' AND ic.checked_at < $2))
		ORDER BY 1`, staleBefore, retryBefore)
}

// SaveImageCheck records what a registry serves for a reference.
func (s *Store) SaveImageCheck(ctx context.Context, ref, registry, digest, checkErr string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO image_check (image_ref, registry, latest_digest, checked_at, error) VALUES ($1, $2, $3, now(), $4)
		ON CONFLICT (image_ref) DO UPDATE
		SET registry = EXCLUDED.registry, checked_at = now(), error = EXCLUDED.error,
		    -- a failed check keeps the last digest it knew
		    latest_digest = CASE WHEN EXCLUDED.error = '' THEN EXCLUDED.latest_digest ELSE image_check.latest_digest END`,
		ref, registry, digest, checkErr)
	return err
}

// ForgetImageCheck makes the next check of ref happen at once.
func (s *Store) ForgetImageCheck(ctx context.Context, ref string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE image_check SET checked_at = 'epoch' WHERE image_ref = $1`, ref)
	return err
}

// RuledImageRefs lists the references of containers that have a semver rule,
// their own or their Compose service's.
func (s *Store) RuledImageRefs(ctx context.Context) ([]string, error) {
	return s.strings(ctx, `
		SELECT DISTINCT c.check_ref FROM container c JOIN host h ON h.ci_id = c.host JOIN ci ON ci.id = c.ci_id
		LEFT JOIN compose_stack s ON s.host = c.host AND s.engine = c.engine AND s.project = c.compose_project
		WHERE c.check_ref <> '' AND NOT h.revoked
		  AND (ci.attrs ? 'semver_rule' OR (c.compose_service <> '' AND s.semver_rules ? c.compose_service))
		ORDER BY 1`)
}

// TagsCheckedAt returns when a repository's tags were last listed.
func (s *Store) TagsCheckedAt(ctx context.Context, repository string) (time.Time, string, error) {
	var at time.Time
	var e string
	err := s.db.QueryRowContext(ctx, `SELECT checked_at, error FROM registry_tags WHERE repository = $1`, repository).Scan(&at, &e)
	return at, e, mapErr(err)
}

// SaveTags records a repository's tags; a failed listing keeps the old ones.
func (s *Store) SaveTags(ctx context.Context, repository string, tags []string, listErr string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO registry_tags (repository, tags, checked_at, error) VALUES ($1, $2, now(), $3)
		ON CONFLICT (repository) DO UPDATE
		SET checked_at = now(), error = EXCLUDED.error,
		    tags = CASE WHEN EXCLUDED.error = '' THEN EXCLUDED.tags ELSE registry_tags.tags END`,
		repository, pq.Array(nonNil(tags)), listErr)
	return err
}

// RepositoryTags returns the stored tags of the given repositories.
func (s *Store) RepositoryTags(ctx context.Context, repos []string) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT repository, tags FROM registry_tags WHERE repository = ANY($1)`, pq.Array(nonNil(repos)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var repo string
		var tags []string
		if err := rows.Scan(&repo, pq.Array(&tags)); err != nil {
			return nil, err
		}
		out[repo] = tags
	}
	return out, rows.Err()
}

func (s *Store) strings(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Registry credentials -----------------------------------------------------------

// RegistryCred is a login for a container registry. The secret is stored
// sealed with BASELINE_SECRET_KEY; callers seal and open it.
type RegistryCred struct {
	ID        string
	Registry  string
	Username  string
	SecretEnc string
	CreatedAt time.Time
}

func (s *Store) ListRegistryCreds(ctx context.Context) ([]RegistryCred, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, registry, username, secret_enc, created_at FROM registry_cred ORDER BY registry`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RegistryCred
	for rows.Next() {
		var c RegistryCred
		if err := rows.Scan(&c.ID, &c.Registry, &c.Username, &c.SecretEnc, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveRegistryCred adds or replaces the login for a registry. Checks of
// images on it run again at once.
func (s *Store) SaveRegistryCred(ctx context.Context, actor Actor, registry, username, secretEnc string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO registry_cred (registry, username, secret_enc, created_by)
			VALUES ($1, $2, $3, (SELECT id FROM app_user WHERE id = $4))
			ON CONFLICT (registry) DO UPDATE
			SET username = EXCLUDED.username, secret_enc = EXCLUDED.secret_enc, created_by = EXCLUDED.created_by, created_at = now()`,
			registry, username, secretEnc, actor.userID()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE image_check SET checked_at = 'epoch' WHERE registry = $1`, registry); err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "registry_cred.save", ObjectType: "registry_cred", ObjectID: registry,
			Details: map[string]any{"registry": registry, "username": username},
		})
	})
}

func (s *Store) DeleteRegistryCred(ctx context.Context, actor Actor, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var registry string
		if err := tx.QueryRowContext(ctx, `DELETE FROM registry_cred WHERE id = $1 RETURNING registry`, id).Scan(&registry); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "registry_cred.delete", ObjectType: "registry_cred", ObjectID: registry,
			Details: map[string]any{"registry": registry},
		})
	})
}

// SaveProbeCert records the server's own TLS check of a CI's endpoint,
// replacing earlier probes of other addresses.
func (s *Store) SaveProbeCert(ctx context.Context, ciID string, c model.Cert, probeErr string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM ci_cert WHERE ci_id = $1 AND source = 'probe' AND location <> $2`,
			ciID, c.Location); err != nil {
			return err
		}
		if probeErr != "" {
			// Keep what an earlier probe found; just note the failure.
			res, err := tx.ExecContext(ctx, `UPDATE ci_cert SET error = $3, checked_at = now() WHERE ci_id = $1 AND location = $2`,
				ciID, c.Location, probeErr)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				return nil
			}
		}
		return insertCert(ctx, tx, ciID, "probe", c, probeErr)
	})
}

// ClearProbeCerts removes probe results of CIs that no longer have an
// endpoint configured.
func (s *Store) ClearProbeCerts(ctx context.Context, keep []string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ci_cert WHERE source = 'probe' AND NOT ci_id::text = ANY($1)`, pq.Array(nonNil(keep)))
	return err
}
