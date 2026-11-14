package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/registry"
	"github.com/jw6ventures/baseline/internal/stackname"
)

// MissingAfter is how long a container or stack can be gone before its CI
// is marked missing (docs/data-model.md §1). Compose recreating a container
// takes seconds; an hour rides out a host reboot.
const MissingAfter = time.Hour

// keepFailedEngines carries over what the previous snapshot had for engines
// that couldn't be read this time: a Docker daemon restarting shouldn't
// look like every container was removed.
func keepFailedEngines(prev, cur []byte) ([]byte, error) {
	var p, c model.Containers
	if err := json.Unmarshal(cur, &c); err != nil {
		return nil, err
	}
	failed := map[string]bool{}
	for _, e := range c.Engines {
		if e.Error != "" {
			failed[e.Name] = true
		}
	}
	if len(failed) == 0 || prev == nil {
		return cur, nil
	}
	if err := json.Unmarshal(prev, &p); err != nil {
		return cur, nil // an older, unreadable copy: nothing to keep
	}
	for _, x := range p.Containers {
		if failed[x.Engine] {
			c.Containers = append(c.Containers, x)
		}
	}
	for _, x := range p.Images {
		if failed[x.Engine] {
			c.Images = append(c.Images, x)
		}
	}
	for _, x := range p.Stacks {
		if failed[x.Engine] {
			c.Stacks = append(c.Stacks, x)
		}
	}
	slices.SortFunc(c.Containers, func(a, b model.Container) int { return strings.Compare(a.Key(), b.Key()) })
	slices.SortFunc(c.Images, func(a, b model.ContainerImage) int {
		return strings.Compare(a.Engine+"/"+a.ID, b.Engine+"/"+b.ID)
	})
	slices.SortFunc(c.Stacks, func(a, b model.ComposeStack) int { return strings.Compare(a.Key(), b.Key()) })
	return json.Marshal(c)
}

// checkRef works out what a registry can be asked about a container's image:
// the normalized reference and the digests the image was pulled by from that
// repository. Images pinned by digest, built locally or loaded from a file
// have nothing to compare, so they're left out.
func checkRef(imageRef string, repoDigests []string) (string, []string) {
	ref, err := registry.ParseRef(imageRef)
	if err != nil || ref.Digest != "" || ref.Tag == "" {
		return "", nil
	}
	var digests []string
	for _, rd := range repoDigests {
		repo, digest, ok := strings.Cut(rd, "@")
		if !ok {
			continue
		}
		if r, err := registry.ParseRef(repo); err == nil && r.Repo() == ref.Repo() {
			digests = append(digests, digest)
		}
	}
	if len(digests) == 0 {
		return "", nil
	}
	slices.Sort(digests)
	return ref.String(), slices.Compact(digests)
}

func containerSourceKey(hostID, engine, name string) string {
	return hostID + "/" + engine + "/" + name
}

func projectContainers(ctx context.Context, tx *sql.Tx, hostID string, payload []byte) error {
	var c model.Containers
	if err := json.Unmarshal(payload, &c); err != nil {
		return err
	}
	digests := map[string][]string{} // engine/image ID -> RepoDigests
	for _, im := range c.Images {
		digests[im.Engine+"/"+im.ID] = im.Digests
	}

	// Stacks first: containers link to them.
	stackCI := map[string]string{} // engine/project -> CI
	var present []string
	for _, st := range c.Stacks {
		var files []string
		for _, f := range st.ConfigFiles {
			files = append(files, f.Path)
		}
		// What the project's name says (environment, category, visibility).
		attrs, err := json.Marshal(nonNilMap(stackname.Attrs(st.Project)))
		if err != nil {
			return err
		}
		var id string
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO ci (type, name, source, source_key, status, last_seen, attrs)
			VALUES ('compose_stack', $2, 'agent', $1, 'active', now(), $3)
			ON CONFLICT (source, source_key) DO UPDATE
			SET status = 'active', last_seen = now(), name = EXCLUDED.name, attrs = EXCLUDED.attrs,
			    updated_at = CASE WHEN ci.status <> 'active' OR ci.attrs <> EXCLUDED.attrs THEN now() ELSE ci.updated_at END
			RETURNING id`, containerSourceKey(hostID, st.Engine, "compose:"+st.Project), st.Project, string(attrs)).Scan(&id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO compose_stack (ci_id, host, engine, project, working_dir, config_files, cli, orphaned, stopped, present)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true)
			ON CONFLICT (host, engine, project) DO UPDATE
			SET working_dir = EXCLUDED.working_dir, config_files = EXCLUDED.config_files, cli = EXCLUDED.cli,
			    orphaned = EXCLUDED.orphaned, stopped = EXCLUDED.stopped, present = true`,
			id, hostID, st.Engine, st.Project, st.WorkingDir, pq.Array(nonNil(files)), st.CLI, st.Orphaned, st.Stopped); err != nil {
			return err
		}
		stackCI[st.Key()] = id
		present = append(present, id)
	}
	// Stacks that went away keep their settings; their CI turns missing later.
	if _, err := tx.ExecContext(ctx, `
		WITH gone AS (
		    UPDATE compose_stack SET present = false
		    WHERE host = $1 AND present AND NOT ci_id::text = ANY($2) RETURNING ci_id)
		UPDATE ci SET last_seen = now() FROM gone WHERE ci.id = gone.ci_id`,
		hostID, pq.Array(nonNil(present))); err != nil {
		return err
	}

	n := len(c.Containers)
	names, keys := make([]string, n), make([]string, n)
	for i, ct := range c.Containers {
		names[i], keys[i] = ct.Name, containerSourceKey(hostID, ct.Engine, ct.Name)
	}
	ciByKey := map[string]string{}
	rows, err := tx.QueryContext(ctx, `
		INSERT INTO ci (type, name, source, source_key, status, last_seen)
		SELECT 'container', n, 'agent', k, 'active', now() FROM unnest($1::text[], $2::text[]) AS t(n, k)
		ON CONFLICT (source, source_key) DO UPDATE
		SET status = 'active', last_seen = now(),
		    updated_at = CASE WHEN ci.status <> 'active' THEN now() ELSE ci.updated_at END
		RETURNING id, source_key`, pq.Array(names), pq.Array(keys))
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, key string
		if err := rows.Scan(&id, &key); err != nil {
			rows.Close()
			return err
		}
		ciByKey[key] = id
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Containers that went away: note when they were last seen, so they
	// turn missing an hour from now unless they come back.
	ids := make([]string, 0, n)
	for _, k := range keys {
		ids = append(ids, ciByKey[k])
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE ci SET last_seen = now()
		WHERE id IN (SELECT ci_id FROM container WHERE host = $1 AND NOT ci_id::text = ANY($2))`,
		hostID, pq.Array(ids)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM container WHERE host = $1`, hostID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM ci_relationship WHERE source = 'discovered' AND kind = 'member_of'
		AND from_ci = ANY($1::uuid[])`, pq.Array(ids)); err != nil {
		return err
	}
	for i, ct := range c.Containers {
		id := ciByKey[keys[i]]
		ref, imgDigests := checkRef(ct.Image, digests[ct.Engine+"/"+ct.ImageID])
		labels, err := json.Marshal(nonNilMap(ct.Labels))
		if err != nil {
			return err
		}
		attrs, err := json.Marshal(ct)
		if err != nil {
			return err
		}
		var started sql.NullTime
		if t, err := time.Parse(time.RFC3339, ct.StartedAt); err == nil {
			started = sql.NullTime{Time: t, Valid: true}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO container (ci_id, host, engine, name, engine_id, image_ref, image_id, check_ref, image_digests,
			                       state, health, started_at, compose_project, compose_service, labels, attrs)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
			id, hostID, ct.Engine, ct.Name, ct.ID, ct.Image, ct.ImageID, ref, pq.Array(nonNil(imgDigests)),
			ct.State, ct.Health, started, ct.ComposeProject, ct.ComposeService, string(labels), string(attrs)); err != nil {
			return err
		}
		if err := relate(ctx, tx, id, hostID, "runs_on"); err != nil {
			return err
		}
		if st, ok := stackCI[ct.Engine+"/"+ct.ComposeProject]; ok && ct.ComposeProject != "" {
			if err := relate(ctx, tx, id, st, "member_of"); err != nil {
				return err
			}
		}
	}
	for _, id := range stackCI {
		if err := relate(ctx, tx, id, hostID, "runs_on"); err != nil {
			return err
		}
	}
	ctrCI := make(map[string]string, n)
	for i, ct := range c.Containers {
		ctrCI[ct.Key()] = ciByKey[keys[i]]
	}
	return projectTraefik(ctx, tx, hostID, c.Containers, ctrCI, stackCI)
}

// relate records a discovered relationship.
func relate(ctx context.Context, tx *sql.Tx, from, to, kind string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO ci_relationship (from_ci, to_ci, kind, source) VALUES ($1, $2, $3, 'discovered')
		ON CONFLICT (from_ci, to_ci, kind) DO NOTHING`, from, to, kind)
	return err
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// MarkMissing turns containers, stacks, Traefik and Ingress hostnames, hypervisor
// guests, Kubernetes objects and what UniFi consoles reported that have been gone for MissingAfter into
// missing CIs. They're never deleted automatically, so their history and
// relationships survive.
func (s *Store) MarkMissing(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE ci SET status = 'missing', updated_at = now()
		WHERE source <> 'manual' AND status = 'active' AND last_seen < $1
		  AND ((type = 'container' AND NOT EXISTS (SELECT 1 FROM container c WHERE c.ci_id = ci.id))
		    OR (type = 'compose_stack' AND NOT EXISTS (SELECT 1 FROM compose_stack s WHERE s.ci_id = ci.id AND s.present))
		    OR (type = 'service_endpoint' AND EXISTS (SELECT 1 FROM traefik_hostname th WHERE th.ci_id = ci.id AND NOT th.present))
		    OR (type = 'service_endpoint' AND EXISTS (SELECT 1 FROM k8s_ingress_host ih WHERE ih.ci_id = ci.id AND NOT ih.present))
		    OR (type IN ('vm', 'lxc') AND source IN ('proxmox', 'libvirt')
		        AND NOT EXISTS (SELECT 1 FROM vm_guest g WHERE g.ci_id = ci.id AND g.present))
		    OR (type IN ('k8s_node', 'k8s_workload')
		        AND NOT EXISTS (SELECT 1 FROM k8s_object o WHERE o.ci_id = ci.id AND o.present))
		    OR (source = 'unifi' AND NOT EXISTS (SELECT 1 FROM unifi_object u WHERE u.ci_id = ci.id AND u.present)))`,
		now.Add(-MissingAfter))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Queries ----------------------------------------------------------------------

// ContainerRow is a container with its host and update status.
type ContainerRow struct {
	model.Container
	CIID     string
	HostID   string
	Hostname string
	// CheckRef is the normalized reference registries are asked about;
	// "" when the image can't be checked (built locally, pinned by digest).
	CheckRef      string
	ImageDigests  []string
	LatestDigest  string
	CheckedAt     time.Time
	CheckError    string
	Drift         bool // the tag now points to a newer image
	Pinned        bool // its stack is pinned: no update prompts
	StackCI       string
	SemverRule    json.RawMessage // the container's own rule; stacks hold their services' rules
	HostConnected bool
}

const containerCols = `c.ci_id, c.host, h.hostname, h.connected, c.attrs::text, c.check_ref, c.image_digests,
	COALESCE(u.latest_digest, ''), COALESCE(u.checked_at, 'epoch'), COALESCE(u.error, ''),
	COALESCE(u.drift, false), COALESCE(u.pinned, false),
	COALESCE((SELECT s.ci_id::text FROM compose_stack s WHERE s.host = c.host AND s.engine = c.engine
	          AND s.project = c.compose_project AND c.compose_project <> ''), ''),
	COALESCE((SELECT ci.attrs->'semver_rule' FROM ci WHERE ci.id = c.ci_id), 'null')::text`

func scanContainer(row interface{ Scan(...any) error }) (ContainerRow, error) {
	var c ContainerRow
	var attrs, rule string
	err := row.Scan(&c.CIID, &c.HostID, &c.Hostname, &c.HostConnected, &attrs, &c.CheckRef, pq.Array(&c.ImageDigests),
		&c.LatestDigest, &c.CheckedAt, &c.CheckError, &c.Drift, &c.Pinned, &c.StackCI, &rule)
	if err != nil {
		return c, err
	}
	if c.CheckedAt.Unix() == 0 {
		c.CheckedAt = time.Time{}
	}
	if rule != "null" {
		c.SemverRule = json.RawMessage(rule)
	}
	return c, json.Unmarshal([]byte(attrs), &c.Container)
}

// SemverRules returns the rule that applies to each row: its Compose
// service's, kept on its stack, else its own; nil for none.
func SemverRules(rows []ContainerRow, stacks []Stack) []*registry.Rule {
	byService := map[string]registry.Rule{} // stack CI + service -> rule
	for _, st := range stacks {
		for svc, rule := range st.SemverRules {
			byService[st.CIID+"/"+svc] = rule
		}
	}
	out := make([]*registry.Rule, len(rows))
	for i, c := range rows {
		if rule, ok := byService[c.StackCI+"/"+c.ComposeService]; ok && c.StackCI != "" && c.ComposeService != "" {
			out[i] = &rule
		} else if c.SemverRule != nil {
			var rule registry.Rule
			if json.Unmarshal(c.SemverRule, &rule) == nil {
				out[i] = &rule
			}
		}
	}
	return out
}

// Advise returns the newest tag of its repository that rule allows the
// container, given the repository's tags and what its tags were last
// checked to serve (by reference, from RepositoryImageChecks). A tag
// serving the image the container's tag does, or the one it runs, is no
// update and is passed over.
func (c ContainerRow) Advise(rule registry.Rule, tags []string, checks map[string]ImageCheck) (string, bool) {
	ref, err := registry.ParseRef(c.CheckRef)
	if err != nil || ref.Tag == "" {
		return "", false
	}
	same := func(tag string) bool {
		d := checks[ref.Repo()+":"+tag].Digest
		return d != "" && (d == c.LatestDigest || slices.Contains(c.ImageDigests, d))
	}
	return registry.AdviseExcept(ref.Tag, tags, rule, same)
}

// ListContainers returns the containers on the given hosts, by host and name.
func (s *Store) ListContainers(ctx context.Context, hostIDs []string) ([]ContainerRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+containerCols+` FROM container c JOIN host h ON h.ci_id = c.host
		LEFT JOIN container_update u ON u.ci_id = c.ci_id
		WHERE c.host::text = ANY($1)
		ORDER BY lower(h.hostname), c.compose_project, c.name`, pq.Array(nonNil(hostIDs)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ContainerRow
	for rows.Next() {
		c, err := scanContainer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetContainer returns one container by its CI ID.
func (s *Store) GetContainer(ctx context.Context, ciID string) (ContainerRow, error) {
	c, err := scanContainer(s.db.QueryRowContext(ctx, `
		SELECT `+containerCols+` FROM container c JOIN host h ON h.ci_id = c.host
		LEFT JOIN container_update u ON u.ci_id = c.ci_id
		WHERE c.ci_id = $1`, ciID))
	return c, mapErr(err)
}

// Stack is a Compose stack and its settings.
type Stack struct {
	CIID        string
	HostID      string
	Hostname    string
	Engine      string
	Project     string
	WorkingDir  string
	ConfigFiles []string
	CLI         string
	Orphaned    bool
	// Stopped: found on disk under a Compose root, nothing of it running.
	Stopped     bool
	Present     bool
	AutoUpdate  bool
	Pinned      bool
	SemverRules map[string]registry.Rule // by service
	// UpdateGroups are the update groups set on the stack's page, by
	// service; a container's labels win over them (internal/updategroup).
	UpdateGroups map[string]UpdateGroup
	Containers   int
	Running      int
	Drift        int // containers whose tag moved on
	Status       string
	// Updates: the Standard change model they run under (manual ones too;
	// auto-update needs one) and the stack's own maintenance window.
	ModelID    string
	ModelName  string
	ModelState string
	WindowID   string
	WindowName string
	// From the project's name (internal/stackname); "" when it carries none.
	Environment string
	Category    string
	Visibility  string
}

// Named reports whether the stack's name carries metadata.
func (st Stack) Named() bool { return st.Environment != "" }

// Drivable reports whether Baseline can run Compose on the stack's files,
// and if not, why.
func (st Stack) Drivable() (bool, string) {
	switch {
	case !st.Present:
		return false, "its containers are gone"
	case st.Orphaned:
		return false, "its Compose files aren't readable on the host"
	case st.CLI == "":
		return false, "no Compose CLI on the host"
	}
	return true, ""
}

// Updatable reports whether Baseline can update the stack, and if not, why.
func (st Stack) Updatable() (bool, string) {
	if st.Stopped {
		return false, "it isn't running; start it first"
	}
	return st.Drivable()
}

// Can reports whether Baseline can run a compose.* action on the stack, and
// if not, why.
func (st Stack) Can(act string) (bool, string) {
	switch act {
	case action.ComposeStart:
		return st.Startable()
	case action.ComposeArchive, action.ComposeMove:
		return st.Drivable()
	}
	return st.Updatable()
}

// Startable reports whether Baseline can start the stack, and if not, why:
// none of its containers may be running.
func (st Stack) Startable() (bool, string) {
	if ok, why := st.Drivable(); !ok {
		return false, why
	}
	if st.Running > 0 {
		return false, "it is running"
	}
	return true, ""
}

const stackCols = `s.ci_id, s.host, h.hostname, s.engine, s.project, s.working_dir, s.config_files, s.cli,
	s.orphaned, s.stopped, s.present, s.auto_update, s.pinned, s.semver_rules::text, s.update_groups::text, ci.status,
	(SELECT count(*) FROM container c WHERE c.host = s.host AND c.engine = s.engine AND c.compose_project = s.project),
	(SELECT count(*) FROM container c WHERE c.host = s.host AND c.engine = s.engine AND c.compose_project = s.project
	   AND c.state = 'running'),
	(SELECT count(*) FROM container c JOIN container_update u ON u.ci_id = c.ci_id
	   WHERE c.host = s.host AND c.engine = s.engine AND c.compose_project = s.project AND u.drift),
	COALESCE(s.change_model_id::text, ''), COALESCE(m.name, ''), COALESCE(m.state, ''),
	COALESCE(s.window_id::text, ''), COALESCE(w.name, ''),
	COALESCE(ci.attrs->>'environment', ''), COALESCE(ci.attrs->>'category', ''), COALESCE(ci.attrs->>'visibility', '')`

const stackFrom = ` FROM compose_stack s JOIN host h ON h.ci_id = s.host JOIN ci ON ci.id = s.ci_id
	LEFT JOIN change_model m ON m.id = s.change_model_id LEFT JOIN maintenance_window w ON w.id = s.window_id `

func scanStack(row interface{ Scan(...any) error }) (Stack, error) {
	var st Stack
	var rules, groups string
	err := row.Scan(&st.CIID, &st.HostID, &st.Hostname, &st.Engine, &st.Project, &st.WorkingDir, pq.Array(&st.ConfigFiles),
		&st.CLI, &st.Orphaned, &st.Stopped, &st.Present, &st.AutoUpdate, &st.Pinned, &rules, &groups, &st.Status,
		&st.Containers, &st.Running, &st.Drift, &st.ModelID, &st.ModelName, &st.ModelState, &st.WindowID, &st.WindowName,
		&st.Environment, &st.Category, &st.Visibility)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal([]byte(groups), &st.UpdateGroups); err != nil {
		return st, err
	}
	return st, json.Unmarshal([]byte(rules), &st.SemverRules)
}

// ListStacks returns the stacks on the given hosts, present ones first.
// Gone stacks that were retired (RetireMissingStacks) are left out.
func (s *Store) ListStacks(ctx context.Context, hostIDs []string) ([]Stack, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+stackCols+stackFrom+`
		WHERE s.host::text = ANY($1) AND (s.present OR ci.status <> 'retired')
		ORDER BY NOT s.present, lower(h.hostname), s.project`, pq.Array(nonNil(hostIDs)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Stack
	for rows.Next() {
		st, err := scanStack(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) GetStack(ctx context.Context, ciID string) (Stack, error) {
	st, err := scanStack(s.db.QueryRowContext(ctx, `
		SELECT `+stackCols+stackFrom+`
		WHERE s.ci_id = $1`, ciID))
	return st, mapErr(err)
}

// SetStackPinned turns update prompts for a stack off or on.
func (s *Store) SetStackPinned(ctx context.Context, actor Actor, ciID string, pinned bool) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var project, host string
		if err := tx.QueryRowContext(ctx, `
			UPDATE compose_stack SET pinned = $2 WHERE ci_id = $1 RETURNING project, host`, ciID, pinned).
			Scan(&project, &host); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "stack.pin", ObjectType: "compose_stack", ObjectID: ciID,
			Details: map[string]any{"project": project, "host": host, "pinned": pinned},
		})
	})
}

// AutoUpdateStacks lists the stacks set to update themselves, whatever
// their state; internal/change decides which to update.
func (s *Store) AutoUpdateStacks(ctx context.Context) ([]Stack, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+stackCols+stackFrom+` WHERE s.auto_update AND NOT h.revoked
		ORDER BY lower(h.hostname), s.project`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Stack
	for rows.Next() {
		st, err := scanStack(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// SetStackUpdates sets how a stack's updates run: the Standard change model
// ("" for Normal changes), its own window ("" for the host's) and
// auto-update, which needs a model.
func (s *Store) SetStackUpdates(ctx context.Context, actor Actor, ciID, modelID, windowID string, auto bool) error {
	if auto && modelID == "" {
		return errors.New("auto-update runs under a Standard change model; pick one")
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var project, host string
		if err := tx.QueryRowContext(ctx, `
			UPDATE compose_stack SET change_model_id = $2, window_id = $3, auto_update = $4 WHERE ci_id = $1
			RETURNING project, host`, ciID, nullString(modelID), nullString(windowID), auto).Scan(&project, &host); err != nil {
			return mapErr(err)
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "stack.updates", ObjectType: "compose_stack", ObjectID: ciID,
			Details: map[string]any{"project": project, "host": host, "model": modelID, "window": windowID, "auto_update": auto},
		})
	})
}

// SetSemverRule sets or clears (rule nil) the semver advisory rule of a
// container. A Compose service's rule is kept on its stack, so it carries
// over to the containers Compose recreates and to every replica.
func (s *Store) SetSemverRule(ctx context.Context, actor Actor, containerCI string, rule *registry.Rule) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name, project, service, stack string
		if err := tx.QueryRowContext(ctx, `
			SELECT c.name, c.compose_project, c.compose_service,
			       COALESCE((SELECT s.ci_id::text FROM compose_stack s WHERE s.host = c.host AND s.engine = c.engine
			                 AND s.project = c.compose_project AND c.compose_project <> ''), '')
			FROM container c WHERE c.ci_id = $1`, containerCI).Scan(&name, &project, &service, &stack); err != nil {
			return mapErr(err)
		}
		var b []byte
		if rule != nil {
			var err error
			if b, err = json.Marshal(rule); err != nil {
				return err
			}
		}
		var err error
		switch {
		case stack != "" && service != "" && rule != nil:
			_, err = tx.ExecContext(ctx, `
				UPDATE compose_stack SET semver_rules = jsonb_set(semver_rules, ARRAY[$2::text], $3::jsonb) WHERE ci_id = $1`,
				stack, service, string(b))
		case stack != "" && service != "":
			_, err = tx.ExecContext(ctx, `UPDATE compose_stack SET semver_rules = semver_rules - $2::text WHERE ci_id = $1`, stack, service)
		case rule != nil:
			_, err = tx.ExecContext(ctx, `UPDATE ci SET attrs = jsonb_set(attrs, '{semver_rule}', $2::jsonb) WHERE id = $1`,
				containerCI, string(b))
		default:
			_, err = tx.ExecContext(ctx, `UPDATE ci SET attrs = attrs - 'semver_rule' WHERE id = $1`, containerCI)
		}
		if err != nil {
			return err
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "container.semver_rule", ObjectType: "container", ObjectID: containerCI,
			Details: map[string]any{"container": name, "project": project, "service": service, "rule": rule},
		})
	})
}

// UpdateGroup puts a Compose service in an update group: its members
// update together, lowest Order first (docs/change-management.md §5.3).
type UpdateGroup struct {
	Group string `json:"group"`
	Order int    `json:"order"`
}

// SetStackUpdateGroup puts a service of a stack in an update group, or
// takes it out (g nil). Labels on the service's containers win over it.
func (s *Store) SetStackUpdateGroup(ctx context.Context, actor Actor, stackCI, service string, g *UpdateGroup) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var project, host string
		var err error
		if g != nil {
			b, merr := json.Marshal(g)
			if merr != nil {
				return merr
			}
			err = tx.QueryRowContext(ctx, `
				UPDATE compose_stack SET update_groups = jsonb_set(update_groups, ARRAY[$2::text], $3::jsonb)
				WHERE ci_id = $1 RETURNING project, host`, stackCI, service, string(b)).Scan(&project, &host)
		} else {
			err = tx.QueryRowContext(ctx, `
				UPDATE compose_stack SET update_groups = update_groups - $2::text
				WHERE ci_id = $1 RETURNING project, host`, stackCI, service).Scan(&project, &host)
		}
		if err != nil {
			return mapErr(err)
		}
		details := map[string]any{"project": project, "host": host, "service": service}
		if g != nil {
			details["group"], details["order"] = g.Group, g.Order
		}
		return appendAudit(ctx, tx, actor, AuditEvent{
			Action: "stack.update_group", ObjectType: "compose_stack", ObjectID: stackCI, Details: details,
		})
	})
}
