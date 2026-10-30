package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/jw6ventures/baseline/internal/action"
)

// Job states (docs/data-model.md §4).
const (
	JobQueued     = "queued"
	JobDispatched = "dispatched"
	JobRunning    = "running"
	JobSucceeded  = "succeeded"
	JobFailed     = "failed"
	JobCancelled  = "cancelled"
	JobTimedOut   = "timed_out"
	JobRejected   = "rejected"
	// JobRolledBack: the action failed and put things back as they were
	// (compose.update).
	JobRolledBack = "rolled_back"

	// JobRebooting is what an agent reports for a job that finishes once
	// the host is back. The job stays running meanwhile.
	JobRebooting = "rebooting"
)

const (
	// MaxJobOutput caps the output kept per job.
	MaxJobOutput = 5 << 20
	// jobGrace is how long past its timeout the server waits for an
	// agent's own timeout to arrive before giving up on a job.
	jobGrace = 5 * time.Minute
	// offlineLimit is how long a job waits for its host to come online.
	offlineLimit = time.Hour
	// rebootWindow attributes changes reported shortly after a job that
	// rebooted the host (the new kernel, restarted services) to its change.
	rebootWindowSQL = "10 minutes"
)

// Job is one action on one host.
type Job struct {
	ID              string
	ChangeID        string
	ChangeNumber    int64
	ChangeTitle     string
	ChangeState     string
	Seq             int
	HostID          string
	AgentID         string
	Hostname        string
	Action          string
	Params          json.RawMessage
	ScriptID        string
	ScriptVersion   int
	TimeoutS        int
	State           string
	AwaitingReboot  bool
	QueuedAt        time.Time
	DispatchedAt    time.Time
	StartedAt       time.Time
	FinishedAt      time.Time
	ExitCode        sql.NullInt64
	Result          json.RawMessage
	Error           string
	OutputBytes     int
	RequestedByName string
}

// Summary is a one-line description of what the job does.
func (j Job) Summary() string { return action.Describe(j.Action, j.Params) }

// ChangeRef is the job's change, CHG-000123.
func (j Job) ChangeRef() string { return ChangeRef(j.ChangeNumber) }

// Final reports whether the job has ended.
func (j Job) Final() bool {
	return j.State != JobQueued && j.State != JobDispatched && j.State != JobRunning
}

// Duration is how long the job ran, or has been running.
func (j Job) Duration() time.Duration {
	switch {
	case j.StartedAt.IsZero():
		return 0
	case j.FinishedAt.IsZero():
		return time.Since(j.StartedAt).Round(time.Second)
	}
	return j.FinishedAt.Sub(j.StartedAt).Round(time.Second)
}

// JobRef locates a job's agent, to ask it to stop the job.
type JobRef struct {
	ID      string
	HostID  string
	AgentID string
}

const jobCols = `j.id, j.change_id, c.number, c.title, c.state, j.seq, j.host, h.agent_id, h.hostname, j.action, j.params::text,
	COALESCE(j.script_id::text, ''), COALESCE(j.script_version, 0), j.timeout_s, j.state, j.awaiting_reboot, j.queued_at,
	COALESCE(j.dispatched_at, 'epoch'), COALESCE(j.started_at, 'epoch'), COALESCE(j.finished_at, 'epoch'),
	j.exit_code, COALESCE(j.result::text, ''), j.error, j.output_bytes, COALESCE(NULLIF(u.name, ''), u.email, '')`

const jobFrom = ` FROM job j JOIN change c ON c.id = j.change_id JOIN host h ON h.ci_id = j.host
	LEFT JOIN app_user u ON u.id = j.requested_by `

func scanJob(row interface{ Scan(...any) error }) (Job, error) {
	var j Job
	var params, result string
	err := row.Scan(&j.ID, &j.ChangeID, &j.ChangeNumber, &j.ChangeTitle, &j.ChangeState, &j.Seq, &j.HostID, &j.AgentID,
		&j.Hostname, &j.Action, &params, &j.ScriptID, &j.ScriptVersion, &j.TimeoutS, &j.State, &j.AwaitingReboot,
		&j.QueuedAt, &j.DispatchedAt, &j.StartedAt, &j.FinishedAt, &j.ExitCode, &result, &j.Error, &j.OutputBytes,
		&j.RequestedByName)
	j.Params = json.RawMessage(params)
	if result != "" {
		j.Result = json.RawMessage(result)
	}
	for _, t := range []*time.Time{&j.DispatchedAt, &j.StartedAt, &j.FinishedAt} {
		if t.Unix() == 0 {
			*t = time.Time{}
		}
	}
	return j, err
}

// JobFilter narrows ListJobs.
type JobFilter struct {
	ChangeID string
	HostID   string
	States   []string
	Limit    int
}

// ListJobs returns jobs, newest first (in plan order within a change).
func (s *Store) ListJobs(ctx context.Context, f JobFilter) ([]Job, error) {
	if f.Limit <= 0 {
		f.Limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+jobCols+jobFrom+`
		WHERE ($1 = '' OR j.change_id::text = $1) AND ($2 = '' OR j.host::text = $2)
		  AND (cardinality($3::text[]) = 0 OR j.state = ANY($3))
		ORDER BY c.number DESC, j.seq LIMIT $4`, f.ChangeID, f.HostID, pq.Array(nonNil(f.States)), f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanJobs(rows)
}

func scanJobs(rows *sql.Rows) ([]Job, error) {
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) GetJob(ctx context.Context, id string) (Job, error) {
	j, err := scanJob(s.db.QueryRowContext(ctx, `SELECT `+jobCols+jobFrom+` WHERE j.id = $1`, id))
	return j, mapErr(err)
}

// OutputChunk is a piece of a job's output.
type OutputChunk struct {
	ID     int64
	Seq    int64
	Stream string
	At     time.Time
	Chunk  string
}

// JobOutput returns output stored after the chunk with ID after, in
// arrival order.
func (s *Store) JobOutput(ctx context.Context, jobID string, after int64, limit int) ([]OutputChunk, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, seq, stream, at, chunk FROM job_output WHERE job_id = $1 AND id > $2 ORDER BY id LIMIT $3`,
		jobID, after, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []OutputChunk
	for rows.Next() {
		var c OutputChunk
		if err := rows.Scan(&c.ID, &c.Seq, &c.Stream, &c.At, &c.Chunk); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Dispatching -------------------------------------------------------------------

// QueuedJob is a job waiting for dispatch, with its change's limits.
type QueuedJob struct {
	Job
	Concurrency int
	Open        int    // the change's jobs already dispatched or running
	Kind        string // the change's
	// WindowEndsAt is when the change's window opening ends; zero without
	// a window.
	WindowEndsAt time.Time
}

// QueuedJobs lists the queued jobs of changes in progress, in plan order.
func (s *Store) QueuedJobs(ctx context.Context) ([]QueuedJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+jobCols+`, c.concurrency,
		(SELECT count(*) FROM job o WHERE o.change_id = j.change_id AND o.state IN ('dispatched', 'running')),
		c.kind, COALESCE(c.window_ends_at, 'epoch')`+jobFrom+`
		WHERE c.state = 'in_progress' AND j.state = 'queued' AND NOT h.revoked
		ORDER BY c.number, j.seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QueuedJob
	for rows.Next() {
		var q QueuedJob
		var params, result string
		j := &q.Job
		if err := rows.Scan(&j.ID, &j.ChangeID, &j.ChangeNumber, &j.ChangeTitle, &j.ChangeState, &j.Seq, &j.HostID, &j.AgentID,
			&j.Hostname, &j.Action, &params, &j.ScriptID, &j.ScriptVersion, &j.TimeoutS, &j.State, &j.AwaitingReboot,
			&j.QueuedAt, &j.DispatchedAt, &j.StartedAt, &j.FinishedAt, &j.ExitCode, &result, &j.Error, &j.OutputBytes,
			&j.RequestedByName, &q.Concurrency, &q.Open, &q.Kind, &q.WindowEndsAt); err != nil {
			return nil, err
		}
		if q.WindowEndsAt.Unix() == 0 {
			q.WindowEndsAt = time.Time{}
		}
		j.Params = json.RawMessage(params)
		out = append(out, q)
	}
	return out, rows.Err()
}

// MarkDispatched records that a queued job is being sent to its agent. It
// returns false if the job is no longer queued (its change was cancelled).
func (s *Store) MarkDispatched(ctx context.Context, j Job) (bool, error) {
	ok := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE job SET state = 'dispatched', dispatched_at = now() WHERE id = $1 AND state = 'queued'`, j.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		ok = true
		return appendAudit(ctx, tx, System, AuditEvent{Action: "job.dispatch", ObjectType: "job", ObjectID: j.ID,
			Details: map[string]any{"change": j.ChangeRef(), "host": j.Hostname, "action": j.Action, "params": j.Params}})
	})
	return ok, err
}

// OpenJobs lists a host's jobs that were sent but haven't ended, which an
// agent is sent again when it connects.
func (s *Store) OpenJobs(ctx context.Context, hostID string) ([]Job, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+jobCols+jobFrom+`
		WHERE j.host = $1 AND j.state IN ('dispatched', 'running') ORDER BY c.number, j.seq`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanJobs(rows)
}

// JobStarted records that the agent began a job.
func (s *Store) JobStarted(ctx context.Context, hostID, jobID string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE job SET state = 'running', started_at = COALESCE(started_at, now())
		WHERE id::text = $1 AND host = $2 AND state IN ('queued', 'dispatched')`, jobID, hostID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// AppendJobOutput stores a chunk of output. Chunks the server already has
// (the agent resends after a reconnect) are dropped, and so is everything
// past MaxJobOutput, after one note saying so.
func (s *Store) AppendJobOutput(ctx context.Context, hostID, jobID string, seq int64, stream, chunk string) (bool, error) {
	chunk = cleanText(chunk)
	stored := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var size int
		if err := tx.QueryRowContext(ctx,
			`SELECT output_bytes FROM job WHERE id::text = $1 AND host = $2 FOR UPDATE`, jobID, hostID).Scan(&size); err != nil {
			return mapErr(err)
		}
		if size > MaxJobOutput {
			return nil // already truncated
		}
		if size+len(chunk) > MaxJobOutput {
			stored = true
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO job_output (job_id, seq, stream, chunk) VALUES ($1, 0, 'info', $2)`,
				jobID, fmt.Sprintf("\n[output truncated at %d MB]\n", MaxJobOutput>>20)); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `UPDATE job SET output_bytes = $2 WHERE id = $1`, jobID, MaxJobOutput+1)
			return err
		}
		res, err := tx.ExecContext(ctx, `
			INSERT INTO job_output (job_id, seq, stream, chunk) VALUES ($1, $2, $3, $4)
			ON CONFLICT (job_id, seq) WHERE seq > 0 DO NOTHING`, jobID, seq, stream, chunk)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		stored = true
		_, err = tx.ExecContext(ctx, `UPDATE job SET output_bytes = output_bytes + $2 WHERE id = $1`, jobID, len(chunk))
		return err
	})
	return stored, err
}

// cleanText makes agent output storable as Postgres text.
func cleanText(s string) string {
	return strings.ReplaceAll(strings.ToValidUTF8(s, "�"), "\x00", "")
}

// JobResult is how a job ended, as the agent reported it.
type JobResult struct {
	State    string // succeeded | failed | cancelled | timed_out | rejected | rebooting
	ExitCode *int
	Result   []byte // JSON
	Error    string
}

// FinishJob records a job's result. A result for a job that already ended
// (an agent resending after a reconnect) is ignored; ok is false then.
// "rebooting" keeps the job running until the host is back.
func (s *Store) FinishJob(ctx context.Context, actor Actor, hostID, jobID string, r JobResult) (ok bool, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var changeID string
		if err := tx.QueryRowContext(ctx, `SELECT change_id FROM job WHERE id::text = $1 AND host = $2`, jobID, hostID).
			Scan(&changeID); err != nil {
			return mapErr(err)
		}
		// Lock order: change, then its jobs, then the audit chain.
		if _, err := tx.ExecContext(ctx, `SELECT 1 FROM change WHERE id = $1 FOR UPDATE`, changeID); err != nil {
			return err
		}
		ok, err = finishJob(ctx, tx, actor, jobID, r)
		return err
	})
	return ok, err
}

func finishJob(ctx context.Context, tx *sql.Tx, actor Actor, jobID string, r JobResult) (bool, error) {
	var result sql.NullString
	if len(r.Result) > 0 && json.Valid(r.Result) {
		result = sql.NullString{String: cleanText(string(r.Result)), Valid: true}
	}
	var exit sql.NullInt64
	if r.ExitCode != nil {
		exit = sql.NullInt64{Int64: int64(*r.ExitCode), Valid: true}
	}
	errMsg := cleanText(r.Error)
	if len(errMsg) > 2000 {
		errMsg = errMsg[:2000] + "…"
	}
	if r.State == JobRebooting {
		_, err := tx.ExecContext(ctx, `
			UPDATE job SET state = 'running', awaiting_reboot = true, started_at = COALESCE(started_at, now()),
			       result = COALESCE($2, result), exit_code = $3
			WHERE id::text = $1 AND state IN ('queued', 'dispatched', 'running')`, jobID, result, exit)
		return false, err
	}
	switch r.State {
	case JobSucceeded, JobFailed, JobCancelled, JobTimedOut, JobRejected, JobRolledBack:
	default:
		return false, fmt.Errorf("unknown job state %q", r.State)
	}
	var changeID, hostname, act, stopped string
	var number int64
	var stop bool
	err := tx.QueryRowContext(ctx, `
		UPDATE job j SET state = $2, exit_code = $3, result = COALESCE($4, j.result), error = $5,
		       started_at = COALESCE(j.started_at, now()), finished_at = now()
		FROM change c, host h
		WHERE j.id::text = $1 AND c.id = j.change_id AND h.ci_id = j.host AND j.state IN ('queued', 'dispatched', 'running')
		RETURNING j.change_id, c.number, h.hostname, j.action, c.stop_on_failure, c.state`,
		jobID, r.State, exit, result, errMsg).Scan(&changeID, &number, &hostname, &act, &stop, &stopped)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	details := map[string]any{"change": ChangeRef(number), "host": hostname, "action": act, "state": r.State}
	if r.ExitCode != nil {
		details["exit_code"] = *r.ExitCode
	}
	if errMsg != "" {
		details["error"] = errMsg
	}
	if err := appendAudit(ctx, tx, actor, AuditEvent{Action: "job.result", ObjectType: "job", ObjectID: jobID, Details: details}); err != nil {
		return false, err
	}
	if r.State != JobSucceeded && stop && stopped == ChangeInProgress {
		if _, err := tx.ExecContext(ctx, `
			UPDATE job SET state = 'cancelled', finished_at = now(), error = 'skipped: an earlier job in this change failed'
			WHERE change_id = $1 AND state = 'queued'`, changeID); err != nil {
			return false, err
		}
	}
	return true, completeChange(ctx, tx, changeID)
}

// completeChange ends a change in progress once none of its jobs is left
// to run. When every job succeeded, a Standard change closes, an Emergency
// one waits for its review and a Normal one is implemented (closing it is
// up to its people). Otherwise it failed, or was rolled back when every job
// that didn't succeed was; both need a review.
func completeChange(ctx context.Context, tx *sql.Tx, changeID string) error {
	var state, kind string
	var number int64
	var total, ok, open, rolled int
	if err := tx.QueryRowContext(ctx, `
		SELECT c.state, c.kind, c.number, count(j.id), count(j.id) FILTER (WHERE j.state = 'succeeded'),
		       count(j.id) FILTER (WHERE j.state IN ('queued', 'dispatched', 'running')),
		       count(j.id) FILTER (WHERE j.state = 'rolled_back')
		FROM change c LEFT JOIN job j ON j.change_id = c.id WHERE c.id = $1 GROUP BY c.id`, changeID).
		Scan(&state, &kind, &number, &total, &ok, &open, &rolled); err != nil {
		return err
	}
	if state != ChangeInProgress || open > 0 {
		return nil
	}
	to, outcome := ChangeImplemented, "success"
	switch {
	case ok == total:
		switch kind {
		case KindStandard:
			to = ChangeClosed
		case KindEmergency:
			to = ChangeReview
		}
	case rolled > 0 && ok+rolled == total:
		to, outcome = ChangeRolledBack, "rolled_back"
	case ok == 0:
		to, outcome = ChangeFailed, "failed"
	default:
		to, outcome = ChangeFailed, "partial"
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE change SET state = $2, outcome = $3, actual_end = now(), window_ends_at = NULL,
		       closed_at = CASE WHEN $2 = 'closed' THEN now() END, updated_at = now() WHERE id = $1`,
		changeID, to, outcome); err != nil {
		return err
	}
	return appendAudit(ctx, tx, System, AuditEvent{Action: "change.state", ObjectType: "change", ObjectID: changeID,
		Details: map[string]any{"number": ChangeRef(number), "from": state, "to": to, "outcome": outcome,
			"jobs": total, "succeeded": ok}})
}

// ExpireJobs ends jobs the server has given up on: sent jobs with no result
// well past their timeout (it returns those, so the caller can ask their
// agents to stop them), and queued jobs whose host has been offline for an
// hour or was revoked.
func (s *Store) ExpireJobs(ctx context.Context) ([]JobRef, error) {
	var late []JobRef
	err := s.tx(ctx, func(tx *sql.Tx) error {
		type expired struct {
			JobRef
			changeID, msg, state string
		}
		var list []expired
		rows, err := tx.QueryContext(ctx, `
			SELECT j.id, j.host, h.agent_id, j.change_id, j.state, j.awaiting_reboot FROM job j JOIN host h ON h.ci_id = j.host
			WHERE j.state IN ('dispatched', 'running')
			  AND COALESCE(j.started_at, j.dispatched_at) + make_interval(secs => j.timeout_s) + $1 * interval '1 second' < now()`,
			jobGrace.Seconds())
		if err != nil {
			return err
		}
		for rows.Next() {
			var e expired
			var reboot bool
			if err := rows.Scan(&e.ID, &e.HostID, &e.AgentID, &e.changeID, &e.state, &reboot); err != nil {
				rows.Close()
				return err
			}
			e.state, e.msg = JobTimedOut, "no result from the agent within the job's timeout"
			if reboot {
				e.state, e.msg = JobFailed, "the host didn't come back after rebooting"
			}
			list = append(list, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		n := len(list)
		rows, err = tx.QueryContext(ctx, `
			SELECT j.id, j.host, h.agent_id, j.change_id, h.revoked FROM job j JOIN host h ON h.ci_id = j.host
			JOIN change c ON c.id = j.change_id
			WHERE j.state = 'queued' AND c.state = 'in_progress'
			  AND (h.revoked OR (NOT h.connected AND COALESCE(h.last_seen, 'epoch') < now() - $1 * interval '1 second'
			                     AND c.actual_start < now() - $1 * interval '1 second'))`, offlineLimit.Seconds())
		if err != nil {
			return err
		}
		for rows.Next() {
			var e expired
			var revoked bool
			if err := rows.Scan(&e.ID, &e.HostID, &e.AgentID, &e.changeID, &revoked); err != nil {
				rows.Close()
				return err
			}
			e.state, e.msg = JobFailed, "the host was offline for an hour, so the job never started"
			if revoked {
				e.msg = "the host was revoked"
			}
			list = append(list, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for i, e := range list {
			if _, err := tx.ExecContext(ctx, `SELECT 1 FROM change WHERE id = $1 FOR UPDATE`, e.changeID); err != nil {
				return err
			}
			done, err := finishJob(ctx, tx, System, e.ID, JobResult{State: e.state, Error: e.msg})
			if err != nil {
				return err
			}
			if done && i < n {
				late = append(late, e.JobRef)
			}
		}
		return nil
	})
	return late, err
}

// jobChange is the change behind an inventory section: the job the agent
// says it collected the section for, or else a job on the host that could
// have changed it and is running now, or rebooted the host minutes ago.
func jobChange(ctx context.Context, tx *sql.Tx, hostID, jobID, section string) (sql.NullString, error) {
	var id sql.NullString
	var err error
	if jobID != "" {
		err = tx.QueryRowContext(ctx, `SELECT change_id FROM job WHERE id::text = $1 AND host = $2`, jobID, hostID).Scan(&id)
	} else {
		err = tx.QueryRowContext(ctx, `
			SELECT change_id FROM job WHERE host = $1 AND action = ANY($2)
			  AND (state IN ('dispatched', 'running') OR (awaiting_reboot AND finished_at > now() - interval '`+rebootWindowSQL+`'))
			ORDER BY finished_at DESC NULLS FIRST LIMIT 1`, hostID, pq.Array(nonNil(action.Affecting(section)))).Scan(&id)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return sql.NullString{}, nil
	}
	return id, err
}

// JobCounts summarizes jobs for a host's overview.
func (s *Store) HostJobCounts(ctx context.Context, hostID string) (open int, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM job WHERE host = $1 AND state IN ('queued', 'dispatched', 'running')`, hostID).Scan(&open)
	return open, err
}
