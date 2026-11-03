package server

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/vuln"
)

// Changes ----------------------------------------------------------------------

// listChangesJSON lists changes matching f that affect only hosts the
// user can see, as the Changes page does. The query's show, state and
// limit narrow it further.
func (s *Server) listChangesJSON(r *http.Request, f store.ChangeFilter) ([]changeJSON, error) {
	q := r.URL.Query()
	if show := q.Get("show"); show != "" {
		states, ok := changeFilters[show]
		if !ok {
			return nil, failf(http.StatusBadRequest, "show must be one of open, approval, scheduled, review, all")
		}
		f.States = states
	}
	if st := q.Get("state"); st != "" {
		f.States = strings.Split(st, ",")
	}
	f.Limit = queryInt(r, "limit", 300, 2000)
	hosts, err := s.hostIndex(r)
	if err != nil {
		return nil, err
	}
	all, err := s.store.ListChanges(r.Context(), f)
	if err != nil {
		return nil, err
	}
	g := principal(r).Grants
	out := make([]changeJSON, 0, len(all))
	for _, c := range all {
		if canOnAll(g, rbac.Viewer, c.HostIDs, hosts) {
			out = append(out, changeToJSON(c))
		}
	}
	return out, nil
}

func (s *Server) apiChanges(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	changes, err := s.listChangesJSON(r, store.ChangeFilter{HostID: q.Get("host"), ModelID: q.Get("model"), CIID: q.Get("ci")})
	s.respond(w, r, changes, err)
}

// apiLoadChange fetches a change the user may see: one affecting only
// hosts they can view.
func (s *Server) apiLoadChange(r *http.Request, id string) (store.Change, map[string]store.Host, error) {
	c, err := s.store.GetChange(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return c, nil, errAPINotFound
	}
	if err != nil {
		return c, nil, err
	}
	hosts, err := s.hostIndex(r)
	if err != nil {
		return c, nil, err
	}
	if !canOnAll(principal(r).Grants, rbac.Viewer, c.HostIDs, hosts) {
		return c, nil, errAPINotFound
	}
	return c, hosts, nil
}

func (s *Server) changeDetail(r *http.Request, c store.Change) (any, error) {
	ctx := r.Context()
	var out struct {
		changeJSON
		Approvals []approvalJSON  `json:"approvals"`
		Jobs      []jobJSON       `json:"jobs"`
		Cycle     *patchCycleJSON `json:"patch_cycle,omitempty"`
		// Revisions are the files a compose.deploy or compose.edit writes.
		Revisions []stackRevisionJSON `json:"stack_revisions,omitempty"`
		// WorkItems are the work items linked to it, and how.
		WorkItems []linkedItemJSON `json:"work_items"`
	}
	out.changeJSON = changeToJSON(c)
	approvals, err := s.store.ChangeApprovals(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	out.Approvals = make([]approvalJSON, 0, len(approvals))
	for _, a := range approvals {
		out.Approvals = append(out.Approvals, approvalJSON{Approver: a.Approver, ApproverName: a.ApproverName,
			Decision: a.Decision, Comment: a.Comment, SelfApproved: a.SelfApproved, At: a.At})
	}
	jobs, err := s.store.ListJobs(ctx, store.JobFilter{ChangeID: c.ID, Limit: 1000})
	if err != nil {
		return nil, err
	}
	out.Jobs = jobsToJSON(jobs)
	cycle, err := s.store.ChangeCycle(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	if cycle != nil {
		cj := patchCycleToJSON(*cycle)
		out.Cycle = &cj
	}
	revs, err := s.store.ChangeRevisions(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	for _, rev := range revs {
		out.Revisions = append(out.Revisions, stackRevisionToJSON(rev))
	}
	if out.WorkItems, err = s.changeWorkItems(r, c.ID); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Server) apiChange(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.apiLoadChange(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	out, err := s.changeDetail(r, c)
	s.respond(w, r, out, err)
}

// apiChangeSubmit submits a draft for approval. Only its requester may,
// and the API never approves: that stays with approvers in the UI.
func (s *Server) apiChangeSubmit(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.apiLoadChange(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	switch {
	case c.State != store.ChangeDraft:
		apiError(w, http.StatusConflict, "only a draft can be submitted; this change is "+c.State)
		return
	case c.RequestedBy != principal(r).User.ID:
		apiError(w, http.StatusForbidden, "only the requester submits a draft")
		return
	}
	err = s.store.SubmitChange(r.Context(), s.actor(r), c.ID)
	if errors.Is(err, store.ErrState) {
		apiError(w, http.StatusConflict, "only its requester submits a draft")
		return
	}
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	c, err = s.store.GetChange(r.Context(), c.ID)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	out, err := s.changeDetail(r, c)
	s.respond(w, r, out, err)
}

func (s *Server) apiChangeModels(w http.ResponseWriter, r *http.Request) {
	ms, err := s.store.ListChangeModels(r.Context(), r.URL.Query().Get("action"))
	out := make([]changeModelJSON, 0, len(ms))
	for _, m := range ms {
		if st := r.URL.Query().Get("state"); st != "" && m.State != st {
			continue
		}
		out = append(out, changeModelToJSON(m))
	}
	s.respond(w, r, out, err)
}

func (s *Server) apiChangeModel(w http.ResponseWriter, r *http.Request) {
	m, err := s.store.GetChangeModel(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		err = errAPINotFound
	}
	s.respond(w, r, changeModelToJSON(m), err)
}

// Jobs --------------------------------------------------------------------------

func (s *Server) apiJobs(w http.ResponseWriter, r *http.Request) {
	visible, _, err := s.apiVisibleIDs(r)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	q := r.URL.Query()
	states, ok := jobFilters[q.Get("show")]
	if !ok && q.Get("show") != "" {
		apiError(w, http.StatusBadRequest, "show must be one of open, failed, all")
		return
	}
	if st := q.Get("state"); st != "" {
		states = strings.Split(st, ",")
	}
	all, err := s.store.ListJobs(r.Context(), store.JobFilter{ChangeID: q.Get("change"), HostID: q.Get("host"), States: states,
		Limit: queryInt(r, "limit", 500, 5000)})
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	all = slices.DeleteFunc(all, func(j store.Job) bool { return !visible[j.HostID] })
	writeJSON(w, http.StatusOK, jobsToJSON(all))
}

func (s *Server) apiLoadJob(r *http.Request, id string) (store.Job, error) {
	j, err := s.store.GetJob(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return j, errAPINotFound
	}
	if err != nil {
		return j, err
	}
	if _, err := s.apiLoadHost(r, j.HostID, rbac.Viewer); err != nil {
		return j, errAPINotFound
	}
	return j, nil
}

func (s *Server) apiJob(w http.ResponseWriter, r *http.Request) {
	j, err := s.apiLoadJob(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, jobToJSON(j))
}

// apiJobOutput pages through a job's output: pass the last chunk's id as
// after to get what followed. The job page's live stream is /jobs/{id}/events.
func (s *Server) apiJobOutput(w http.ResponseWriter, r *http.Request) {
	j, err := s.apiLoadJob(r, r.PathValue("id"))
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	chunks, err := s.store.JobOutput(r.Context(), j.ID, after, queryInt(r, "limit", 1000, 5000))
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	var out struct {
		State  string            `json:"state"`
		Final  bool              `json:"final"`
		Chunks []outputChunkJSON `json:"chunks"`
		LastID int64             `json:"last_id"`
	}
	out.State, out.Final, out.Chunks, out.LastID = j.State, j.Final(), []outputChunkJSON{}, after
	for _, c := range chunks {
		out.Chunks = append(out.Chunks, outputChunkJSON{ID: c.ID, Seq: c.Seq, Stream: c.Stream, At: c.At, Chunk: c.Chunk})
		out.LastID = c.ID
	}
	writeJSON(w, http.StatusOK, out)
}

// Scripts ------------------------------------------------------------------------

func (s *Server) apiScripts(w http.ResponseWriter, r *http.Request) {
	scripts, err := s.store.ListScripts(r.Context())
	out := make([]scriptJSON, 0, len(scripts))
	for _, sc := range scripts {
		if sc.Archived && !queryBool(r, "archived") {
			continue
		}
		out = append(out, scriptToJSON(sc))
	}
	s.respond(w, r, out, err)
}

func (s *Server) apiScript(w http.ResponseWriter, r *http.Request) {
	sc, err := s.store.GetScript(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		err = errAPINotFound
	}
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	versions, err := s.store.ScriptVersions(r.Context(), sc.ID)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	var out struct {
		scriptJSON
		Versions []scriptVersionJSON `json:"versions"`
	}
	out.scriptJSON, out.Versions = scriptToJSON(sc), make([]scriptVersionJSON, 0, len(versions))
	for _, v := range versions {
		out.Versions = append(out.Versions, scriptVersionToJSON(v, false))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiScriptVersion(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || n < 1 {
		apiError(w, http.StatusNotFound, "the version is a number from 1")
		return
	}
	v, err := s.store.GetScriptVersion(r.Context(), r.PathValue("id"), n)
	if errors.Is(err, store.ErrNotFound) {
		err = errAPINotFound
	}
	s.respond(w, r, scriptVersionToJSON(v, true), err)
}

// Windows, calendar, patch groups ------------------------------------------------

func (s *Server) apiWindows(w http.ResponseWriter, r *http.Request) {
	ws, err := s.store.ListWindows(r.Context())
	out := make([]windowJSON, 0, len(ws))
	for _, mw := range ws {
		if k := r.URL.Query().Get("kind"); k != "" && mw.Kind != k {
			continue
		}
		out = append(out, windowToJSON(mw))
	}
	s.respond(w, r, out, err)
}

// apiCalendar lists window and freeze openings and planned changes
// between from and to (RFC 3339 or YYYY-MM-DD; the next 30 days by default).
func (s *Server) apiCalendar(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	from, to := now, now.Add(30*24*time.Hour)
	var err error
	if v := r.URL.Query().Get("from"); v != "" {
		if from, err = parseAPITime(v, s.cfg.Location); err != nil {
			apiError(w, http.StatusBadRequest, "from: "+err.Error())
			return
		}
		to = from.Add(30 * 24 * time.Hour)
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if to, err = parseAPITime(v, s.cfg.Location); err != nil {
			apiError(w, http.StatusBadRequest, "to: "+err.Error())
			return
		}
	}
	if !to.After(from) || to.Sub(from) > 366*24*time.Hour {
		apiError(w, http.StatusBadRequest, "to must be after from, at most a year later")
		return
	}
	items, err := s.calendarItems(r.Context(), principal(r).Grants, from, to, now)
	out := make([]calendarItemJSON, 0, len(items))
	for _, it := range items {
		out = append(out, calendarItemJSON{Kind: it.Kind, Name: it.Name, Detail: it.Detail, Start: it.Start, End: ts(it.End)})
	}
	s.respond(w, r, out, err)
}

func parseAPITime(v string, loc *time.Location) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if t, err := time.ParseInLocation("2006-01-02", v, loc); err == nil {
		return t, nil
	}
	return time.Time{}, errors.New("not an RFC 3339 time or a YYYY-MM-DD date")
}

func (s *Server) apiPatchGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListPatchGroups(r.Context())
	out := make([]patchGroupJSON, 0, len(groups))
	for _, g := range groups {
		out = append(out, patchGroupToJSON(g))
	}
	s.respond(w, r, out, err)
}

func (s *Server) apiPatchGroup(w http.ResponseWriter, r *http.Request) {
	pg, err := s.store.GetPatchGroup(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		err = errAPINotFound
	}
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	cycles, err := s.store.ListPatchCycles(r.Context(), pg.ID, queryInt(r, "limit", 50, 500))
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	var out struct {
		patchGroupJSON
		Cycles []patchCycleJSON `json:"cycles"`
	}
	out.patchGroupJSON, out.Cycles = patchGroupToJSON(pg), make([]patchCycleJSON, 0, len(cycles))
	for _, c := range cycles {
		out.Cycles = append(out.Cycles, patchCycleToJSON(c))
	}
	writeJSON(w, http.StatusOK, out)
}

// Vulnerabilities -------------------------------------------------------------------

// vulnFilterFrom reads the query's fixable, severity and q into a filter
// over hostIDs.
func vulnFilterFrom(r *http.Request, hostIDs []string) store.VulnFilter {
	q := r.URL.Query()
	f := store.VulnFilter{HostIDs: hostIDs, FixableOnly: queryBool(r, "fixable"), MinSeverity: q.Get("severity"),
		Query: strings.TrimSpace(q.Get("q"))}
	if !slices.Contains(vuln.Severities, f.MinSeverity) {
		f.MinSeverity = ""
	}
	return f
}

func (s *Server) apiVulns(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.visibleHosts(r)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	var ids []string
	for _, h := range hosts {
		if !h.Revoked {
			ids = append(ids, h.ID)
		}
	}
	f := vulnFilterFrom(r, ids)
	f.Limit = queryInt(r, "limit", 500, 5000)
	rows, err := s.store.ListVulns(r.Context(), f)
	out := make([]vulnRowJSON, 0, len(rows))
	for _, v := range rows {
		out = append(out, vulnRowJSON{ID: v.ID, Aliases: strs(v.Aliases), Summary: v.Summary, Severity: v.Severity,
			CVSSScore: v.CVSSScore, Published: ts(v.Published), Hosts: v.Hosts, FixableHosts: v.FixableHosts,
			Packages: strs(v.Packages), FirstSeen: ts(v.FirstSeen)})
	}
	s.respond(w, r, out, err)
}

func (s *Server) apiVuln(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vl, aff, err := s.store.GetVuln(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		err = errAPINotFound
	}
	if err != nil {
		s.respond(w, r, nil, err)
		return
	}
	_, ids, err := s.apiVisibleIDs(r)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	matches, err := s.store.HostVulns(ctx, store.VulnFilter{HostIDs: ids, Query: vl.ID})
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	matches = slices.DeleteFunc(matches, func(m store.HostVuln) bool { return m.VulnID != vl.ID }) // the query also matches longer IDs
	out := vulnJSON{ID: vl.ID, Aliases: strs(vl.Aliases), Summary: vl.Summary, Details: vl.Details, Severity: vl.Severity,
		CVSSScore: vl.CVSSScore, CVSSVector: vl.CVSSVector, Published: ts(vl.Published), Modified: ts(vl.Modified),
		Refs: vl.Refs, Affected: make([]vulnAffectedJSON, 0, len(aff)), Matches: hostVulnsToJSON(matches)}
	if out.Refs == nil {
		out.Refs = []store.VulnRef{}
	}
	for _, a := range aff {
		out.Affected = append(out.Affected, vulnAffectedJSON{Ecosystem: a.Ecosystem, Package: a.Package, Severity: a.Severity,
			Ranges: raw(a.Ranges), Binaries: a.Binaries})
	}
	seen, fixable := map[string]bool{}, map[string]bool{}
	for _, m := range matches {
		seen[m.HostID] = true
		if m.FixAvailable {
			fixable[m.HostID] = true
		}
	}
	out.Hosts, out.Fixable = len(seen), len(fixable)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiVulnSources(w http.ResponseWriter, r *http.Request) {
	srcs, err := s.store.VulnSources(r.Context())
	out := make([]vulnSourceJSON, 0, len(srcs))
	for _, v := range srcs {
		out = append(out, vulnSourceJSON{Ecosystem: v.Ecosystem, Dump: v.Dump, Cursor: ts(v.Cursor), FullAt: ts(v.FullAt),
			SyncedAt: ts(v.SyncedAt), TriedAt: ts(v.TriedAt), Error: v.Error, Vulns: v.Vulns})
	}
	s.respond(w, r, out, err)
}

// Alerts ---------------------------------------------------------------------------

func (s *Server) apiAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AlertFilter{Open: true, RuleID: q.Get("rule"), CIID: q.Get("ci"), Limit: queryInt(r, "limit", 500, 5000)}
	if queryBool(r, "history") {
		f.Open = false
		f.Resolved = time.Now().Add(-time.Duration(queryInt(r, "days", 7, 90)) * 24 * time.Hour)
	}
	alerts, err := s.store.ListAlerts(r.Context(), f)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	out := make([]alertJSON, 0, len(alerts))
	for _, a := range alerts {
		if canSee(r, a.GroupIDs) {
			out = append(out, alertToJSON(a))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiAlert(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetAlert(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || err == nil && !canSee(r, a.GroupIDs) {
		err = errAPINotFound
	}
	s.respond(w, r, alertToJSON(a), err)
}

func (s *Server) apiAlertRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListAlertRules(r.Context())
	out := make([]alertRuleJSON, 0, len(rules))
	for _, rl := range rules {
		out = append(out, alertRuleToJSON(rl))
	}
	s.respond(w, r, out, err)
}

func (s *Server) apiSilences(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	since := time.Now().Add(-time.Duration(queryInt(r, "days", 1, 365)) * 24 * time.Hour)
	sils, err := s.store.ListSilences(ctx, since)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	hosts, err := s.visibleHosts(r)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	groupsOf := map[string][]string{}
	for _, h := range hosts {
		groupsOf[h.ID] = h.GroupIDs
	}
	out := make([]silenceJSON, 0, len(sils))
	for _, sl := range sils {
		if _, ok := s.silenceAccess(r, sl, groupsOf); ok {
			out = append(out, silenceToJSON(sl))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// Audit ----------------------------------------------------------------------------

func (s *Server) apiAudit(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	entries, err := s.store.ListAudit(r.Context(), before, queryInt(r, "limit", auditPageSize, 1000))
	out := make([]auditJSON, 0, len(entries))
	for _, e := range entries {
		out = append(out, auditToJSON(e))
	}
	s.respond(w, r, out, err)
}
