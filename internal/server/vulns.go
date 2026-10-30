package server

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/vuln"
)

// VulnSyncer keeps OSV data current (internal/vuln).
type VulnSyncer interface{ Trigger() }

// SetVulns lets admins ask for a sync now.
func (s *Server) SetVulns(v VulnSyncer) { s.vulns = v }

func (s *Server) vulnRoutes(mux *http.ServeMux) {
	mux.Handle("GET /vulnerabilities", s.page(anyRole, s.vulnList))
	mux.Handle("POST /vulnerabilities/sync", s.page(adminOnly, s.vulnSync))
	mux.Handle("GET /vulnerabilities/{id}", s.page(anyRole, s.vulnPage))
}

// vulnFilterForm is the filter bar both views share.
type vulnFilterForm struct {
	View        string // vulns | hosts
	Fixable     bool
	MinSeverity string
	Query       string
}

func (f vulnFilterForm) query() string {
	q := url.Values{}
	if f.View != "vulns" {
		q.Set("view", f.View)
	}
	if !f.Fixable {
		q.Set("fixable", "0")
	}
	if f.MinSeverity != "" {
		q.Set("severity", f.MinSeverity)
	}
	if f.Query != "" {
		q.Set("q", f.Query)
	}
	return q.Encode()
}

func readVulnFilter(r *http.Request) vulnFilterForm {
	q := r.URL.Query()
	f := vulnFilterForm{View: q.Get("view"), Fixable: q.Get("fixable") != "0", MinSeverity: q.Get("severity"),
		Query: strings.TrimSpace(q.Get("q"))}
	if f.View != "hosts" {
		f.View = "vulns"
	}
	if !slices.Contains(vuln.Severities, f.MinSeverity) {
		f.MinSeverity = ""
	}
	return f
}

type vulnHostRow struct {
	Host    store.Host
	Counts  store.VulnCounts
	Covered bool
}

type vulnListView struct {
	Filter vulnFilterForm
	// The two views' URLs, keeping the filter.
	VulnsQuery, HostsQuery string
	Severities             []string
	Vulns                  []store.VulnRow
	Limited                bool
	Hosts                  []vulnHostRow
	Sources                []store.VulnSource
	// Uncovered are hosts whose distro OSV doesn't cover.
	Uncovered []store.Host
	Pending   []store.Host // not matched yet
	IsAdmin   bool
	SyncOff   bool
	Notice    string
}

const vulnLimit = 500

func (s *Server) vulnList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hosts, err := s.visibleHosts(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v := vulnListView{Filter: readVulnFilter(r), Severities: vuln.Severities[1:], IsAdmin: principal(r).Grants.Has(rbac.Admin),
		SyncOff: s.vulns == nil, Notice: r.URL.Query().Get("notice")}
	byVuln, byHost := v.Filter, v.Filter
	byVuln.View, byHost.View = "vulns", "hosts"
	v.VulnsQuery, v.HostsQuery = byVuln.query(), byHost.query()
	var ids []string
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		ids = append(ids, h.ID)
		switch {
		case h.VulnsAt.IsZero():
			v.Pending = append(v.Pending, h)
		case h.VulnEcosystem == "":
			v.Uncovered = append(v.Uncovered, h)
		}
	}
	if v.Sources, err = s.store.VulnSources(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	f := store.VulnFilter{HostIDs: ids, FixableOnly: v.Filter.Fixable, MinSeverity: v.Filter.MinSeverity, Query: v.Filter.Query}
	if v.Filter.View == "hosts" {
		counts, err := s.store.HostVulnCounts(ctx, ids)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, h := range hosts {
			if !h.Revoked && h.VulnEcosystem != "" {
				v.Hosts = append(v.Hosts, vulnHostRow{Host: h, Counts: counts[h.ID], Covered: true})
			}
		}
		slices.SortStableFunc(v.Hosts, func(a, b vulnHostRow) int {
			for _, d := range [][2]int{{a.Counts.Critical, b.Counts.Critical}, {a.Counts.High, b.Counts.High},
				{a.Counts.Fixable, b.Counts.Fixable}, {a.Counts.Total, b.Counts.Total}} {
				if d[0] != d[1] {
					return d[1] - d[0]
				}
			}
			return 0
		})
	} else {
		f.Limit = vulnLimit + 1
		if v.Vulns, err = s.store.ListVulns(ctx, f); err != nil {
			s.serverError(w, r, err)
			return
		}
		if len(v.Vulns) > vulnLimit {
			v.Vulns, v.Limited = v.Vulns[:vulnLimit], true
		}
	}
	s.pages.render(w, http.StatusOK, "vulnerabilities", s.data(r, "Vulnerabilities", v))
}

func (s *Server) vulnSync(w http.ResponseWriter, r *http.Request) {
	msg := "Syncing OSV data now. Large ecosystems (Ubuntu) take a few minutes the first time."
	if s.vulns == nil {
		msg = "Syncing is turned off (BASELINE_OSV_URL=off)."
	} else {
		s.vulns.Trigger()
		s.store.Audit(r.Context(), s.actor(r), store.AuditEvent{Action: "vuln.sync"})
	}
	http.Redirect(w, r, s.url("/vulnerabilities?notice="+url.QueryEscape(msg)), http.StatusSeeOther)
}

type vulnPageView struct {
	Vuln     store.Vuln
	Affected []store.VulnAffected
	Matches  []store.HostVuln
	Fixable  int
	Hosts    int
}

func (s *Server) vulnPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vl, aff, err := s.store.GetVuln(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "No such vulnerability, or no enrolled host's distro has it.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	hosts, err := s.visibleHosts(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var ids []string
	for _, h := range hosts {
		ids = append(ids, h.ID)
	}
	matches, err := s.store.HostVulns(ctx, store.VulnFilter{HostIDs: ids, Query: vl.ID})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v := vulnPageView{Vuln: vl, Affected: aff}
	seen := map[string]bool{}
	for _, m := range matches {
		if m.VulnID != vl.ID {
			continue // the query also matches longer IDs
		}
		v.Matches = append(v.Matches, m)
		if !seen[m.HostID] {
			seen[m.HostID] = true
			v.Hosts++
		}
	}
	fixable := map[string]bool{}
	for _, m := range v.Matches {
		if m.FixAvailable {
			fixable[m.HostID] = true
		}
	}
	v.Fixable = len(fixable)
	s.pages.render(w, http.StatusOK, "vulnerability", s.data(r, vl.ID, v))
}
