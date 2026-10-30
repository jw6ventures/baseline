package server

import (
	"net/http"
	"net/url"
	"slices"

	"github.com/jw6ventures/baseline/internal/store"
)

type agentsView struct {
	Releases []store.ReleaseVersion
	Latest   string
	Hosts    []store.Host
	Outdated int
	Pending  int
	Refusing int // hosts whose agent.conf has self_update = off
	Error    string
	Notice   string
}

// agentSettings lists published agent releases and the version each host
// runs, with a way to move the fleet to a release (Settings → Agents).
func (s *Server) agentSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := agentsView{Error: r.URL.Query().Get("error"), Notice: r.URL.Query().Get("notice")}
	var err error
	if v.Releases, err = s.store.ListReleases(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(v.Releases) > 0 {
		v.Latest = v.Releases[0].Version
	}
	hosts, err := s.store.ListHosts(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		v.Hosts = append(v.Hosts, h)
		if h.AgentVersion != "" && h.AgentVersion != v.Latest {
			v.Outdated++
		}
		if h.AgentUpdateTarget != "" {
			v.Pending++
		}
		if h.Policy.SelfUpdateOff {
			v.Refusing++
		}
	}
	s.pages.render(w, http.StatusOK, "agents", s.data(r, "Agents", v))
}

func (s *Server) backToAgents(w http.ResponseWriter, r *http.Request, kind, msg string) {
	http.Redirect(w, r, s.url("/settings/agents?"+kind+"="+url.QueryEscape(msg)), http.StatusSeeOther)
}

// agentsUpdate asks every host not on a version to move to it. Agents that
// are offline get it when they next connect.
func (s *Server) agentsUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	version := r.FormValue("version")
	rels, err := s.store.ListReleases(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !slices.ContainsFunc(rels, func(rv store.ReleaseVersion) bool { return rv.Version == version }) {
		s.backToAgents(w, r, "error", "Pick a published version.")
		return
	}
	hosts, err := s.store.ListHosts(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var ids []string
	for _, h := range hosts {
		ids = append(ids, h.ID)
	}
	changed, err := s.store.RequestAgentUpdate(ctx, s.actor(r), ids, version)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sent := 0
	for _, h := range changed {
		if s.hub != nil && s.hub.UpdateAgent(h.AgentID) {
			sent++
		}
	}
	switch {
	case len(changed) == 0:
		s.backToAgents(w, r, "notice", "Every agent that can run "+version+" already does.")
	default:
		s.backToAgents(w, r, "notice", plural(len(changed), "agent")+" will update to "+version+": "+
			plural(sent, "is", "are")+" connected and update now; the rest update when they next connect.")
	}
}
