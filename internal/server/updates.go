package server

import (
	"net/http"
)

type updatesView struct {
	Tab  string // hosts | packages
	List *listView

	HostCount        int
	HostsWithUpdates int
	Total            int
	Security         int
	Unchecked        int // hosts that never reported updates
}

// updates is the fleet view of pending updates by host.
func (s *Server) updates(w http.ResponseWriter, r *http.Request) {
	if q := r.URL.Query(); q.Get("view") == "packages" {
		q.Del("view")
		http.Redirect(w, r, s.url("/updates/packages?"+q.Encode()), http.StatusSeeOther)
		return
	}
	s.updateList(w, r, "update")
}

// packageUpdates is the same by package.
func (s *Server) packageUpdates(w http.ResponseWriter, r *http.Request) {
	s.updateList(w, r, "package")
}

func (s *Server) updateList(w http.ResponseWriter, r *http.Request, table string) {
	l, ok := s.buildList(w, r, table)
	if !ok {
		return
	}
	v := updatesView{Tab: "hosts", List: l}
	if table == "package" {
		v.Tab = "packages"
	}
	if !isHTMX(r) {
		hosts, err := s.visibleHosts(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, h := range hosts {
			if h.Revoked {
				continue
			}
			v.HostCount++
			v.Total += h.Updates
			v.Security += h.SecurityUpdates
			if h.Updates > 0 {
				v.HostsWithUpdates++
			}
			if h.UpdatesAt.IsZero() {
				v.Unchecked++
			}
		}
	}
	s.renderList(w, r, "updates", "Updates", v, l)
}
