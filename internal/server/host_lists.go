package server

import (
	"net/http"
	"slices"
	"strings"

	"github.com/jw6ventures/baseline/internal/list"
)

// A host's related lists: the tabs of its page that show a list engine
// table, scoped to the host. Each lives at /hosts/{id}/{tab}, since a list
// page's links are its path plus the list's query.

type hostRelated struct {
	Table string // the list engine table
	Host  string // SQL of a row's host
}

var hostLists = map[string]hostRelated{
	"containers": {Table: "container", Host: "c.host"},
	"stacks":     {Table: "stack", Host: "s.host"},
	"vms":        {Table: "vm", Host: "g.host"},
	"jobs":       {Table: "job", Host: "j.host"},
}

// hostListPath reports whether path is a host's related list of the
// table, /hosts/{id}/containers, so a form posted from it may return there.
func hostListPath(table, path string) bool {
	rest, ok := strings.CutPrefix(path, "/hosts/")
	if !ok {
		return false
	}
	id, tab, ok := strings.Cut(rest, "/")
	if !ok || !validUUID(id) {
		return false
	}
	l, ok := hostLists[tab]
	return ok && l.Table == table
}

// validUUID reports whether s looks like a CI id.
func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case !strings.ContainsRune("0123456789abcdefABCDEF", c):
			return false
		}
	}
	return true
}

// listBack is where a list form posted from path returns: path itself when
// it is the table's page or one of a host's lists, otherwise the page.
func listBack(table, page, path string) string {
	if path != page && hostListPath(table, path) {
		return path
	}
	return page
}

// onHost returns t limited to one host's rows, without its Host column,
// which would say the same on every row.
func onHost(t *list.Table, hostExpr, hostID string) *list.Table {
	c := *t
	scope := t.Scope
	c.Scope = func(a *list.Args, v list.Viewer) string {
		return scope(a, v) + " AND " + hostExpr + "::text = " + a.Add(hostID)
	}
	noHost := func(q list.Query) list.Query {
		q.Cols = slices.DeleteFunc(slices.Clone(q.Cols), func(k string) bool { return k == "host" || k == "hypervisor" })
		return q
	}
	c.Default = noHost(t.Default)
	c.Views = make([]list.View, len(t.Views))
	for i, v := range t.Views {
		v.Query = noHost(v.Query)
		c.Views[i] = v
	}
	return &c
}

// hostTabPage serves a host's tab at its own path.
func (s *Server) hostTabPage(tab string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.hostPage(w, r, tab) }
}

// hostListView runs a host's related list.
func (s *Server) hostListView(w http.ResponseWriter, r *http.Request, hostID, tab string) (*listView, bool) {
	hl := hostLists[tab]
	t, _, err := s.listTable(r.Context(), hl.Table)
	if err != nil {
		s.serverError(w, r, err)
		return nil, false
	}
	return s.buildTableList(w, r, onHost(t, hl.Host, hostID), "/hosts/"+hostID+"/"+tab, listSelect{})
}
