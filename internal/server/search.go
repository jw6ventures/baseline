package server

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/list"
)

// Global search (Ctrl-K, docs/search.md): one box that finds hosts,
// containers, stacks, guests, CIs, work items, changes and projects by
// name. Each source is a list engine table searched on a few name-like
// fields, so a row shows up here only if the viewer's list would show it.

// searchSource is one kind of record global search looks in.
type searchSource struct {
	Table  string   // list table key
	Label  string   // heading for its results
	Title  string   // field shown as the result
	Ref    string   // optional field shown before the title (OPS-12)
	Detail string   // optional field shown after it, muted
	Fields []string // fields the search matches
	// Groups narrow the table's rows (CIs that have a page of their own
	// are found under that kind instead).
	Groups [][]list.Cond
}

var searchSources = []searchSource{
	{Table: "host", Label: "Hosts", Title: "name", Detail: "fqdn", Fields: []string{"name", "fqdn"}},
	{Table: "container", Label: "Containers", Title: "name", Detail: "host", Fields: []string{"name", "stack"}},
	{Table: "stack", Label: "Compose stacks", Title: "project", Detail: "host", Fields: []string{"project"}},
	{Table: "vm", Label: "Virtual machines", Title: "name", Detail: "hypervisor", Fields: []string{"name", "guest_id"}},
	{Table: "ci", Label: "Other CIs", Title: "name", Detail: "type", Fields: []string{"name"},
		Groups: [][]list.Cond{
			{cond("type", list.Ne, "host"), cond("type", list.Ne, "container"), cond("type", list.Ne, "compose_stack"),
				cond("type", list.Ne, "vm"), cond("type", list.Ne, "lxc")},
			{cond("source", list.Eq, "manual"), cond("type", list.Ne, "host")},
		}},
	{Table: "work", Label: "Work items", Ref: "ref", Title: "title", Detail: "status_name", Fields: []string{"ref", "title"}},
	{Table: "change", Label: "Changes", Ref: "ref", Title: "title", Detail: "state", Fields: []string{"ref", "title"}},
	{Table: "project", Label: "Projects", Ref: "key", Title: "name", Fields: []string{"key", "name"}},
}

const (
	searchPerSource = 5  // results shown per kind
	searchFetch     = 25 // rows fetched per kind, to rank the best five
	searchMaxLen    = 100
)

type searchResult struct {
	Ref    string `json:"ref,omitempty"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	URL    string `json:"url"`
	Dim    bool   `json:"dim,omitempty"`
}

type searchGroup struct {
	Key     string         `json:"key"`
	Label   string         `json:"label"`
	Results []searchResult `json:"results"`
	// More is set when there were more matches than shown; All links to
	// the kind's list searched for the same text.
	More bool   `json:"more,omitempty"`
	All  string `json:"all"`
}

type searchView struct {
	Query  string        `json:"query"`
	Groups []searchGroup `json:"groups"`
}

// searchTable returns the list table of a source. Containers skip
// containerAdvice: search never shows the newest-version field.
func (s *Server) searchTable(ctx context.Context, key string) (*list.Table, string, error) {
	if key == "container" {
		return containerTable(nil), "/containers", nil
	}
	return s.listTable(ctx, key)
}

// searchFor builds a copy of t whose quick search matches only fields.
func searchFor(t *list.Table, fields []string) *list.Table {
	c := *t
	c.Fields = slices.Clone(t.Fields)
	for i := range c.Fields {
		c.Fields[i].Search = slices.Contains(fields, c.Fields[i].Key)
	}
	return &c
}

// searchRank orders matches: the whole title, then a title that starts
// with the text, then a word in it that does, then the rest.
func searchRank(r searchResult, q string) int {
	for i, v := range []string{r.Ref, r.Title} {
		v = strings.ToLower(v)
		switch {
		case v == q:
			return 0 + i
		case strings.HasPrefix(v, q):
			return 2 + i
		}
	}
	for _, w := range strings.FieldsFunc(strings.ToLower(r.Title), func(c rune) bool {
		return c == ' ' || c == '-' || c == '_' || c == '.' || c == '/'
	}) {
		if strings.HasPrefix(w, q) {
			return 4
		}
	}
	return 5
}

func (s *Server) runSearch(r *http.Request, q string) (searchView, error) {
	v := searchView{Query: q, Groups: []searchGroup{}}
	if q == "" {
		return v, nil
	}
	ctx := r.Context()
	viewer, err := s.listViewer(r)
	if err != nil {
		return v, err
	}
	lq := strings.ToLower(q)
	for _, src := range searchSources {
		base, path, err := s.searchTable(ctx, src.Table)
		if err != nil {
			return v, err
		}
		t := searchFor(base, src.Fields)
		cols := []string{src.Title}
		for _, k := range []string{src.Ref, src.Detail} {
			if k != "" {
				cols = append(cols, k)
			}
		}
		query := list.Query{Cols: cols, Groups: src.Groups, Search: q, Sort: list.Sort{Field: src.Title}}
		st, err := list.Build(t, query, list.Options{Viewer: viewer, Now: time.Now(), Loc: s.cfg.Location, Limit: searchFetch})
		if err != nil {
			return v, err
		}
		res, err := s.store.ListRows(ctx, st)
		if err != nil {
			return v, err
		}
		if len(res.Rows) == 0 {
			continue
		}
		g := searchGroup{Key: src.Table, Label: src.Label, More: res.Total > searchPerSource,
			All: s.url(path + "?q=" + url.QueryEscape(q))}
		for _, row := range res.Rows {
			sr := searchResult{URL: s.url(row.Link), Dim: row.Dim}
			for i, f := range st.Cols {
				text := cellText(f, row.Values[i])
				switch f.Key {
				case src.Title:
					sr.Title = text
				case src.Ref:
					sr.Ref = text
				case src.Detail:
					sr.Detail = text
				}
			}
			g.Results = append(g.Results, sr)
		}
		slices.SortStableFunc(g.Results, func(a, b searchResult) int {
			ra, rb := searchRank(a, lq), searchRank(b, lq)
			if ra != rb {
				return ra - rb
			}
			// Live records before missing and retired ones.
			if a.Dim != b.Dim {
				if a.Dim {
					return 1
				}
				return -1
			}
			return 0
		})
		g.Results = g.Results[:min(len(g.Results), searchPerSource)]
		v.Groups = append(v.Groups, g)
	}
	return v, nil
}

// cellText is a list cell as plain text.
func cellText(f *list.Field, v any) string {
	switch x := v.(type) {
	case string:
		if f.Type == list.Enum {
			return f.OptionLabel(x)
		}
		return x
	case []string:
		return strings.Join(x, ", ")
	case nil:
		return ""
	}
	return ""
}

// searchQuery is the ?q= of a search, trimmed and capped.
func searchQuery(r *http.Request) string {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > searchMaxLen {
		q = q[:searchMaxLen]
		for !utf8.ValidString(q) {
			q = q[:len(q)-1]
		}
	}
	return q
}

// searchPage is the results page the top bar's form opens without JS.
func (s *Server) searchPage(w http.ResponseWriter, r *http.Request) {
	v, err := s.runSearch(r, searchQuery(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, http.StatusOK, "search", s.data(r, "Search", v))
}

// searchJSON answers the Ctrl-K palette.
func (s *Server) searchJSON(w http.ResponseWriter, r *http.Request) {
	v, err := s.runSearch(r, searchQuery(r))
	if err != nil {
		s.log.Log("Search", r.URL.Path, jw6_utils.Error, err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Search failed."})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, v)
}
