package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/list"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/web"
)

// renderer holds one template set per page, each parsed together with the
// shared layout.
type renderer struct {
	pages map[string]*template.Template
}

func newRenderer(loc *time.Location) (*renderer, error) {
	funcs := template.FuncMap{
		"time": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.In(loc).Format("2006-01-02 15:04:05 MST")
		},
		// ts formats an RFC 3339 timestamp from an inventory section.
		"ts": func(s string) string {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil || t.IsZero() {
				return "—"
			}
			return t.In(loc).Format("2006-01-02 15:04:05 MST")
		},
		"hasPrefix":    strings.HasPrefix,
		"join":         strings.Join,
		"bytes":        humanBytes,
		"ago":          func(t time.Time) string { return ago(time.Since(t)) },
		"value":        diffValue,
		"list":         func(s ...string) []string { return s },
		"title":        func(s string) string { return strings.ToUpper(s[:1]) + s[1:] },
		"has":          slices.Contains[[]string],
		"mod":          func(a, b int) int { return a % b },
		"add":          func(a, b int) int { return a + b },
		"digest":       shortDigest,
		"lower":        strings.ToLower,
		"uint":         func(n int64) uint64 { return uint64(max(n, 0)) },
		"jobClass":     jobStateClass,
		"changeClass":  changeStateClass,
		"human":        humanState,
		"itemStatus":   itemStatusLabel,
		"fieldType":    fieldTypeLabel,
		"fieldDefault": hasDefault,
		"rules":        ruleTexts,
		"mapHow":       mapHowText,
		"describe":     func(name string, params []byte) string { return action.Describe(name, params) },
		"duration":     func(d time.Duration) string { return d.String() },
		"plural":       plural,
		"mins":         formatSpan,
		"secs":         func(n int) time.Duration { return time.Duration(n) * time.Second },
		// dict passes several values to a shared template.
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		// score formats a CVSS score.
		"score": func(p *float64) string {
			if p == nil {
				return ""
			}
			return fmt.Sprintf("%.1f", *p)
		},
		"span": spanText,
		// chipStyle colors a project category or tag chip.
		"chipStyle": chipStyle,
		// The list engine's builder and cells (list_parts.html).
		"opTypes": func(o list.Op) string { return list.OpTypes(o) },
		"opFits":  func(f *list.Field, o list.Op) bool { return slices.Contains(f.Type.Ops(), o) },
		"optionsJSON": func(opts []list.Option) string {
			type o struct {
				V string `json:"v"`
				L string `json:"l"`
			}
			out := make([]o, len(opts))
			for i, x := range opts {
				out[i] = o{x.Value, x.Label}
			}
			b, _ := json.Marshal(out)
			return string(b)
		},
		"flagClass": hostFlagClass,
		"short": func(s string, n int) string {
			if len(s) > n {
				for n > 0 && !utf8.RuneStart(s[n]) {
					n--
				}
				return s[:n]
			}
			return s
		},
	}
	layout, err := template.New("layout.html").Funcs(funcs).ParseFS(web.FS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	files, err := fs.Glob(web.FS, "templates/pages/*.html")
	if err != nil {
		return nil, err
	}
	r := &renderer{pages: map[string]*template.Template{}}
	for _, f := range files {
		t, err := template.Must(layout.Clone()).ParseFS(web.FS, f)
		if err != nil {
			return nil, err
		}
		r.pages[strings.TrimSuffix(path.Base(f), ".html")] = t
	}
	return r, nil
}

// render executes into a buffer first, so a template error becomes a clean
// 500 rather than half a page.
func (r *renderer) render(w http.ResponseWriter, status int, page string, data pageData) {
	t, ok := r.pages[page]
	if !ok {
		http.Error(w, "unknown page "+page, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout.html", data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

// partial renders one shared template without the layout, for htmx. page
// picks the page's template set, which matters only for templates a page
// defines itself; "" uses the shared ones.
func (r *renderer) partial(w http.ResponseWriter, status int, page, name string, data any) {
	if page == "" {
		page = "error"
	}
	t, ok := r.pages[page]
	if !ok {
		http.Error(w, "unknown page "+page, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

// pageData is what every page template receives. Body is page-specific.
type pageData struct {
	Title   string
	Path    string // current path, for highlighting the nav
	Base    string // public URL path prefix
	User    *Principal
	Nav     []navGroup
	Version string
	Body    any
}

type navItem struct {
	Path    string
	Label   string
	Current bool // the page being shown is this item or below it
}

// navGroup is a collapsible topic in the side nav. A group with no Label
// is drawn as plain links (the dashboard).
type navGroup struct {
	Key   string // stable id, for remembering open groups in the browser
	Label string
	Items []navItem
	Open  bool // holds the current page
}

func (s *Server) data(r *http.Request, title string, body any) pageData {
	p := principal(r)
	d := pageData{Title: title, Path: r.URL.Path, Base: s.cfg.PublicURL.Path, User: p, Version: s.version, Body: body}
	if p != nil && !p.Grants.Empty() {
		d.Nav = buildNav(p, r.URL.Path)
	}
	return d
}

// buildNav lays out the side nav for p, marking the item for path.
func buildNav(p *Principal, path string) []navGroup {
	groups := []navGroup{
		{Key: "home", Items: []navItem{{Path: "/", Label: "Dashboard"}}},
		{Key: "work", Label: "Work", Items: []navItem{
			{Path: "/work", Label: "Work items"}, {Path: "/boards", Label: "Boards"}, {Path: "/projects", Label: "Projects"}}},
		{Key: "inventory", Label: "Inventory", Items: []navItem{
			{Path: "/cis", Label: "CIs"}, {Path: "/map", Label: "CI map"}, {Path: "/hosts", Label: "Hosts"},
			{Path: "/vms", Label: "Virtual machines"}, {Path: "/containers", Label: "Containers"}, {Path: "/kubernetes", Label: "Kubernetes"}}},
		{Key: "change", Label: "Change", Items: []navItem{
			{Path: "/changes", Label: "Changes"}, {Path: "/calendar", Label: "Calendar"}, {Path: "/windows", Label: "Windows"},
			{Path: "/change-models", Label: "Change models"}}},
		{Key: "patching", Label: "Patching", Items: []navItem{
			{Path: "/updates", Label: "Updates"}, {Path: "/patch-groups", Label: "Patch groups"},
			{Path: "/update-groups", Label: "Update groups"}, {Path: "/vulnerabilities", Label: "Vulnerabilities"}}},
		{Key: "automation", Label: "Automation", Items: []navItem{
			{Path: "/jobs", Label: "Jobs"}, {Path: "/scripts", Label: "Scripts"}}},
	}
	monitoring := navGroup{Key: "monitoring", Label: "Monitoring", Items: []navItem{{Path: "/alerts", Label: "Alerts"}}}
	if p.Grants.Has(rbac.Viewer) {
		monitoring.Items = append(monitoring.Items, navItem{Path: "/audit", Label: "Audit log"})
	}
	groups = append(groups, monitoring)
	if p.Grants.Has(rbac.Admin) {
		groups = append(groups, navGroup{Key: "admin", Label: "Administration", Items: []navItem{
			{Path: "/settings/access", Label: "Access"}, {Path: "/settings/enrollment", Label: "Enrollment"},
			{Path: "/settings/agents", Label: "Agents"}, {Path: "/settings/registries", Label: "Registries"},
			{Path: "/settings/unifi", Label: "UniFi"},
			{Path: "/settings/notifications", Label: "Notifications"}, {Path: "/settings/ticket-types", Label: "Ticket types"},
			{Path: "/settings/workflows", Label: "Workflows"}, {Path: "/settings/migrations", Label: "Migrations"},
			{Path: "/settings/fields", Label: "Custom fields"}, {Path: "/settings/field-groups", Label: "Field groups"}}})
	}
	for gi := range groups {
		g := &groups[gi]
		for ii := range g.Items {
			it := &g.Items[ii]
			it.Current = path == it.Path || (it.Path != "/" && strings.HasPrefix(path, it.Path+"/"))
			g.Open = g.Open || it.Current
		}
	}
	return groups
}

func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.pages.render(w, status, "error", s.data(r, http.StatusText(status), msg))
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Log("Server", r.Method+" "+r.URL.Path, jw6_utils.Error, err.Error())
	s.errorPage(w, r, http.StatusInternalServerError, "Something went wrong. The details are in the server log.")
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(web.FS, "static")
	if err != nil {
		panic(fmt.Sprintf("embedded static files: %v", err))
	}
	fsrv := http.StripPrefix("/static/", http.FileServerFS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fsrv.ServeHTTP(w, r)
	})
}

// humanBytes formats sizes with binary units, as disks and DIMMs are sold
// in decimal units but most tools show binary ones.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ago is a coarse relative time: "just now", "5m ago", "3h ago", "2d ago".
func ago(d time.Duration) string {
	switch {
	case d < 0:
		return "just now"
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

// diffValue renders a history value: strings as-is, anything else as
// compact JSON.
func diffValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// plural formats a count with a noun: plural(1, "host") is "1 host",
// plural(2, "host") "2 hosts"; an explicit plural form can follow.
func plural(n int, forms ...string) string {
	one, many := forms[0], forms[0]+"s"
	if len(forms) > 1 {
		many = forms[1]
	}
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
