package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/inventory"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

var ciStatuses = []string{"active", "planned", "retired"}

// ciHostIDs are the hosts whose discovered CIs (the host, its containers
// and stacks) the user may see.
func (s *Server) ciHostIDs(r *http.Request) ([]string, error) { return s.visibleHostIDs(r) }

// canSeeCI: agentless CIs are visible to every viewer; discovered ones to
// whoever may see the host they live on.
func canSeeCI(c store.CI, hostIDs []string) bool {
	return c.Agentless() || (c.HostID != "" && slices.Contains(hostIDs, c.HostID))
}

// ciLink is where a CI's main page is: hosts, containers, stacks,
// discovered guests and clusters have their own.
func ciLink(c store.CI) string {
	switch c.Type {
	case "host":
		return "/hosts/" + c.ID
	case "container":
		if c.Status == "active" {
			return "/containers/" + c.ID
		}
	case "compose_stack":
		return "/stacks/" + c.ID
	case "vm", "lxc":
		if !c.Manual() {
			return "/vms/" + c.ID
		}
	case "k8s_cluster":
		return "/kubernetes/" + c.ID
	}
	return "/cis/" + c.ID
}

type ciListView struct {
	CanEdit bool
	List    *listView
}

func (s *Server) ciList(w http.ResponseWriter, r *http.Request) {
	v, ok := s.buildList(w, r, "ci")
	if !ok {
		return
	}
	s.renderList(w, r, "cis", "CIs", ciListView{CanEdit: principal(r).Grants.Has(rbac.Operator), List: v}, v)
}

// loadCI fetches the CI in the path if the user may see it.
func (s *Server) loadCI(w http.ResponseWriter, r *http.Request) (store.CI, []string, bool) {
	c, err := s.store.GetCI(r.Context(), r.PathValue("id"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return c, nil, false
	}
	ids, ierr := s.ciHostIDs(r)
	if ierr != nil {
		s.serverError(w, r, ierr)
		return c, nil, false
	}
	if err != nil || !canSeeCI(c, ids) {
		s.errorPage(w, r, http.StatusNotFound, "No such CI.")
		return c, nil, false
	}
	return c, ids, true
}

type ciPageView struct {
	CI        store.CI
	Type      store.CIType
	Link      string // the CI's own page, when it isn't this one
	Rels      []relView
	Graph     template.HTML
	Certs     []store.CertRow
	WorkItems []linkedItem
	History   []historyView
	Targets   []store.CI // CIs a relationship can point to
	Kinds     []string
	CanEdit   bool // edit fields and relationships
	CanDelete bool
	Notice    string
	Error     string
}

type relView struct {
	store.Relationship
	Link string
}

func (s *Server) ciPage(w http.ResponseWriter, r *http.Request) {
	c, ids, ok := s.loadCI(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	g := principal(r).Grants
	v := ciPageView{CI: c, Kinds: store.RelationKinds, CanEdit: g.Has(rbac.Operator),
		Notice: r.URL.Query().Get("notice"), Error: r.URL.Query().Get("error")}
	v.CanDelete = (c.Manual() && g.Has(rbac.Operator)) || (!c.Manual() && c.Type != "host" && g.Has(rbac.Admin) &&
		(c.Status == "missing" || c.Status == "retired"))
	if l := ciLink(c); l != "/cis/"+c.ID {
		v.Link = l
	}
	types, err := s.store.CITypes(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, t := range types {
		if t.Key == c.Type {
			v.Type = t
		}
	}
	rels, err := s.store.CIRelationships(ctx, c.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, rel := range rels {
		if canSeeCI(rel.Other, ids) {
			v.Rels = append(v.Rels, relView{Relationship: rel, Link: ciLink(rel.Other)})
		}
	}
	v.Graph = s.relGraph(c, v.Rels)
	if v.Certs, err = s.store.CICerts(ctx, c.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	items, err := s.store.CIWorkItems(ctx, c.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, it := range items {
		v.WorkItems = append(v.WorkItems, linkedItem{Rel: it.Role, Item: it.Item})
	}
	if c.Type != "host" { // a host's history is on its own page
		entries, err := s.store.CIHistory(ctx, c.ID, 100)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		v.History = historyViews(entries)
	}
	if v.CanEdit {
		all, err := s.store.ListCIs(ctx, store.CIFilter{HostIDs: ids, Limit: 1000})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		v.Targets = slices.DeleteFunc(all, func(o store.CI) bool { return o.ID == c.ID })
	}
	s.pages.render(w, http.StatusOK, "ci", s.data(r, c.Name, v))
}

func historyViews(entries []store.HistoryEntry) []historyView {
	var out []historyView
	for _, e := range entries {
		hv := historyView{At: e.At, Actor: e.Actor, Section: e.Section, ChangeID: e.ChangeID}
		if e.ChangeID != "" {
			hv.ChangeRef = e.ChangeRef()
		}
		var raw struct {
			Initial bool `json:"initial"`
			inventory.Diff
		}
		if json.Unmarshal(e.Diff, &raw) == nil {
			hv.Initial, hv.Diff = raw.Initial, raw.Diff
			hv.Summary = raw.Diff.Summary(e.Section)
		}
		out = append(out, hv)
	}
	return out
}

type ciFormView struct {
	CI       store.CI
	Types    []store.CIType
	Type     store.CIType
	Statuses []string
	New      bool
	Error    string
}

func (s *Server) ciForm(w http.ResponseWriter, r *http.Request, v ciFormView, status int) {
	types, err := s.store.CITypes(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, t := range types {
		if t.Manual() {
			v.Types = append(v.Types, t)
		}
		if t.Key == v.CI.Type {
			v.Type = t
		}
	}
	v.Statuses = ciStatuses
	title := "New CI"
	if !v.New {
		title = "Edit " + v.CI.Name
	}
	s.pages.render(w, status, "ci_form", s.data(r, title, v))
}

// ciNew shows the form for an agentless CI. Picking the type reloads it with
// that type's fields.
func (s *Server) ciNew(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("type")
	if t == "" {
		t = "network_device"
	}
	s.ciForm(w, r, ciFormView{New: true, CI: store.CI{Type: t, Status: "active", Attrs: map[string]any{}}}, http.StatusOK)
}

var endpointRe = regexp.MustCompile(`^[A-Za-z0-9.\-]+(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$`)

// ciInput reads and validates the CI form against the fields of type typ.
func (s *Server) ciInput(r *http.Request, typ string) (store.CIInput, store.CI, error) {
	in := store.CIInput{
		Type: typ, Name: strings.TrimSpace(r.FormValue("name")), Status: r.FormValue("status"),
		Owner: strings.TrimSpace(r.FormValue("owner")), Description: strings.TrimSpace(r.FormValue("description")),
		Attrs: map[string]string{},
	}
	for _, t := range strings.FieldsFunc(r.FormValue("tags"), func(c rune) bool { return c == ',' || c == ' ' }) {
		if !slices.Contains(in.Tags, t) {
			in.Tags = append(in.Tags, t)
		}
	}
	echo := store.CI{Type: in.Type, Name: in.Name, Status: in.Status, Owner: in.Owner, Description: in.Description,
		Tags: in.Tags, Attrs: map[string]any{}}
	types, err := s.store.CITypes(r.Context())
	if err != nil {
		return in, echo, err
	}
	i := slices.IndexFunc(types, func(t store.CIType) bool { return t.Key == in.Type && t.Manual() })
	if i < 0 {
		return in, echo, errBadInput("Pick a type.")
	}
	for _, f := range types[i].Fields {
		if f.Discovered {
			continue
		}
		val := strings.TrimSpace(r.FormValue("attr_" + f.Key))
		in.Attrs[f.Key] = val
		echo.Attrs[f.Key] = val
		if val == "" {
			continue
		}
		switch f.Type {
		case "date":
			if _, err := time.Parse(time.DateOnly, val); err != nil {
				return in, echo, errBadInput(f.Label + " must be a date (YYYY-MM-DD).")
			}
		case "url":
			if u, err := url.Parse(val); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return in, echo, errBadInput(f.Label + " must be an http(s) URL.")
			}
		case "endpoint":
			if !endpointRe.MatchString(val) {
				return in, echo, errBadInput(f.Label + " must be host or host:port, e.g. nas.lan:443.")
			}
		}
	}
	switch {
	case in.Name == "":
		return in, echo, errBadInput("Enter a name.")
	case !slices.Contains(ciStatuses, in.Status):
		return in, echo, errBadInput("Pick a status.")
	}
	return in, echo, nil
}

type errBadInput string

func (e errBadInput) Error() string { return string(e) }

func (s *Server) ciCreate(w http.ResponseWriter, r *http.Request) {
	in, echo, err := s.ciInput(r, r.FormValue("type"))
	var bad errBadInput
	if errors.As(err, &bad) {
		s.ciForm(w, r, ciFormView{New: true, CI: echo, Error: string(bad)}, http.StatusBadRequest)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	id, err := s.store.CreateCI(r.Context(), s.actor(r), in)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if in.Attrs["tls_endpoint"] != "" && s.checker != nil {
		s.checker.Trigger()
	}
	http.Redirect(w, r, s.url("/cis/"+id+"?notice="+url.QueryEscape("Created.")), http.StatusSeeOther)
}

func (s *Server) ciEdit(w http.ResponseWriter, r *http.Request) {
	c, _, ok := s.loadCI(w, r)
	if !ok {
		return
	}
	if !c.Manual() {
		s.errorPage(w, r, http.StatusBadRequest, "This CI is maintained by discovery and can't be edited.")
		return
	}
	s.ciForm(w, r, ciFormView{CI: c}, http.StatusOK)
}

func (s *Server) ciUpdate(w http.ResponseWriter, r *http.Request) {
	c, _, ok := s.loadCI(w, r)
	if !ok {
		return
	}
	if !c.Manual() {
		s.errorPage(w, r, http.StatusBadRequest, "This CI is maintained by discovery and can't be edited.")
		return
	}
	// The type is fixed once created: its fields are what's validated.
	in, echo, err := s.ciInput(r, c.Type)
	var bad errBadInput
	if errors.As(err, &bad) {
		echo.ID = c.ID
		s.ciForm(w, r, ciFormView{CI: echo, Error: string(bad)}, http.StatusBadRequest)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	err = s.store.UpdateCI(r.Context(), s.actor(r), c.ID, in)
	if errors.Is(err, store.ErrNotManual) {
		s.errorPage(w, r, http.StatusBadRequest, "This CI is maintained by discovery and can't be edited.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if in.Attrs["tls_endpoint"] != c.Attr("tls_endpoint") && s.checker != nil {
		s.checker.Trigger()
	}
	http.Redirect(w, r, s.url("/cis/"+c.ID+"?notice="+url.QueryEscape("Saved.")), http.StatusSeeOther)
}

func (s *Server) ciDelete(w http.ResponseWriter, r *http.Request) {
	c, _, ok := s.loadCI(w, r)
	if !ok {
		return
	}
	g := principal(r).Grants
	if (c.Manual() && !g.Has(rbac.Operator)) || (!c.Manual() && !g.Has(rbac.Admin)) {
		s.errorPage(w, r, http.StatusForbidden, "Your role doesn't allow this.")
		return
	}
	err := s.store.DeleteCI(r.Context(), s.actor(r), c.ID)
	switch {
	case errors.Is(err, store.ErrNotManual):
		s.errorPage(w, r, http.StatusBadRequest, "Discovered CIs can be deleted only once they're missing or retired; hosts are revoked instead.")
	case err != nil && !errors.Is(err, store.ErrNotFound):
		s.serverError(w, r, err)
	default:
		http.Redirect(w, r, s.url("/cis?notice="+url.QueryEscape("Deleted "+c.Name+".")), http.StatusSeeOther)
	}
}

func (s *Server) backToCI(w http.ResponseWriter, r *http.Request, id, kind, msg string) {
	http.Redirect(w, r, s.url("/cis/"+id+"?"+kind+"="+url.QueryEscape(msg)), http.StatusSeeOther)
}

// ciRelate adds a manual relationship between this CI and another one the
// user can see.
func (s *Server) ciRelate(w http.ResponseWriter, r *http.Request) {
	c, ids, ok := s.loadCI(w, r)
	if !ok {
		return
	}
	kind := r.FormValue("kind")
	other, err := s.store.GetCI(r.Context(), r.FormValue("other"))
	if err != nil || !canSeeCI(other, ids) || !slices.Contains(store.RelationKinds, kind) {
		s.backToCI(w, r, c.ID, "error", "Pick a relationship and another CI.")
		return
	}
	from, to := c.ID, other.ID
	if r.FormValue("direction") == "in" {
		from, to = to, from
	}
	err = s.store.AddRelationship(r.Context(), s.actor(r), from, to, kind)
	switch {
	case errors.Is(err, store.ErrConflict):
		s.backToCI(w, r, c.ID, "error", "That relationship already exists.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToCI(w, r, c.ID, "notice", "Relationship added.")
	}
}

func (s *Server) ciUnrelate(w http.ResponseWriter, r *http.Request) {
	c, _, ok := s.loadCI(w, r)
	if !ok {
		return
	}
	err := s.store.DeleteRelationship(r.Context(), s.actor(r), c.ID, r.PathValue("rel"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.backToCI(w, r, c.ID, "error", "Only manual relationships can be removed; discovered ones follow discovery.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToCI(w, r, c.ID, "notice", "Relationship removed.")
	}
}

// graphNode is a neighbour in the relationship graph: one CI, or several
// of one type related the same way ("94 containers run on this").
type graphNode struct {
	Name, Kind, Link, Edge string
	Outgoing, Manual, Dim  bool
}

// maxGraphNodes is how many neighbours are drawn one by one; past it,
// neighbours of one type related the same way are drawn as one node.
const maxGraphNodes = 12

func graphNodes(rels []relView) []graphNode {
	type key struct {
		kind, typ string
		out       bool
	}
	count := map[key]int{}
	for _, r := range rels {
		count[key{r.Kind, r.Other.TypeLabel, r.Outgoing}]++
	}
	var nodes []graphNode
	grouped := map[key]bool{}
	for _, r := range rels {
		k := key{r.Kind, r.Other.TypeLabel, r.Outgoing}
		if len(rels) > maxGraphNodes && count[k] >= 3 {
			if !grouped[k] {
				grouped[k] = true
				nodes = append(nodes, graphNode{Name: fmt.Sprintf("%d × %s", count[k], r.Other.TypeLabel), Kind: "listed below",
					Edge: r.Kind, Outgoing: r.Outgoing})
			}
			continue
		}
		nodes = append(nodes, graphNode{Name: r.Other.Name, Kind: r.Other.TypeLabel, Link: r.Link, Edge: r.Kind,
			Outgoing: r.Outgoing, Manual: r.Source == "manual", Dim: r.Other.Status != "active"})
	}
	return nodes
}

// relGraph draws a CI and its neighbours: the CI in the middle, related CIs
// on an ellipse around it, each edge labelled with its kind and pointing
// from "from" to "to". Nodes link to their pages.
func (s *Server) relGraph(c store.CI, rels []relView) template.HTML {
	nodes := graphNodes(rels)
	if len(nodes) == 0 {
		return ""
	}
	const w, nodeW, nodeH = 760.0, 150.0, 38.0
	n := len(nodes)
	ry := math.Min(math.Max(float64(n)*16, 90), 230)
	if n <= 2 {
		ry = 0 // a single row: neighbours left and right
	}
	h := 2*ry + nodeH + 40
	cx, cy, rx := w/2, h/2, w/2-nodeW/2-8
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="rel-graph" viewBox="0 0 %.0f %.0f" role="img" aria-label="Relationships of %s">`, w, h, template.HTMLEscapeString(c.Name))
	b.WriteString(`<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z"/></marker></defs>`)
	type pt struct{ x, y float64 }
	pos := make([]pt, n)
	for i := range nodes {
		// Start at the left so two neighbours sit either side.
		a := math.Pi + 2*math.Pi*float64(i)/float64(n)
		pos[i] = pt{cx + rx*math.Cos(a), cy + ry*math.Sin(a)}
	}
	// Edges first, so nodes sit on top. Each edge stops at the boxes.
	for i, nd := range nodes {
		x1, y1, x2, y2 := cx, cy, pos[i].x, pos[i].y
		if !nd.Outgoing {
			x1, y1, x2, y2 = x2, y2, x1, y1
		}
		sx, sy := clipToBox(x1, y1, x2, y2, nodeW/2, nodeH/2)
		ex, ey := clipToBox(x2, y2, x1, y1, nodeW/2, nodeH/2)
		cls := "edge"
		if nd.Manual {
			cls += " manual"
		}
		fmt.Fprintf(&b, `<line class="%s" x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" marker-end="url(#arrow)"/>`, cls, sx, sy, ex, ey)
		fmt.Fprintf(&b, `<text class="edge-label" x="%.1f" y="%.1f">%s</text>`, (sx+ex)/2, (sy+ey)/2-4,
			template.HTMLEscapeString(strings.ReplaceAll(nd.Edge, "_", " ")))
	}
	node := func(x, y float64, href, name, kind, cls string) {
		if len([]rune(name)) > 20 {
			name = string([]rune(name)[:19]) + "…"
		}
		if href != "" {
			fmt.Fprintf(&b, `<a href="%s">`, template.HTMLEscapeString(s.url(href)))
		}
		fmt.Fprintf(&b, `<g class="%s"><rect x="%.1f" y="%.1f" width="%.0f" height="%.0f" rx="6"/>`, cls, x-nodeW/2, y-nodeH/2, nodeW, nodeH)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" class="name">%s</text><text x="%.1f" y="%.1f" class="kind">%s</text></g>`,
			x, y-2, template.HTMLEscapeString(name), x, y+12, template.HTMLEscapeString(kind))
		if href != "" {
			b.WriteString(`</a>`)
		}
	}
	for i, nd := range nodes {
		cls := "node"
		switch {
		case nd.Link == "":
			cls += " group"
		case nd.Dim:
			cls += " dim"
		}
		node(pos[i].x, pos[i].y, nd.Link, nd.Name, nd.Kind, cls)
	}
	node(cx, cy, ciLink(c), c.Name, c.TypeLabel, "node center")
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// clipToBox moves the point (x1, y1), the centre of a box of half-size
// hw×hh, along the line towards (x2, y2) until it reaches the box's edge.
func clipToBox(x1, y1, x2, y2, hw, hh float64) (float64, float64) {
	dx, dy := x2-x1, y2-y1
	if dx == 0 && dy == 0 {
		return x1, y1
	}
	t := math.Inf(1)
	if dx != 0 {
		t = math.Min(t, hw/math.Abs(dx))
	}
	if dy != 0 {
		t = math.Min(t, hh/math.Abs(dy))
	}
	t = math.Min(t+0.02, 1)
	return x1 + dx*t, y1 + dy*t
}
