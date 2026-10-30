package store_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/store"
)

func TestFieldParse(t *testing.T) {
	loc := time.FixedZone("X", 2*3600)
	cases := []struct {
		f    store.FieldDef
		raw  []string
		want any
		bad  bool
	}{
		{store.FieldDef{Type: store.FieldText}, []string{"  hi "}, "hi", false},
		{store.FieldDef{Type: store.FieldText}, []string{" "}, nil, false},
		{store.FieldDef{Type: store.FieldNumber}, []string{"2.5"}, 2.5, false},
		{store.FieldDef{Type: store.FieldNumber}, []string{"two"}, nil, true},
		{store.FieldDef{Type: store.FieldDate}, []string{"2026-10-01"}, "2026-10-01", false},
		{store.FieldDef{Type: store.FieldDate}, []string{"2026-13-01"}, nil, true},
		{store.FieldDef{Type: store.FieldDatetime}, []string{"2026-10-01T15:04"}, "2026-10-01T13:04:00Z", false},
		{store.FieldDef{Type: store.FieldBool}, []string{"1"}, true, false},
		{store.FieldDef{Type: store.FieldSelect, Options: []string{"a", "b"}}, []string{"b"}, "b", false},
		{store.FieldDef{Type: store.FieldSelect, Options: []string{"a", "b"}}, []string{"c"}, nil, true},
		{store.FieldDef{Type: store.FieldMultiselect, Options: []string{"a", "b"}}, []string{"b", "a", "b"}, []any{"b", "a"}, false},
		{store.FieldDef{Type: store.FieldMultiselect, Options: []string{"a"}}, []string{"a", "z"}, nil, true},
		{store.FieldDef{Type: store.FieldURL}, []string{"https://x.lan/a"}, "https://x.lan/a", false},
		{store.FieldDef{Type: store.FieldURL}, []string{"javascript:alert(1)"}, nil, true},
		{store.FieldDef{Type: store.FieldUser}, []string{"0A0A0A0A-0000-0000-0000-000000000000"}, "0a0a0a0a-0000-0000-0000-000000000000", false},
		{store.FieldDef{Type: store.FieldCI}, []string{"nas1"}, nil, true},
	}
	for _, c := range cases {
		got, err := c.f.Parse(c.raw, loc)
		var bad store.ErrFieldValue
		if c.bad != errors.As(err, &bad) || (!c.bad && err != nil) {
			t.Errorf("%s %q: error %v", c.f.Type, c.raw, err)
			continue
		}
		if !c.bad && !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %q: got %#v, want %#v", c.f.Type, c.raw, got, c.want)
		}
	}
}

func formShape(f store.Form) string {
	var out []string
	for _, s := range f.Sections {
		var items []string
		for _, it := range s.Items {
			if it.Core != "" {
				items = append(items, it.Core)
			} else {
				name := it.Field.Key
				if it.Field.Required {
					name += "*"
				}
				items = append(items, name)
			}
		}
		out = append(out, s.Title+"["+strings.Join(items, " ")+"]")
	}
	return strings.Join(out, " ")
}

func TestBuildForm(t *testing.T) {
	f := func(id, key string) store.FieldDef { return store.FieldDef{ID: id, Key: key, Label: key} }
	g1 := store.FieldGroup{ID: "g1", Name: "Hardware", Fields: []store.GroupField{
		{FieldDef: f("1", "serial")}, {FieldDef: f("2", "site"), Default: "lab"}}}
	g2 := store.FieldGroup{ID: "g2", Name: "Location", Fields: []store.GroupField{
		{FieldDef: f("2", "site"), Required: true, Default: "dc"}, {FieldDef: f("3", "rack")}}}
	core := "[title description priority impact urgency assignee parent estimate due]"

	// No layout: the core fields, then each group; a field in both shows
	// once, in the first, required because the second requires it.
	form := store.BuildForm(nil, []store.FieldGroup{g1, g2})
	if got, want := formShape(form), core+" Hardware[serial site*] Location[rack]"; got != want {
		t.Errorf("no layout:\n got %s\nwant %s", got, want)
	}
	if site := form.Field("site"); site == nil || site.Default != "lab" || len(form.Fields) != 3 {
		t.Errorf("fields: %+v", form.Fields)
	}

	// A layout places a single field and a group; the core fields it
	// leaves out lead, applied fields it leaves out trail in Other, and a
	// group that isn't applied places nothing.
	layout := &store.Layout{Sections: []store.LayoutSection{
		{Title: "Main", Columns: 2, Items: []store.LayoutItem{{Kind: "core", Field: "title"}, {Kind: "field", FieldID: "3"},
			{Kind: "core", Field: "priority"}, {Kind: "core", Field: "title"}}},
		{Title: "Where", Items: []store.LayoutItem{{Kind: "group", GroupID: "g2"}, {Kind: "group", GroupID: "nope"}}},
		{Title: "Empty", Items: []store.LayoutItem{{Kind: "field", FieldID: "3"}}},
	}}
	form = store.BuildForm(layout, []store.FieldGroup{g1, g2})
	want := "[description impact urgency assignee parent estimate due] Main[title rack priority] Where[site*] Other[serial]"
	if got := formShape(form); got != want {
		t.Errorf("layout:\n got %s\nwant %s", got, want)
	}
	if form.Sections[1].Columns != 2 || form.Sections[2].Columns != 1 {
		t.Errorf("columns: %+v", form.Sections)
	}
}

func TestCustomFields(t *testing.T) {
	s := newTestStore(t)
	ann := user(t, s, "ann")
	annID := strings.TrimPrefix(ann.ID, "user:")
	types := typeIDs(t, s, "incident", "task")

	if _, err := s.SaveFieldDef(ctx, ann, "", store.FieldDef{Key: "env", Label: "Environment", Type: store.FieldSelect}); !errors.Is(err, store.ErrNoOptions) {
		t.Fatalf("select without options: %v", err)
	}
	env, err := s.SaveFieldDef(ctx, ann, "", store.FieldDef{Key: "env", Label: "Environment", Type: store.FieldSelect, Options: []string{"prod", "test"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveFieldDef(ctx, ann, "", store.FieldDef{Key: "env", Label: "Again", Type: store.FieldText}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate key: %v", err)
	}
	// The key and type stay as created.
	if _, err := s.SaveFieldDef(ctx, ann, env, store.FieldDef{Key: "other", Label: "Env", Type: store.FieldText, Options: []string{"prod", "test", "dev"}}); err != nil {
		t.Fatal(err)
	}
	if f, _ := s.GetFieldDef(ctx, env); f.Key != "env" || f.Type != store.FieldSelect || f.Label != "Env" || len(f.Options) != 3 {
		t.Fatalf("edited field: %+v", f)
	}
	owner, _ := s.SaveFieldDef(ctx, ann, "", store.FieldDef{Key: "owner", Label: "Owner", Type: store.FieldUser})
	ticket, _ := s.SaveFieldDef(ctx, ann, "", store.FieldDef{Key: "vendor_ticket", Label: "Vendor ticket", Type: store.FieldText})

	ops, err := s.SaveFieldGroup(ctx, ann, "", store.FieldGroupInput{Name: "Ops", Fields: []store.GroupFieldInput{
		{FieldID: env, Required: true, Default: "prod"}, {FieldID: owner}}})
	if err != nil {
		t.Fatal(err)
	}
	vendor, _ := s.SaveFieldGroup(ctx, ann, "", store.FieldGroupInput{Name: "Vendor", Fields: []store.GroupFieldInput{
		{FieldID: ticket}, {FieldID: env}}})
	if _, err := s.SaveFieldGroup(ctx, ann, "", store.FieldGroupInput{Name: "ops"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate group name: %v", err)
	}
	if err := s.DeleteFieldDef(ctx, ann, env); !errors.Is(err, store.ErrInUse) {
		t.Fatalf("delete a field in a group: %v", err)
	}
	g, err := s.GetFieldGroup(ctx, ops)
	if err != nil || len(g.Fields) != 2 || g.Fields[0].Key != "env" || !g.Fields[0].Required || g.Fields[0].Default != "prod" {
		t.Fatalf("group: %+v %v", g, err)
	}

	pid, err := s.CreateProject(ctx, ann, store.ProjectInput{Key: "OPS", Name: "Operations", Kind: "service_desk", TypeIDs: types})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetProjectTypeGroups(ctx, ann, pid, types[0], []string{vendor, ops}); err != nil {
		t.Fatal(err)
	}
	other := typeIDs(t, s, "bug")[0]
	if err := s.SetProjectTypeGroups(ctx, ann, pid, other, []string{ops}); !errors.Is(err, store.ErrTypeNotOffered) {
		t.Fatalf("groups for a type the project doesn't offer: %v", err)
	}

	// Editing the project keeps the groups of the types it keeps.
	if err := s.UpdateProject(ctx, ann, pid, store.ProjectInput{Name: "Ops", Kind: "service_desk", TypeIDs: []string{types[1], types[0]},
		DefaultType: types[1]}); err != nil {
		t.Fatal(err)
	}
	applied, _ := s.ProjectTypeGroups(ctx, pid, types[0])
	if len(applied) != 2 || applied[0].ID != vendor {
		t.Fatalf("groups after a project edit: %+v", applied)
	}

	// No layout: the groups in order, env once and required.
	form, err := s.ResolveForm(ctx, pid, types[0], store.ScreenCreate)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := formShape(form), "[title description priority impact urgency assignee parent estimate due] Vendor[vendor_ticket env*] Ops[owner]"; got != want {
		t.Fatalf("form:\n got %s\nwant %s", got, want)
	}

	// The type's default layout applies until the project has its own, and
	// a create layout "for view too" serves the view screen.
	def := store.Layout{TypeID: types[0], Screen: store.ScreenCreate, ViewUsesCreate: true, Sections: []store.LayoutSection{
		{Title: "Basics", Items: []store.LayoutItem{{Kind: "core", Field: "title"}, {Kind: "field", FieldID: owner}, {Kind: "core", Field: "bogus"}}}}}
	if err := s.SaveLayout(ctx, ann, def); err != nil {
		t.Fatal(err)
	}
	for _, screen := range store.Screens {
		form, _ = s.ResolveForm(ctx, pid, types[0], screen)
		if form.Layout.ProjectID != "" || form.Sections[1].Title != "Basics" || formShape(form)[len(formShape(form))-len("Other[vendor_ticket env*]"):] != "Other[vendor_ticket env*]" {
			t.Fatalf("%s screen from the default: %s", screen, formShape(form))
		}
	}
	own := store.Layout{ProjectID: pid, TypeID: types[0], Screen: store.ScreenView, Sections: []store.LayoutSection{
		{Title: "All", Items: []store.LayoutItem{{Kind: "group", GroupID: ops}, {Kind: "group", GroupID: vendor}}}}}
	if err := s.SaveLayout(ctx, ann, own); err != nil {
		t.Fatal(err)
	}
	form, _ = s.ResolveForm(ctx, pid, types[0], store.ScreenView)
	if form.Layout.ProjectID != pid || !strings.HasSuffix(formShape(form), "All[env* owner vendor_ticket]") {
		t.Fatalf("project view layout: %s", formShape(form))
	}
	if err := s.DeleteLayout(ctx, ann, pid, types[0], store.ScreenView); err != nil {
		t.Fatal(err)
	}
	if form, _ = s.ResolveForm(ctx, pid, types[0], store.ScreenView); form.Layout.ProjectID != "" {
		t.Fatalf("after reset: %+v", form.Layout)
	}

	// Values: set, change and clear, with history by label.
	id, _, err := s.CreateWorkItem(ctx, ann, annID, store.WorkItemInput{ProjectID: pid, TypeID: types[0], Title: "Disk", Priority: "high",
		Custom: map[string]any{"env": "prod", "owner": annID, "vendor_ticket": nil}})
	if err != nil {
		t.Fatal(err)
	}
	w, _ := s.GetWorkItem(ctx, id)
	if !reflect.DeepEqual(w.Custom, map[string]any{"env": "prod", "owner": annID}) {
		t.Fatalf("custom on create: %+v", w.Custom)
	}
	in := store.WorkItemInput{Title: w.Title, Priority: w.Priority, Custom: map[string]any{"env": "test", "owner": nil, "vendor_ticket": "V-1"}}
	if err := s.UpdateWorkItem(ctx, ann, id, in); err != nil {
		t.Fatal(err)
	}
	w, _ = s.GetWorkItem(ctx, id)
	if !reflect.DeepEqual(w.Custom, map[string]any{"env": "test", "vendor_ticket": "V-1"}) {
		t.Fatalf("custom after edit: %+v", w.Custom)
	}
	h, _ := s.WorkItemHistory(ctx, id, 10)
	if len(h) != 2 || h[0].Summary != "changed Env, Owner, Vendor ticket" {
		t.Fatalf("history: %+v", h)
	}
	for _, c := range h[0].Diff.Changed {
		if c.Field == "Owner" && (c.From != "ANN" || c.To != "") {
			t.Fatalf("owner change: %+v", c)
		}
	}
	// A nil map leaves values alone; the same values again aren't a change.
	in.Custom = nil
	s.UpdateWorkItem(ctx, ann, id, in)
	in.Custom = map[string]any{"env": "test"}
	s.UpdateWorkItem(ctx, ann, id, in)
	if h, _ := s.WorkItemHistory(ctx, id, 10); len(h) != 2 {
		t.Fatalf("no-op edits were recorded: %d entries", len(h))
	}
	if w, _ = s.GetWorkItem(ctx, id); len(w.Custom) != 2 {
		t.Fatalf("custom after no-op edits: %+v", w.Custom)
	}

	// Deleting a group takes it off projects; deleting a field it held is
	// then allowed.
	if err := s.DeleteFieldGroup(ctx, ann, vendor); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteFieldDef(ctx, ann, ticket); err != nil {
		t.Fatal(err)
	}
	if applied, _ := s.ProjectTypeGroups(ctx, pid, types[0]); len(applied) != 1 {
		t.Fatalf("groups after deleting one: %+v", applied)
	}
}
