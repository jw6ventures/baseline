package list

import (
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

var testTable = &Table{
	Key: "thing", Label: "Things", Noun: "thing",
	From: "thing t", ID: "t.id::text", LinkExpr: "'/things/' || t.id",
	Scope: func(a *Args, v Viewer) string {
		return "t.host::text = ANY(" + a.Add(TextArray(v.HostIDs)) + "::text[])"
	},
	Fields: []Field{
		{Key: "name", Label: "Name", Type: Text, Expr: "t.name", Search: true},
		{Key: "state", Label: "State", Type: Enum, Expr: "t.state", Options: []Option{{Value: "on", Label: "On"}, {Value: "off", Label: "Off"}}},
		{Key: "size", Label: "Size", Type: Number, Expr: "t.size"},
		{Key: "seen", Label: "Seen", Type: Time, Expr: "t.seen"},
		{Key: "tags", Label: "Tags", Type: Tags, Expr: "t.tags", Search: true},
		{Key: "ok", Label: "OK", Type: Bool, Expr: "t.ok"},
		{Key: "secret", Label: "Secret", Type: Text, Expr: "t.secret", NoFilter: true},
	},
	Default: Query{Cols: []string{"name", "state"}, Sort: Sort{Field: "name"},
		Groups: [][]Cond{{{Field: "state", Op: Eq, Value: "on"}}}},
}

func TestValidate(t *testing.T) {
	if err := testTable.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := *testTable
	bad.Fields = append(slices.Clone(bad.Fields), Field{Key: "name", Label: "Again", Type: Text, Expr: "x"})
	if bad.Validate() == nil {
		t.Fatal("duplicate field accepted")
	}
}

func TestParseRoundTrip(t *testing.T) {
	v, _ := url.ParseQuery("cf=name&co=contains&cv=pl&cg=0&cf=size&co=gt&cv=10&cg=0&cf=tags&co=has&cv=a&cg=3" +
		"&cf=&co=eq&cv=&cg=0&cols=name,size&cols=seen&sort=-size&group=state&page=2&q=x")
	q, problems := Parse(testTable, v)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	if len(q.Groups) != 2 || len(q.Groups[0]) != 2 || q.Groups[1][0].Value != "a" {
		t.Fatalf("groups: %+v", q.Groups)
	}
	if !slices.Equal(q.Cols, []string{"name", "size", "seen"}) || q.Sort != (Sort{"size", true}) ||
		q.GroupBy != "state" || q.Page != 2 || q.Search != "x" {
		t.Fatalf("query: %+v", q)
	}
	again, _ := Parse(testTable, q.Values())
	if again.Encode() != q.Encode() {
		t.Fatalf("round trip:\n%s\n%s", q.Encode(), again.Encode())
	}
}

func TestParseDropsWhatTheRegistryRefuses(t *testing.T) {
	v, _ := url.ParseQuery("cf=nope&co=eq&cv=1&cf=secret&co=eq&cv=1&cf=state&co=eq&cv=maybe" +
		"&cf=size&co=contains&cv=1&cf=size&co=gt&cv=big&cf=seen&co=within&cv=soon&cols=name,evil&sort=evil&group=seen")
	q, problems := Parse(testTable, v)
	if len(q.Groups) != 0 || len(problems) != 9 {
		t.Fatalf("groups %+v, problems %q", q.Groups, problems)
	}
	if !slices.Equal(q.Cols, []string{"name"}) || q.Sort.Field != "name" || q.GroupBy != "" {
		t.Fatalf("query: %+v", q)
	}
}

func TestBareURLUsesDefault(t *testing.T) {
	q, _ := Parse(testTable, url.Values{})
	if len(q.Groups) != 1 {
		t.Fatalf("default: %+v", q)
	}
	// Removing the last condition must not bring the default back.
	q = q.Without(0, 0)
	again, _ := Parse(testTable, q.Values())
	if len(again.Groups) != 0 {
		t.Fatalf("default came back: %+v", again)
	}
}

func TestWithAddsToEveryGroup(t *testing.T) {
	q := Query{Groups: [][]Cond{{{"name", Eq, "a"}}, {{"name", Eq, "b"}}}}
	q = q.With(Cond{"state", Eq, "on"})
	if len(q.Groups[0]) != 2 || len(q.Groups[1]) != 2 {
		t.Fatalf("%+v", q.Groups)
	}
	if n := (Query{}).With(Cond{"state", Ne, "on"}); len(n.Groups) != 1 {
		t.Fatalf("%+v", n.Groups)
	}
}

// Values never reach the SQL text, only the bound parameters.
func TestBuildBindsValues(t *testing.T) {
	evil := "x'); DROP TABLE thing; --"
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	q := Query{
		Groups: [][]Cond{
			{{"name", Contains, evil}, {"size", Ge, "2.5"}, {"seen", Within, "7d"}},
			{{"tags", Has, evil}, {"ok", IsTrue, ""}, {"state", Ne, "off"}},
		},
		Search: evil, Cols: []string{"name", "tags"}, Sort: Sort{"size", true}, GroupBy: "state", Page: 3,
	}
	st, err := Build(testTable, q, Options{Viewer: Viewer{HostIDs: []string{"h1"}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(st.SQL, "DROP") || strings.Contains(st.SQL, "2.5") {
		t.Fatalf("value in SQL:\n%s", st.SQL)
	}
	for _, want := range []string{"FROM thing t WHERE", "t.host::text = ANY($1::text[])", " OR ", "count(*) OVER (PARTITION BY t.state)",
		"ORDER BY t.state NULLS LAST, t.size DESC NULLS LAST, t.id::text", "LIMIT $"} {
		if !strings.Contains(st.SQL, want) {
			t.Errorf("SQL lacks %q:\n%s", want, st.SQL)
		}
	}
	var since time.Time
	var nums []any
	for _, a := range st.Args {
		switch x := a.(type) {
		case time.Time:
			since = x
		case float64, int:
			nums = append(nums, x)
		}
	}
	if !since.Equal(now.Add(-7 * 24 * time.Hour)) {
		t.Errorf("within 7d bound %v", since)
	}
	if !slices.Contains(nums, any(2.5)) || !slices.Contains(nums, any(200)) {
		t.Errorf("numbers: %v (want 2.5 and the offset 200)", nums)
	}
	if st.Group == nil || len(st.Cols) != 2 {
		t.Fatalf("statement: %+v", st)
	}
}

func TestMatchExprTestsMembership(t *testing.T) {
	tbl := *testTable
	tbl.Fields = append(slices.Clone(tbl.Fields), Field{Key: "cat", Label: "Category", Type: Enum, Expr: "t.cat",
		MatchExpr: "t.cat_ancestors", Options: []Option{{Value: "c1", Label: "Infra"}}})
	for op, want := range map[Op]string{Eq: "= ANY(t.cat_ancestors)", Ne: "NOT ($2 = ANY(COALESCE(t.cat_ancestors, '{}')))",
		Empty: "COALESCE(t.cat, '') = ''"} {
		st, err := Build(&tbl, Query{Groups: [][]Cond{{{"cat", op, "c1"}}}}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(st.SQL, want) {
			t.Errorf("%s: SQL lacks %q:\n%s", op, want, st.SQL)
		}
	}
}

func TestTextArray(t *testing.T) {
	if got := (TextArray{`a`, `b"c`, `d\e`}).String(); got != `{"a","b\"c","d\\e"}` {
		t.Fatal(got)
	}
	if got := (TextArray{}).String(); got != `{}` {
		t.Fatal(got)
	}
}

func TestParseAge(t *testing.T) {
	for in, want := range map[string]time.Duration{"30m": 30 * time.Minute, "12h": 12 * time.Hour, "7d": 7 * 24 * time.Hour, "2W": 14 * 24 * time.Hour} {
		if d, err := ParseAge(in); err != nil || d != want {
			t.Errorf("%s: %v %v", in, d, err)
		}
	}
	if _, err := ParseAge("7 days"); err == nil {
		t.Error("7 days accepted")
	}
}
