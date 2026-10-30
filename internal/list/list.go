// Package list is the list engine (docs/lists.md): one condition builder,
// column picker, sort and group-by over every table the UI lists.
//
// A Table is a registry of the fields people may see, filter, sort and
// group by. Each field's SQL is written in Go; what arrives in a URL only
// picks fields and operators by name and supplies values, which reach the
// database as bound parameters. Nothing from a request is ever spliced into
// SQL text.
package list

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Type is what a field holds, which decides its operators and how values
// are parsed and shown.
type Type int

const (
	Text   Type = iota
	Enum        // one of Options
	Number      // integers or decimals
	Bool
	Time
	Tags // text[]
)

// Op is a comparison, named in URLs.
type Op string

const (
	Eq          Op = "eq"
	Ne          Op = "ne"
	Contains    Op = "contains"
	NotContains Op = "not_contains"
	Starts      Op = "starts"
	Empty       Op = "empty"
	NotEmpty    Op = "not_empty"
	Lt          Op = "lt"
	Le          Op = "le"
	Gt          Op = "gt"
	Ge          Op = "ge"
	IsTrue      Op = "true"
	IsFalse     Op = "false"
	Before      Op = "before"
	After       Op = "after"
	Within      Op = "within" // in the last N (7d, 12h)
	Older       Op = "older"  // more than N ago
	Has         Op = "has"
	Lacks       Op = "lacks"
)

var opLabels = map[Op]string{
	Eq: "is", Ne: "is not", Contains: "contains", NotContains: "does not contain", Starts: "starts with",
	Empty: "is empty", NotEmpty: "is not empty", Lt: "<", Le: "≤", Gt: ">", Ge: "≥",
	IsTrue: "is true", IsFalse: "is false", Before: "before", After: "after",
	Within: "in the last", Older: "more than … ago", Has: "has", Lacks: "lacks",
}

// Label is how the condition builder shows an operator.
func (o Op) Label() string { return opLabels[o] }

// NeedsValue is false for operators that compare against nothing.
func (o Op) NeedsValue() bool {
	switch o {
	case Empty, NotEmpty, IsTrue, IsFalse:
		return false
	}
	return true
}

// Ops lists the operators a type allows, in the order the builder offers
// them.
func (t Type) Ops() []Op {
	switch t {
	case Text:
		return []Op{Contains, Eq, Ne, Starts, NotContains, Empty, NotEmpty}
	case Enum:
		return []Op{Eq, Ne, Empty, NotEmpty}
	case Number:
		return []Op{Eq, Ne, Gt, Ge, Lt, Le, Empty, NotEmpty}
	case Bool:
		return []Op{IsTrue, IsFalse}
	case Time:
		return []Op{Within, Older, After, Before, Empty, NotEmpty}
	case Tags:
		return []Op{Has, Lacks, Empty, NotEmpty}
	}
	return nil
}

// Name is the type's name in templates and data attributes.
func (t Type) Name() string {
	return [...]string{"text", "enum", "number", "bool", "time", "tags"}[t]
}

// AllOps is every operator, for the builder's blank rows, which narrow
// them by type in the browser.
func AllOps() []Op {
	var out []Op
	for _, t := range []Type{Text, Enum, Number, Bool, Time, Tags} {
		for _, o := range t.Ops() {
			if !slices.Contains(out, o) {
				out = append(out, o)
			}
		}
	}
	return out
}

// OpTypes lists the type names that allow o, for data attributes.
func OpTypes(o Op) string {
	var out []string
	for _, t := range []Type{Text, Enum, Number, Bool, Time, Tags} {
		if slices.Contains(t.Ops(), o) {
			out = append(out, t.Name())
		}
	}
	return strings.Join(out, " ")
}

// Option is one value of an Enum field.
type Option struct {
	Value string
	Label string
	Color string // #rrggbb for a colored chip, or ""
}

// Field is one column of a table. Expr is trusted SQL over the table's
// From; it is never built from input.
type Field struct {
	Key   string
	Label string
	Type  Type
	Expr  string
	// ViewerExpr, if set, builds Expr for the current viewer instead
	// (assigned to me, watching), binding what it needs in a.
	ViewerExpr func(a *Args, v Viewer) string
	// SortExpr, if set, is what sorting and grouping order by instead
	// (priorities by rank, not name).
	SortExpr string
	Options  []Option // Enum values, in order
	// MatchExpr, if set on an Enum, is a text[] that "is" and "is not"
	// test membership of instead of comparing with Expr, so one value can
	// stand for others too: a category matches its subcategories' rows.
	MatchExpr string
	// LinkExpr, if set, is SQL for the path the cell links to (relative
	// to the public URL), or NULL for no link.
	LinkExpr string
	Search   bool   // matched by the quick search box
	NoFilter bool   // shown only: not offered in the builder
	NoSort   bool   // sorting by it would be meaningless or slow
	NoGroup  bool   // grouping by it would be meaningless
	Class    string // extra cell class: num, mono, nowrap, small
	Badge    string // names how the server styles the value (job, change...)
}

// Filterable, Sortable and Groupable say what the UI offers.
func (f *Field) Filterable() bool { return !f.NoFilter }
func (f *Field) Sortable() bool   { return !f.NoSort }
func (f *Field) Groupable() bool {
	return !f.NoGroup && f.Type != Tags && f.Type != Time
}

// OptionColor returns the color of an Enum or Tags value, or "".
func (f *Field) OptionColor(v string) string {
	for _, o := range f.Options {
		if o.Value == v {
			return o.Color
		}
	}
	return ""
}

// OptionLabel returns the label of an Enum value, or the value itself.
func (f *Field) OptionLabel(v string) string {
	for _, o := range f.Options {
		if o.Value == v {
			return o.Label
		}
	}
	return v
}

// View is a built-in list a table offers above its rows, such as "Open"
// changes.
type View struct {
	Key   string
	Label string
	Query Query
}

// Viewer is what the current user may see, for a table's Scope.
type Viewer struct {
	// HostIDs are the hosts the user holds viewer on.
	HostIDs []string
	// Global is true when the user holds viewer globally, which covers
	// records that belong to no host.
	Global bool
	// GroupIDs are the host groups the user holds viewer on, for records
	// that belong to groups rather than hosts (alerts).
	GroupIDs []string
	UserID   string
}

// Table is one listable table.
type Table struct {
	Key   string // URL and saved-list key: host, ci, change, job
	Label string // plural, for headings: Hosts
	Noun  string // singular, lower case: host
	// From is the FROM clause, without the keyword. ID is the SQL of a
	// row's id, as text. LinkExpr is SQL for the path of a row's record.
	From     string
	ID       string
	LinkExpr string
	// DimExpr, if set, is a SQL boolean for rows to show faded (revoked
	// hosts, retired CIs).
	DimExpr string
	// EditExpr, if set, is a SQL boolean for rows whose fields may be
	// edited in place (manual CIs); the server still checks roles.
	EditExpr string
	// Scope limits rows to what the viewer may see: it returns a SQL
	// condition, adding its values to a.
	Scope  func(a *Args, v Viewer) string
	Fields []Field
	// Default is the query of a bare URL.
	Default Query
	Views   []View
}

// Field returns the field with the key, or nil.
func (t *Table) Field(key string) *Field {
	for i := range t.Fields {
		if t.Fields[i].Key == key {
			return &t.Fields[i]
		}
	}
	return nil
}

// Validate checks the registry itself, so a typo in a table fails tests
// rather than a request.
func (t *Table) Validate() error {
	seen := map[string]bool{}
	for _, f := range t.Fields {
		if f.Key == "" || f.Label == "" || (f.Expr == "") == (f.ViewerExpr == nil) {
			return fmt.Errorf("%s: field %q is missing a key, label or expression", t.Key, f.Key)
		}
		if seen[f.Key] {
			return fmt.Errorf("%s: field %q is defined twice", t.Key, f.Key)
		}
		seen[f.Key] = true
		if f.Type == Enum && len(f.Options) == 0 {
			return fmt.Errorf("%s: enum field %q has no options", t.Key, f.Key)
		}
	}
	queries := []Query{t.Default}
	for _, v := range t.Views {
		queries = append(queries, v.Query)
	}
	for _, q := range queries {
		if _, problems := Parse(t, q.Values()); len(problems) > 0 {
			return fmt.Errorf("%s: a built-in query is invalid: %s", t.Key, strings.Join(problems, "; "))
		}
		if len(q.Cols) == 0 {
			return fmt.Errorf("%s: a built-in query has no columns", t.Key)
		}
	}
	return nil
}

// forViewer returns the table with the ViewerExpr of each field q uses
// built into Expr. A placeholder may appear many times in a statement, so
// each is bound once; unused ones aren't bound at all, since Postgres
// can't type a parameter nothing refers to.
func (t *Table) forViewer(a *Args, v Viewer, q Query) *Table {
	used := map[string]bool{q.Sort.Field: true, q.GroupBy: true}
	for _, k := range q.Cols {
		used[k] = true
	}
	for _, g := range q.Groups {
		for _, c := range g {
			used[c.Field] = true
		}
	}
	var c *Table
	for i, f := range t.Fields {
		if f.ViewerExpr == nil || !(used[f.Key] || (f.Search && q.Search != "")) {
			continue
		}
		if c == nil {
			cp := *t
			cp.Fields = slices.Clone(t.Fields)
			c = &cp
		}
		c.Fields[i].Expr = "(" + f.ViewerExpr(a, v) + ")"
	}
	if c == nil {
		return t
	}
	return c
}

// Args collects bound parameters while SQL is built.
type Args struct{ vals []any }

// Add binds v and returns its placeholder.
func (a *Args) Add(v any) string {
	a.vals = append(a.vals, v)
	return "$" + strconv.Itoa(len(a.vals))
}

// Values returns what was bound, in placeholder order.
func (a *Args) Values() []any { return a.vals }

// Lookup is a ViewerExpr for a value Go computes rather than SQL (a
// window's next opening, a model's summary): m maps a row's id, as idExpr
// gives it, to the value as text, which is cast to sqlType. Rows m lacks
// read as NULL. Both arrays are bound; only idExpr and sqlType, which come
// from the registry, are SQL.
func Lookup(idExpr, sqlType string, m map[string]string) func(a *Args, v Viewer) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	vals := make([]string, len(keys))
	for i, k := range keys {
		vals[i] = m[k]
	}
	return func(a *Args, _ Viewer) string {
		return "(SELECT x.v::" + sqlType + " FROM unnest(" + a.Add(TextArray(keys)) + "::text[], " +
			a.Add(TextArray(vals)) + "::text[]) AS x(k, v) WHERE x.k = " + idExpr + ")"
	}
}
