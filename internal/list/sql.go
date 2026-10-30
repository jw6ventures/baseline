package list

import (
	"database/sql/driver"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PageSize is how many rows a page shows.
const PageSize = 100

// Statement is a built SELECT and what its columns are. Its columns are,
// in order: the row id, the row link, whether the row is dimmed and whether
// it is editable, then each
// of Cols with its link, the group value if
// Group is set, then the total count and the group's count.
type Statement struct {
	SQL   string
	Args  []any
	Cols  []*Field
	Group *Field
}

// Options carries what building needs besides the query.
type Options struct {
	Viewer Viewer
	Now    time.Time
	Loc    *time.Location // for dates typed into conditions
	Limit  int            // rows; PageSize when 0
	// IDs, if set, limits rows to these ids (bulk actions re-check a
	// selection against the filter and the viewer's scope).
	IDs []string
}

// Build turns a parsed query into SQL. Every value is a bound parameter;
// field and table SQL comes from the registry only.
func Build(t *Table, q Query, o Options) (Statement, error) {
	if o.Limit <= 0 {
		o.Limit = PageSize
	}
	if o.Loc == nil {
		o.Loc = time.UTC
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	a := &Args{}
	t = t.forViewer(a, o.Viewer, q)
	st := Statement{}
	dim := "false"
	if t.DimExpr != "" {
		dim = "COALESCE(" + t.DimExpr + ", false)"
	}
	edit := "false"
	if t.EditExpr != "" {
		edit = "COALESCE(" + t.EditExpr + ", false)"
	}
	sel := []string{t.ID, "COALESCE(" + orNull(t.LinkExpr) + ", '')", dim, edit}
	for _, key := range q.Cols {
		f := t.Field(key)
		if f == nil {
			return st, fmt.Errorf("list %s: no field %q", t.Key, key)
		}
		st.Cols = append(st.Cols, f)
		sel = append(sel, f.Expr, "COALESCE("+orNull(f.LinkExpr)+", '')")
	}
	where, err := whereClause(t, q, o, a)
	if err != nil {
		return st, err
	}
	var order []string
	if q.GroupBy != "" {
		st.Group = t.Field(q.GroupBy)
		if st.Group == nil || !st.Group.Groupable() {
			return st, fmt.Errorf("list %s: can't group by %q", t.Key, q.GroupBy)
		}
		sel = append(sel, st.Group.Expr)
		order = append(order, st.Group.sortExpr()+" NULLS LAST")
	}
	sel = append(sel, "count(*) OVER ()")
	if st.Group != nil {
		sel = append(sel, "count(*) OVER (PARTITION BY "+st.Group.Expr+")")
	}
	if s := t.Field(q.Sort.Field); s != nil && s.Sortable() {
		dir := " ASC NULLS LAST"
		if q.Sort.Desc {
			dir = " DESC NULLS LAST"
		}
		expr := s.sortExpr()
		order = append(order, expr+dir)
	}
	order = append(order, t.ID)
	offset := 0
	if q.Page > 1 {
		offset = (q.Page - 1) * o.Limit
	}
	st.SQL = "SELECT " + strings.Join(sel, ", ") + " FROM " + t.From + " WHERE " + where +
		" ORDER BY " + strings.Join(order, ", ") +
		" LIMIT " + a.Add(o.Limit) + " OFFSET " + a.Add(offset)
	st.Args = a.Values()
	return st, nil
}

// sortExpr is what ordering by f uses.
func (f *Field) sortExpr() string {
	switch {
	case f.SortExpr != "":
		return f.SortExpr
	case f.Type == Text:
		return "lower(" + f.Expr + ")"
	}
	return f.Expr
}

func orNull(expr string) string {
	if expr == "" {
		return "NULL::text"
	}
	return expr
}

func whereClause(t *Table, q Query, o Options, a *Args) (string, error) {
	parts := []string{"true"}
	if t.Scope != nil {
		parts = append(parts, "("+t.Scope(a, o.Viewer)+")")
	}
	if o.IDs != nil {
		parts = append(parts, t.ID+" = ANY("+a.Add(TextArray(o.IDs))+"::text[])")
	}
	var ors []string
	for _, g := range q.Groups {
		var ands []string
		for _, c := range g {
			f := t.Field(c.Field)
			if f == nil || !f.Filterable() {
				return "", fmt.Errorf("list %s: can't filter on %q", t.Key, c.Field)
			}
			s, err := condSQL(f, c, o, a)
			if err != nil {
				return "", err
			}
			ands = append(ands, s)
		}
		if len(ands) > 0 {
			ors = append(ors, "("+strings.Join(ands, " AND ")+")")
		}
	}
	if len(ors) > 0 {
		parts = append(parts, "("+strings.Join(ors, " OR ")+")")
	}
	if q.Search != "" {
		var any []string
		p := a.Add(q.Search)
		for _, f := range t.Fields {
			if !f.Search {
				continue
			}
			if f.Type == Tags {
				any = append(any, "strpos(lower(array_to_string("+f.Expr+", ' ')), lower("+p+")) > 0")
			} else {
				any = append(any, "strpos(lower(COALESCE("+f.Expr+"::text, '')), lower("+p+")) > 0")
			}
		}
		if len(any) > 0 {
			parts = append(parts, "("+strings.Join(any, " OR ")+")")
		}
	}
	return strings.Join(parts, " AND "), nil
}

func condSQL(f *Field, c Cond, o Options, a *Args) (string, error) {
	e := f.Expr
	switch f.Type {
	case Text, Enum:
		if f.MatchExpr != "" {
			switch c.Op {
			case Eq:
				return a.Add(c.Value) + " = ANY(" + f.MatchExpr + ")", nil
			case Ne:
				return "NOT (" + a.Add(c.Value) + " = ANY(COALESCE(" + f.MatchExpr + ", '{}')))", nil
			}
		}
		switch c.Op {
		case Eq:
			return e + " = " + a.Add(c.Value), nil
		case Ne:
			return "COALESCE(" + e + ", '') <> " + a.Add(c.Value), nil
		case Contains:
			return "strpos(lower(COALESCE(" + e + ", '')), lower(" + a.Add(c.Value) + ")) > 0", nil
		case NotContains:
			return "strpos(lower(COALESCE(" + e + ", '')), lower(" + a.Add(c.Value) + ")) = 0", nil
		case Starts:
			return "starts_with(lower(COALESCE(" + e + ", '')), lower(" + a.Add(c.Value) + "))", nil
		case Empty:
			return "COALESCE(" + e + ", '') = ''", nil
		case NotEmpty:
			return "COALESCE(" + e + ", '') <> ''", nil
		}
	case Number:
		if c.Op == Empty {
			return e + " IS NULL", nil
		}
		if c.Op == NotEmpty {
			return e + " IS NOT NULL", nil
		}
		n, err := strconv.ParseFloat(c.Value, 64)
		if err != nil {
			return "", fmt.Errorf("%s needs a number", f.Label)
		}
		if sym, ok := map[Op]string{Eq: "=", Ne: "<>", Lt: "<", Le: "<=", Gt: ">", Ge: ">="}[c.Op]; ok {
			cmp := e + " " + sym + " " + a.Add(n) + "::float8"
			if c.Op == Ne {
				cmp = "(" + e + " IS NULL OR " + cmp + ")"
			}
			return cmp, nil
		}
	case Bool:
		switch c.Op {
		case IsTrue:
			return "COALESCE(" + e + ", false)", nil
		case IsFalse:
			return "NOT COALESCE(" + e + ", false)", nil
		}
	case Time:
		switch c.Op {
		case Empty:
			return e + " IS NULL", nil
		case NotEmpty:
			return e + " IS NOT NULL", nil
		case Within, Older:
			d, err := ParseAge(c.Value)
			if err != nil {
				return "", err
			}
			since := o.Now.Add(-d)
			if c.Op == Within {
				return e + " >= " + a.Add(since), nil
			}
			return e + " < " + a.Add(since), nil
		case Before, After:
			t, err := parseDate(c.Value, o.Loc)
			if err != nil {
				return "", err
			}
			if c.Op == Before {
				return e + " < " + a.Add(t), nil
			}
			return e + " >= " + a.Add(t), nil
		}
	case Tags:
		switch c.Op {
		case Has:
			return a.Add(c.Value) + " = ANY(" + e + ")", nil
		case Lacks:
			return "NOT (" + a.Add(c.Value) + " = ANY(COALESCE(" + e + ", '{}')))", nil
		case Empty:
			return "cardinality(COALESCE(" + e + ", '{}')) = 0", nil
		case NotEmpty:
			return "cardinality(COALESCE(" + e + ", '{}')) > 0", nil
		}
	}
	return "", fmt.Errorf("%s can't be compared with %q", f.Label, c.Op)
}

// TextArray binds strings as a Postgres text[] literal, so the list
// package needs no driver. Compare with = ANY($n::text[]).
type TextArray []string

func (s TextArray) Value() (driver.Value, error) { return s.String(), nil }

func (s TextArray) String() string {
	var b strings.Builder
	b.WriteByte('{')
	for i, v := range s {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

var ageRe = regexp.MustCompile(`^(\d+)\s*([mhdw])$`)

// ParseAge reads a span such as 30m, 12h, 7d or 2w.
func ParseAge(s string) (time.Duration, error) {
	m := ageRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return 0, fmt.Errorf("%q isn't a span like 30m, 12h, 7d or 2w", s)
	}
	n, _ := strconv.Atoi(m[1])
	unit := map[string]time.Duration{"m": time.Minute, "h": time.Hour, "d": 24 * time.Hour, "w": 7 * 24 * time.Hour}[m[2]]
	return time.Duration(n) * unit, nil
}

// parseDate reads 2026-10-01 or 2026-10-01T15:04 in loc (UTC when nil).
func parseDate(s string, loc *time.Location) (time.Time, error) {
	if loc == nil {
		loc = time.UTC
	}
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, strings.TrimSpace(s), loc); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%q isn't a date like 2026-10-01 or 2026-10-01T15:04", s)
}

// Row is one result row. Values hold, per column: string (Text, Enum),
// float64 or nil (Number), bool, time.Time (zero for NULL) or []string.
type Row struct {
	ID         string
	Link       string
	Dim        bool
	Editable   bool
	Values     []any
	Links      []string // per column, "" for none
	Group      any
	GroupCount int
}

// Result is a page of rows and the count of every matching row.
type Result struct {
	Rows  []Row
	Total int
}
