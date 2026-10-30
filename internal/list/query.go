package list

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Cond is one condition: a field, an operator and a value.
type Cond struct {
	Field string `json:"field"`
	Op    Op     `json:"op"`
	Value string `json:"value"`
}

// Sort orders rows by one field.
type Sort struct {
	Field string `json:"field"`
	Desc  bool   `json:"desc"`
}

// Query is everything a list URL says. Groups are ORed together and the
// conditions inside a group are ANDed, which is enough for any boolean
// filter and keeps the builder flat.
type Query struct {
	Groups  [][]Cond
	Search  string // quick search over the table's Search fields
	Cols    []string
	Sort    Sort
	GroupBy string
	Page    int    // from 1
	List    string // the saved list it came from, for the heading
}

// URL parameters. Conditions are parallel lists, so the builder works as a
// plain GET form: cf (field), co (operator), cv (value) and cg (group,
// from 0; missing means 0).
const (
	pField = "cf"
	pOp    = "co"
	pValue = "cv"
	pGroup = "cg"
)

// keys are the parameters that make a URL a list URL: without any of them
// the table's default applies.
var keys = []string{pField, "q", "cols", "sort", "group", "page", "list"}

// IsBare reports whether v holds no list parameters.
func IsBare(v url.Values) bool {
	for _, k := range keys {
		if v.Has(k) {
			return false
		}
	}
	return true
}

// Parse reads a query from URL values, checked against the table. Anything
// the registry doesn't allow is dropped and described in problems, so a
// stale link still opens.
func Parse(t *Table, v url.Values) (q Query, problems []string) {
	if IsBare(v) {
		q = t.Default.clone()
		return q, nil
	}
	fields, ops, vals, groups := v[pField], v[pOp], v[pValue], v[pGroup]
	byGroup := map[int][]Cond{}
	var order []int
	for i, key := range fields {
		key = strings.TrimSpace(key)
		if key == "" {
			continue // a blank builder row
		}
		c := Cond{Field: key, Op: Op(at(ops, i)), Value: strings.TrimSpace(at(vals, i))}
		g, _ := strconv.Atoi(at(groups, i))
		f := t.Field(c.Field)
		switch {
		case f == nil || !f.Filterable():
			problems = append(problems, fmt.Sprintf("There is no field %q to filter on.", c.Field))
			continue
		case !slices.Contains(f.Type.Ops(), c.Op):
			problems = append(problems, fmt.Sprintf("%s can't be compared with %q.", f.Label, c.Op))
			continue
		case !c.Op.NeedsValue():
			c.Value = ""
		case c.Value == "":
			continue // a blank row whose field was picked but not filled in
		}
		if err := checkValue(f, c); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if _, ok := byGroup[g]; !ok {
			order = append(order, g)
		}
		byGroup[g] = append(byGroup[g], c)
	}
	slices.Sort(order)
	for _, g := range order {
		q.Groups = append(q.Groups, byGroup[g])
	}

	q.Search = strings.TrimSpace(v.Get("q"))
	// cols is one comma-separated value in links, or one value per
	// checkbox from the column picker.
	for _, key := range strings.Split(strings.Join(v["cols"], ","), ",") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if t.Field(key) == nil {
			problems = append(problems, fmt.Sprintf("There is no column %q.", key))
			continue
		}
		if !slices.Contains(q.Cols, key) {
			q.Cols = append(q.Cols, key)
		}
	}
	if len(q.Cols) == 0 {
		q.Cols = slices.Clone(t.Default.Cols)
	}
	q.Sort = t.Default.Sort
	if s := v.Get("sort"); s != "" {
		key, desc := strings.CutPrefix(s, "-")
		if f := t.Field(key); f != nil && f.Sortable() {
			q.Sort = Sort{Field: key, Desc: desc}
		} else {
			problems = append(problems, fmt.Sprintf("Can't sort by %q.", key))
		}
	}
	if g := v.Get("group"); g != "" {
		if f := t.Field(g); f != nil && f.Groupable() {
			q.GroupBy = g
		} else {
			problems = append(problems, fmt.Sprintf("Can't group by %q.", g))
		}
	}
	if p, err := strconv.Atoi(v.Get("page")); err == nil && p > 1 {
		q.Page = p
	}
	q.List = v.Get("list")
	return q, problems
}

func at(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return ""
}

// checkValue rejects values that can't be compared with the field, so the
// database never sees them.
func checkValue(f *Field, c Cond) error {
	if !c.Op.NeedsValue() {
		return nil
	}
	switch f.Type {
	case Enum:
		for _, o := range f.Options {
			if o.Value == c.Value {
				return nil
			}
		}
		return fmt.Errorf("%q isn't a value of %s.", c.Value, f.Label)
	case Number:
		if _, err := strconv.ParseFloat(c.Value, 64); err != nil {
			return fmt.Errorf("%s needs a number, not %q.", f.Label, c.Value)
		}
	case Time:
		switch c.Op {
		case Within, Older:
			if _, err := ParseAge(c.Value); err != nil {
				return fmt.Errorf("%s: %v", f.Label, err)
			}
		default:
			if _, err := parseDate(c.Value, nil); err != nil {
				return fmt.Errorf("%s: %v", f.Label, err)
			}
		}
	}
	return nil
}

func (q Query) clone() Query {
	c := q
	c.Groups = make([][]Cond, len(q.Groups))
	for i, g := range q.Groups {
		c.Groups[i] = slices.Clone(g)
	}
	c.Cols = slices.Clone(q.Cols)
	return c
}

// Values encodes the query as URL values. The sort is always written, so
// a list URL is never bare and never falls back to the table's default.
func (q Query) Values() url.Values {
	v := url.Values{}
	for g, conds := range q.Groups {
		for _, c := range conds {
			v.Add(pField, c.Field)
			v.Add(pOp, string(c.Op))
			v.Add(pValue, c.Value)
			v.Add(pGroup, strconv.Itoa(g))
		}
	}
	if q.Search != "" {
		v.Set("q", q.Search)
	}
	if len(q.Cols) > 0 {
		v.Set("cols", strings.Join(q.Cols, ","))
	}
	s := q.Sort.Field
	if q.Sort.Desc {
		s = "-" + s
	}
	v.Set("sort", s)
	if q.GroupBy != "" {
		v.Set("group", q.GroupBy)
	}
	if q.Page > 1 {
		v.Set("page", strconv.Itoa(q.Page))
	}
	if q.List != "" {
		v.Set("list", q.List)
	}
	return v
}

// Encode is Values as a query string.
func (q Query) Encode() string { return q.Values().Encode() }

// Conditions is the filter alone, as a query string, to compare queries
// by what they select.
func (q Query) Conditions() string {
	v := Query{Groups: q.Groups}.Values()
	v.Del("sort")
	return v.Encode()
}

// With adds c to every group (or starts the first), as "show matching"
// and "filter out" do. It returns to page 1.
func (q Query) With(c Cond) Query {
	n := q.clone()
	if len(n.Groups) == 0 {
		n.Groups = [][]Cond{{c}}
	}
	for i := range n.Groups {
		if !slices.Contains(n.Groups[i], c) {
			n.Groups[i] = append(n.Groups[i], c)
		}
	}
	n.Page = 0
	n.List = ""
	return n
}

// Without drops one condition, and its group if that empties it.
func (q Query) Without(group, i int) Query {
	n := q.clone()
	if group < 0 || group >= len(n.Groups) || i < 0 || i >= len(n.Groups[group]) {
		return n
	}
	n.Groups[group] = slices.Delete(n.Groups[group], i, i+1)
	if len(n.Groups[group]) == 0 {
		n.Groups = slices.Delete(n.Groups, group, group+1)
	}
	n.Page = 0
	n.List = ""
	return n
}

// SortedBy sorts by key: ascending, or descending if it already sorts
// ascending by it.
func (q Query) SortedBy(key string) Query {
	n := q.clone()
	n.Sort = Sort{Field: key, Desc: q.Sort.Field == key && !q.Sort.Desc}
	n.Page = 0
	return n
}

// OnPage moves to page p.
func (q Query) OnPage(p int) Query {
	n := q.clone()
	n.Page = p
	return n
}
