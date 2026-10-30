// Package inventory turns successive snapshots of an inventory section into
// change history (docs/data-model.md §3).
package inventory

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/jw6ventures/baseline/internal/model"
)

// Change is one entry in a section diff.
type Change struct {
	Field string `json:"field"`
	From  any    `json:"from,omitempty"`
	To    any    `json:"to,omitempty"`
}

// Diff is what ci_history.diff holds.
type Diff struct {
	Added   []Change `json:"added,omitempty"`
	Removed []Change `json:"removed,omitempty"`
	Changed []Change `json:"changed,omitempty"`
}

func (d *Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// Compare diffs two payloads of one section. It returns nil when nothing
// changed.
func Compare(section string, before, after []byte) (*Diff, error) {
	var d *Diff
	var err error
	switch {
	case section == model.SectionPackages:
		d, err = comparePackages(before, after)
	case keyedSections[section] != nil:
		d, err = compareKeyed(keyedSections[section], before, after)
	default:
		d, err = compareGeneric(before, after)
	}
	if err != nil || d.Empty() {
		return nil, err
	}
	return d, nil
}

// Packages are compared by manager/name/arch. A name installed in several
// versions at once (kernels) is compared as a set of versions.
func comparePackages(before, after []byte) (*Diff, error) {
	var a, b model.Packages
	if err := json.Unmarshal(before, &a); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(after, &b); err != nil {
		return nil, err
	}
	index := func(ps []model.Package) map[string][]string {
		m := map[string][]string{}
		for _, p := range ps {
			k := p.Manager + "/" + p.Name
			if p.Arch != "" {
				k += "." + p.Arch
			}
			m[k] = append(m[k], p.FullVersion())
		}
		for _, v := range m {
			sort.Strings(v)
		}
		return m
	}
	ia, ib := index(a.Packages), index(b.Packages)
	d := &Diff{}
	for _, k := range sortedKeys(ia, ib) {
		va, vb := ia[k], ib[k]
		switch {
		case len(va) == 0:
			for _, v := range vb {
				d.Added = append(d.Added, Change{Field: k, To: v})
			}
		case len(vb) == 0:
			for _, v := range va {
				d.Removed = append(d.Removed, Change{Field: k, From: v})
			}
		case len(va) == 1 && len(vb) == 1:
			if va[0] != vb[0] {
				d.Changed = append(d.Changed, Change{Field: k, From: va[0], To: vb[0]})
			}
		default:
			for _, v := range vb {
				if !slices.Contains(va, v) {
					d.Added = append(d.Added, Change{Field: k, To: v})
				}
			}
			for _, v := range va {
				if !slices.Contains(vb, v) {
					d.Removed = append(d.Removed, Change{Field: k, From: v})
				}
			}
		}
	}
	return d, nil
}

func compareGeneric(before, after []byte) (*Diff, error) {
	var a, b any
	if err := json.Unmarshal(before, &a); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(after, &b); err != nil {
		return nil, err
	}
	d := &Diff{}
	walk("", a, b, d)
	return d, nil
}

// identityFields name list elements, so a reordered or inserted disk shows
// as one change rather than a cascade by index.
var identityFields = []string{"name", "locator", "mountpoint", "address", "serial", "path", "location"}

// keyedList is a list in a section compared item by item under a key.
// Ignored fields change on their own (a container's state, a service
// starting, a listener's PID) and history is about configuration, so they
// are left out of the comparison; the current state still shows them.
type keyedList struct {
	field string // the section's JSON field holding the list
	// key holds the fields joined with "/" to identify an item; none means
	// the field is a single object, compared field by field.
	key    []string
	ignore []string
}

// keyedSections are compared list by list. Top-level fields not listed are
// skipped: a container's images churn with every pull, and its image ID
// already says what changed.
var keyedSections = map[string][]keyedList{
	model.SectionContainers: {
		{field: "engines", key: []string{"name"}, ignore: []string{"error", "version", "api_version"}},
		{field: "containers", key: []string{"engine", "name"},
			ignore: []string{"state", "health", "exit_code", "restart_count", "started_at", "created"}},
		{field: "stacks", key: []string{"engine", "project"}},
	},
	model.SectionServices: {{field: "units", key: []string{"name"}, ignore: []string{"active", "sub"}}},
	model.SectionPorts:    {{field: "listeners", key: []string{"proto", "addr", "port"}, ignore: []string{"pid"}}},
	model.SectionCerts:    {{field: "certs", key: []string{"location"}}},
	model.SectionVMs: {
		{field: "hypervisors", key: []string{"platform"}, ignore: []string{"error"}},
		{field: "guests", key: []string{"platform", "id"}, ignore: []string{"state"}},
		{field: "storage", key: []string{"name"}},
	},
	// A cluster's version is its upgrade history; readiness comes and goes.
	model.SectionK8s: {
		{field: "cluster", ignore: []string{"name"}},
		{field: "nodes", key: []string{"name"}, ignore: []string{"ready"}},
		{field: "workloads", key: []string{"kind", "namespace", "name"}, ignore: []string{"ready"}},
		{field: "services", key: []string{"namespace", "name"}},
		{field: "ingresses", key: []string{"namespace", "name"}},
	},
}

// Compose files are compared by hash: their content is in the section for
// the UI, but a history entry holding two copies of a file says less than
// "this file changed".
var ignoredDeep = []string{"content", "truncated"}

func compareKeyed(lists []keyedList, before, after []byte) (*Diff, error) {
	var a, b map[string]any
	if err := json.Unmarshal(before, &a); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(after, &b); err != nil {
		return nil, err
	}
	d := &Diff{}
	for _, l := range lists {
		if l.key == nil {
			x, _ := a[l.field].(map[string]any)
			y, _ := b[l.field].(map[string]any)
			for _, f := range l.ignore {
				delete(x, f)
				delete(y, f)
			}
			walk(l.field, x, y, d)
			continue
		}
		ia, ib := index(a[l.field], l), index(b[l.field], l)
		for _, k := range sortedKeys(ia, ib) {
			x, inA := ia[k]
			y, inB := ib[k]
			p := l.field + "[" + k + "]"
			switch {
			case !inA:
				d.Added = append(d.Added, Change{Field: p, To: y})
			case !inB:
				d.Removed = append(d.Removed, Change{Field: p, From: x})
			default:
				walk(p, x, y, d)
			}
		}
	}
	return d, nil
}

// index keys a list's objects, dropping ignored fields.
func index(list any, l keyedList) map[string]any {
	m := map[string]any{}
	items, _ := list.([]any)
	for _, it := range items {
		obj, ok := it.(map[string]any)
		if !ok {
			continue
		}
		var parts []string
		for _, f := range l.key {
			parts = append(parts, fmt.Sprint(obj[f]))
		}
		for _, f := range l.ignore {
			delete(obj, f)
		}
		stripDeep(obj)
		m[strings.Join(parts, "/")] = obj
	}
	return m
}

func stripDeep(v any) {
	switch x := v.(type) {
	case map[string]any:
		for _, f := range ignoredDeep {
			delete(x, f)
		}
		for _, e := range x {
			stripDeep(e)
		}
	case []any:
		for _, e := range x {
			stripDeep(e)
		}
	}
}

func walk(path string, a, b any, d *Diff) {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			break
		}
		for _, k := range sortedKeys(av, bv) {
			x, inA := av[k]
			y, inB := bv[k]
			p := join(path, k)
			switch {
			case !inA:
				d.Added = append(d.Added, Change{Field: p, To: y})
			case !inB:
				d.Removed = append(d.Removed, Change{Field: p, From: x})
			default:
				walk(p, x, y, d)
			}
		}
		return
	case []any:
		bv, ok := b.([]any)
		if !ok {
			break
		}
		if ka, ok := keyed(av); ok {
			if kb, ok := keyed(bv); ok {
				for _, k := range sortedKeys(ka, kb) {
					x, inA := ka[k]
					y, inB := kb[k]
					p := path + "[" + k + "]"
					switch {
					case !inA:
						d.Added = append(d.Added, Change{Field: p, To: y})
					case !inB:
						d.Removed = append(d.Removed, Change{Field: p, From: x})
					default:
						walk(p, x, y, d)
					}
				}
				return
			}
		}
		// Lists of scalars (CPU flags, addresses) compare as sets.
		if scalars(av) && scalars(bv) {
			for _, y := range bv {
				if !slices.ContainsFunc(av, func(x any) bool { return reflect.DeepEqual(x, y) }) {
					d.Added = append(d.Added, Change{Field: path, To: y})
				}
			}
			for _, x := range av {
				if !slices.ContainsFunc(bv, func(y any) bool { return reflect.DeepEqual(x, y) }) {
					d.Removed = append(d.Removed, Change{Field: path, From: x})
				}
			}
			return
		}
	}
	if !reflect.DeepEqual(a, b) {
		d.Changed = append(d.Changed, Change{Field: path, From: a, To: b})
	}
}

// keyed indexes a list of objects by their identity field. It fails if any
// element lacks one or two share it.
func keyed(list []any) (map[string]any, bool) {
	m := map[string]any{}
	for _, e := range list {
		obj, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		var key string
		for _, f := range identityFields {
			if s, ok := obj[f].(string); ok && s != "" {
				key = s
				break
			}
		}
		if key == "" {
			return nil, false
		}
		if _, dup := m[key]; dup {
			return nil, false
		}
		m[key] = obj
	}
	return m, true
}

func scalars(list []any) bool {
	for _, e := range list {
		switch e.(type) {
		case map[string]any, []any:
			return false
		}
	}
	return true
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func sortedKeys[V any](a, b map[string]V) []string {
	seen := map[string]bool{}
	var keys []string
	for _, m := range []map[string]V{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// Summary is a one-line description of a diff for lists and notifications.
func (d *Diff) Summary(section string) string {
	var parts []string
	verb := map[string]string{"added": "added", "removed": "removed", "changed": "changed"}
	if section == model.SectionPackages {
		verb["changed"] = "upgraded or downgraded"
	}
	for _, x := range []struct {
		n    int
		kind string
	}{{len(d.Added), "added"}, {len(d.Removed), "removed"}, {len(d.Changed), "changed"}} {
		if x.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", x.n, verb[x.kind]))
		}
	}
	return strings.Join(parts, ", ")
}
