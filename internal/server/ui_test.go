package server

import (
	"slices"
	"testing"

	"github.com/jw6ventures/baseline/internal/list"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestHideEmptyColumns(t *testing.T) {
	name, cluster, groups, num := &list.Field{Key: "name"}, &list.Field{Key: "cluster"}, &list.Field{Key: "groups"}, &list.Field{Key: "n"}
	v := &listView{
		Header:  []headerCell{{Label: "Host"}, {Label: "Cluster"}, {Label: "Groups"}, {Label: "N"}},
		Colspan: 5,
		Rows: []rowView{
			{Cells: []cellView{{Field: name, Text: "a"}, {Field: cluster}, {Field: groups}, {Field: num, Text: "0", Raw: "0"}}},
			{Cells: []cellView{{Field: name, Text: "b"}, {Field: cluster}, {Field: groups, Tags: []string{"media"}}, {Field: num, Text: "2", Raw: "2"}}},
		},
	}
	v.hideEmptyColumns(list.Query{Sort: list.Sort{Field: "name"}})
	if !slices.Equal(v.HiddenEmpty, []string{"Cluster"}) || len(v.Header) != 3 || v.Colspan != 4 {
		t.Fatalf("hidden %v, header %v, colspan %d", v.HiddenEmpty, v.Header, v.Colspan)
	}
	for _, r := range v.Rows {
		if len(r.Cells) != 3 || r.Cells[1].Field != groups {
			t.Fatalf("cells %+v", r.Cells)
		}
	}

	// The sorted column stays even when it's empty.
	v = &listView{Header: []headerCell{{Label: "Host"}, {Label: "Cluster", Sorted: true}}, Colspan: 2,
		Rows: []rowView{{Cells: []cellView{{Field: name, Text: "a"}, {Field: cluster}}}}}
	v.hideEmptyColumns(list.Query{Sort: list.Sort{Field: "cluster"}})
	if len(v.HiddenEmpty) != 0 || len(v.Header) != 2 {
		t.Fatalf("sorted column hidden: %v", v.HiddenEmpty)
	}
}

func TestHostTabsSkipUnreportedSections(t *testing.T) {
	keys := func(tabs []hostTab) (main, more []string) {
		for _, t := range tabs {
			if t.More {
				more = append(more, t.Key)
			} else {
				main = append(main, t.Key)
			}
		}
		return
	}
	h := store.Host{ID: "h1"}
	main, more := keys(tabsFor(h, []string{model.SectionOS, model.SectionPackages}, false, false))
	for _, k := range []string{"services", "ports", "certificates", "containers", "stacks"} {
		if slices.Contains(main, k) {
			t.Errorf("tab %s shown before its section was reported: %v", k, main)
		}
	}
	if !slices.Equal(more, []string{"jobs", "history", "settings"}) {
		t.Errorf("more: %v", more)
	}
	main, _ = keys(tabsFor(h, []string{model.SectionServices, model.SectionPorts, model.SectionCerts, model.SectionContainers}, false, false))
	for _, k := range []string{"services", "ports", "certificates", "containers"} {
		if !slices.Contains(main, k) {
			t.Errorf("tab %s missing: %v", k, main)
		}
	}
}
