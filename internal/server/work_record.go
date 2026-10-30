package server

import (
	"net/url"
	"slices"
	"time"

	"github.com/jw6ventures/baseline/internal/inventory"
	"github.com/jw6ventures/baseline/internal/store"
)

// The work item record view (docs/data-model.md §8): a header with the key
// fields and transitions, the view layout's sections, related lists as
// tabs and one activity stream of comments, work notes and history.

// headerFields are the core fields the header shows, left out of the
// view layout's sections so they don't show twice.
var headerFields = []string{"priority", "assignee", "due"}

// dropHeaderFields hides the header's fields from the sections.
func dropHeaderFields(secs []formSection) {
	for i := range secs {
		secs[i].Empty = true
		for j := range secs[i].Items {
			it := &secs[i].Items[j]
			if slices.Contains(headerFields, it.Core) {
				it.Empty = true
			}
			secs[i].Empty = secs[i].Empty && it.Empty
		}
	}
}

// relTab is one related list on the record view.
type relTab struct {
	Key   string
	Label string
	Count int
}

// relTabKeys are the related lists, in the order they show.
var relTabKeys = []string{"cis", "changes", "links", "children", "slas"}

var relTabLabels = map[string]string{
	"cis": "Configuration items", "changes": "Changes", "links": "Linked items", "children": "Child items",
	"slas": "SLAs",
}

// relTabs lists the related lists with their counts, and picks the open
// one: asked for one, or else the first with rows.
func relTabs(v *workItemView, asked string) {
	counts := map[string]int{"cis": len(v.CIs), "changes": len(v.Changes), "links": len(v.Links), "children": len(v.Children),
		"slas": len(v.SLAs)}
	for _, k := range relTabKeys {
		v.RelTabs = append(v.RelTabs, relTab{Key: k, Label: relTabLabels[k], Count: counts[k]})
	}
	if slices.Contains(relTabKeys, asked) {
		v.Rel = asked
		return
	}
	v.Rel = relTabKeys[0]
	for _, t := range v.RelTabs {
		if t.Count > 0 {
			v.Rel = t.Key
			return
		}
	}
}

// Activity stream filters.
const (
	activityAll      = "all"
	activityComments = "comments"
	activityNotes    = "notes"
	activityHistory  = "history"
)

type activityFilter struct {
	Key   string
	Label string
	Count int
}

// activityEntry is a comment, a work note or a history entry.
type activityEntry struct {
	At      time.Time
	Kind    string // comment | note | created | transition | migration | change
	Comment *store.Comment
	Event   *store.ItemEvent
}

// Move is the status change a transition or migration made, nil for none.
func (e activityEntry) Move() *inventory.Change {
	if e.Event == nil {
		return nil
	}
	for i, c := range e.Event.Diff.Changed {
		if c.Field == "status" {
			return &e.Event.Diff.Changed[i]
		}
	}
	return nil
}

// Rest is what else a history entry changed, beyond the status move.
func (e activityEntry) Rest() inventory.Diff {
	if e.Event == nil {
		return inventory.Diff{}
	}
	d := e.Event.Diff
	d.Changed = slices.DeleteFunc(slices.Clone(d.Changed), func(c inventory.Change) bool { return c.Field == "status" })
	return d
}

// RestEmpty reports whether Rest has nothing to show.
func (e activityEntry) RestEmpty() bool {
	d := e.Rest()
	return len(d.Changed) == 0 && len(d.Added) == 0 && len(d.Removed) == 0
}

func (e activityEntry) group() string {
	switch e.Kind {
	case "comment":
		return activityComments
	case "note":
		return activityNotes
	}
	return activityHistory
}

// activityStream merges comments and history, newest first, and keeps
// the entries the filter asks for.
func activityStream(comments []store.Comment, history []store.ItemEvent, filter string) ([]activityEntry, []activityFilter, string) {
	var all []activityEntry
	for i := range comments {
		c := &comments[i]
		kind := "comment"
		if c.Internal {
			kind = "note"
		}
		all = append(all, activityEntry{At: c.At, Kind: kind, Comment: c})
	}
	for i := range history {
		e := &history[i]
		kind := "change"
		switch {
		case e.Initial:
			kind = "created"
		case e.Migration != "":
			kind = "migration"
		case e.Transition != "":
			kind = "transition"
		}
		all = append(all, activityEntry{At: e.At, Kind: kind, Event: e})
	}
	// Newest first; on a tie a comment goes above the history entry
	// that the same transition wrote.
	slices.SortStableFunc(all, func(a, b activityEntry) int {
		if c := b.At.Compare(a.At); c != 0 {
			return c
		}
		return boolOrder(a.Comment == nil, b.Comment == nil)
	})
	filters := []activityFilter{{Key: activityAll, Label: "All", Count: len(all)},
		{Key: activityComments, Label: "Comments"}, {Key: activityNotes, Label: "Work notes"}, {Key: activityHistory, Label: "History"}}
	for _, e := range all {
		for i := range filters {
			if filters[i].Key == e.group() {
				filters[i].Count++
			}
		}
	}
	if !slices.ContainsFunc(filters, func(f activityFilter) bool { return f.Key == filter }) {
		filter = activityAll
	}
	if filter == activityAll {
		return all, filters, filter
	}
	var out []activityEntry
	for _, e := range all {
		if e.group() == filter {
			out = append(out, e)
		}
	}
	return out, filters, filter
}

// boolOrder sorts false before true.
func boolOrder(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	}
	return 1
}

// RelURL is the record view with a related list open, keeping the
// activity filter.
func (v workItemView) RelURL(key string) string {
	return v.viewURL(key, v.Activity)
}

// ActivityURL is the record view with an activity filter, keeping the
// related list.
func (v workItemView) ActivityURL(key string) string {
	return v.viewURL(v.Rel, key)
}

func (v workItemView) viewURL(rel, activity string) string {
	q := url.Values{}
	q.Set("rel", rel)
	if activity != activityAll {
		q.Set("activity", activity)
	}
	return "/work/" + v.Item.Ref() + "?" + q.Encode()
}
