package server

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/store"
)

// Custom fields on work item screens: the create screen (also used to
// edit) and the view screen lay out core and custom fields by the
// project's layout for the item's type.

// customField is a custom field on a screen, with its value ready for an
// input or for reading.
type customField struct {
	*store.FormField
	Name    string   // the input's name, cf_<key>
	Value   string   // input text
	Values  []string // multiselect choices
	Checked bool     // bool
	Display string   // read text
	Link    string   // read link under the public URL, "" for none
	Hidden  bool     // a CI the user may not see: kept as is, not shown
}

// formItem is a core field (Core set) or a custom field on a screen.
type formItem struct {
	Core  string
	Label string
	Field *customField
	Empty bool // nothing to show when reading
}

type formSection struct {
	Title     string
	Columns   int
	Collapsed bool
	Items     []formItem
	Empty     bool // every item empty
}

// inputText is a stored value as an input shows it.
func (s *Server) inputText(f store.FieldDef, v any) string {
	if t, ok := v.(string); ok && f.Type == store.FieldDatetime {
		if at, err := time.Parse(time.RFC3339, t); err == nil {
			return at.In(s.cfg.Location).Format("2006-01-02T15:04")
		}
	}
	return f.Text(v)
}

// itemCoreEmpty reports whether a core field has nothing to show.
func itemCoreEmpty(it store.WorkItem, name string) bool {
	switch name {
	case "title":
		return true // the page's heading
	case "description":
		return it.Description == ""
	case "impact":
		return it.Impact == ""
	case "urgency":
		return it.Urgency == ""
	case "parent":
		return it.ParentRef == ""
	case "estimate":
		return it.Estimate == nil
	case "due":
		return it.DueAt.IsZero()
	}
	return false
}

// screenSections fills a resolved screen with an item's values.
func (s *Server) screenSections(r *http.Request, form store.Form, it store.WorkItem) ([]formSection, error) {
	ctx := r.Context()
	var users map[string]string
	var hostIDs []string
	var hostsLoaded bool
	var out []formSection
	for _, sec := range form.Sections {
		fs := formSection{Title: sec.Title, Columns: sec.Columns, Collapsed: sec.Collapsed, Empty: true}
		for _, item := range sec.Items {
			fi := formItem{Core: item.Core}
			if item.Core != "" {
				fi.Label, fi.Empty = coreFieldLabels[item.Core], itemCoreEmpty(it, item.Core)
				fs.Items = append(fs.Items, fi)
				fs.Empty = fs.Empty && fi.Empty
				continue
			}
			f := item.Field
			v := it.Custom[f.Key]
			cf := &customField{FormField: f, Name: "cf_" + f.Key, Value: s.inputText(f.FieldDef, v), Display: f.Text(v)}
			switch x := v.(type) {
			case bool:
				cf.Checked = x
			case []any:
				for _, o := range x {
					if str, ok := o.(string); ok {
						cf.Values = append(cf.Values, str)
					}
				}
			}
			id, _ := v.(string)
			switch {
			case f.Type == store.FieldURL && id != "":
				cf.Link = id
			case f.Type == store.FieldDatetime && id != "":
				if at, err := time.Parse(time.RFC3339, id); err == nil {
					cf.Display = at.In(s.cfg.Location).Format("2006-01-02 15:04 MST")
				}
			case f.Type == store.FieldUser && id != "":
				if users == nil {
					list, err := s.store.ListUsers(ctx)
					if err != nil {
						return nil, err
					}
					users = map[string]string{}
					for _, u := range list {
						users[u.ID] = u.DisplayName()
					}
				}
				if name, ok := users[id]; ok {
					cf.Display = name
				} else {
					cf.Display = "a user who no longer exists"
				}
			case f.Type == store.FieldItem && id != "":
				other, err := s.store.GetWorkItem(ctx, id)
				if errors.Is(err, store.ErrNotFound) {
					cf.Display = "an item that no longer exists"
					break
				}
				if err != nil {
					return nil, err
				}
				cf.Value, cf.Display, cf.Link = other.Ref(), other.Ref()+" "+other.Title, "/work/"+other.Ref()
			case f.Type == store.FieldCI && id != "":
				if !hostsLoaded {
					var err error
					if hostIDs, err = s.ciHostIDs(r); err != nil {
						return nil, err
					}
					hostsLoaded = true
				}
				c, err := s.store.GetCI(ctx, id)
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					return nil, err
				}
				switch {
				case errors.Is(err, store.ErrNotFound):
					cf.Display = "a CI that no longer exists"
				case canSeeCI(c, hostIDs):
					cf.Display, cf.Link = c.Name, ciLink(c)
				default:
					cf.Display, cf.Hidden = "a CI you can't see", true
				}
			}
			fi.Label, fi.Field, fi.Empty = f.Label, cf, v == nil
			fs.Items = append(fs.Items, fi)
			fs.Empty = fs.Empty && fi.Empty
		}
		out = append(out, fs)
	}
	return out, nil
}

// customInput reads a screen's custom fields from a form. It returns a
// value for every field on the screen, nil to clear one. current is the
// item's values before the edit: a CI the user can't see may stay as it is
// but not be newly picked.
func (s *Server) customInput(r *http.Request, form store.Form, current map[string]any) (map[string]any, error) {
	ctx := r.Context()
	out := map[string]any{}
	var hostIDs []string
	var hostsLoaded bool
	var users []store.User
	for _, f := range form.Fields {
		raw := r.Form["cf_"+f.Key]
		if f.Type == store.FieldItem {
			if ref := strings.TrimSpace(strings.Join(raw, "")); ref != "" {
				other, err := s.store.GetWorkItemByRef(ctx, ref)
				if errors.Is(err, store.ErrNotFound) {
					return out, errBadInput(f.Label + ": there's no work item " + strings.ToUpper(ref) + ".")
				}
				if err != nil {
					return out, err
				}
				raw = []string{other.ID}
			}
		}
		v, err := f.Parse(raw, s.cfg.Location)
		var bad store.ErrFieldValue
		if errors.As(err, &bad) {
			return out, errBadInput(bad.Error() + ".")
		}
		if err != nil {
			return out, err
		}
		if v == nil && f.Required && f.Type != store.FieldBool {
			return out, errBadInput(f.Label + " is required.")
		}
		id, _ := v.(string)
		cur, _ := current[f.Key].(string)
		switch {
		case id == "":
		case f.Type == store.FieldUser:
			if users == nil {
				if users, err = s.store.ListUsers(ctx); err != nil {
					return out, err
				}
			}
			if !slices.ContainsFunc(users, func(u store.User) bool { return u.ID == id }) {
				return out, errBadInput(f.Label + ": that user no longer exists.")
			}
		case f.Type == store.FieldCI && cur != id:
			if !hostsLoaded {
				if hostIDs, err = s.ciHostIDs(r); err != nil {
					return out, err
				}
				hostsLoaded = true
			}
			c, err := s.store.GetCI(ctx, id)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return out, err
			}
			if err != nil || !canSeeCI(c, hostIDs) {
				return out, errBadInput(f.Label + ": pick a CI.")
			}
		}
		out[f.Key] = v
	}
	return out, nil
}

// withCustom returns current with values laid over it, for showing a form
// again as typed.
func withCustom(current, values map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range current {
		out[k] = v
	}
	for k, v := range values {
		if v == nil {
			delete(out, k)
		} else {
			out[k] = v
		}
	}
	return out
}

// customDefaults are the defaults of a screen's fields, for a new item.
func customDefaults(form store.Form) map[string]any {
	out := map[string]any{}
	for _, f := range form.Fields {
		if f.Default != nil {
			out[f.Key] = f.Default
		}
	}
	return out
}
