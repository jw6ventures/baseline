package server

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jw6ventures/baseline/internal/store"
)

// Project categories and tags (docs/data-model.md §16): admins keep both
// lists in Settings, and pick from them on the project form.

func (s *Server) projectLabelRoutes(mux *http.ServeMux) {
	mux.Handle("GET /settings/project-categories", s.page(adminOnly, s.projectCategories))
	mux.Handle("POST /settings/project-categories", s.page(adminOnly, s.projectCategorySave))
	mux.Handle("POST /settings/project-categories/{id}", s.page(adminOnly, s.projectCategorySave))
	mux.Handle("POST /settings/project-categories/{id}/delete", s.page(adminOnly, s.projectCategoryDelete))
	mux.Handle("GET /settings/project-tags", s.page(adminOnly, s.projectTags))
	mux.Handle("POST /settings/project-tags", s.page(adminOnly, s.projectTagSave))
	mux.Handle("POST /settings/project-tags/{id}", s.page(adminOnly, s.projectTagSave))
	mux.Handle("POST /settings/project-tags/{id}/delete", s.page(adminOnly, s.projectTagDelete))
}

// projectLabels reads the category tree and the tag list.
func (s *Server) projectLabels(ctx context.Context) (projectLabels, error) {
	var l projectLabels
	var err error
	if l.Cats, err = s.store.ListProjectCategories(ctx); err != nil {
		return l, err
	}
	l.Tags, err = s.store.ListProjectTags(ctx)
	return l, err
}

// formColor reads a color input, which always holds one: the "no color"
// box clears it.
func formColor(r *http.Request) (string, bool) {
	if r.FormValue("no_color") == "1" {
		return "", true
	}
	c := strings.ToLower(strings.TrimSpace(r.FormValue("color")))
	return c, store.ColorRe.MatchString(c)
}

// chipStyle colors a category or tag chip: the color as background, with
// black or white text, whichever reads better on it. "" leaves the chip
// plain.
func chipStyle(color string) template.CSS {
	if len(color) != 7 || !store.ColorRe.MatchString(color) {
		return ""
	}
	n, _ := strconv.ParseUint(color[1:], 16, 32)
	r, g, b := float64(n>>16&0xff), float64(n>>8&0xff), float64(n&0xff)
	fg := "#fff"
	if 0.299*r+0.587*g+0.114*b > 150 {
		fg = "#111"
	}
	return template.CSS("background:" + color + ";color:" + fg)
}

// Categories --------------------------------------------------------------------

type projectCategoriesView struct {
	Categories []store.ProjectCategory
	Edit       store.ProjectCategory // the form: empty ID for a new one
	// Parents are where Edit may go: every category but it and its
	// subcategories.
	Parents []store.ProjectCategory
	Notice  string
	Error   string
}

func (s *Server) projectCategoriesPage(w http.ResponseWriter, r *http.Request, v projectCategoriesView, status int) {
	var err error
	if v.Categories, err = s.store.ListProjectCategories(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	// The tree lists subcategories right after their parent, deeper.
	skip := -1
	for _, c := range v.Categories {
		if skip >= 0 && c.Depth > skip {
			continue
		}
		skip = -1
		if v.Edit.ID != "" && c.ID == v.Edit.ID {
			skip = c.Depth
			continue
		}
		v.Parents = append(v.Parents, c)
	}
	s.pages.render(w, status, "project_categories", s.data(r, "Project categories", v))
}

func (s *Server) projectCategories(w http.ResponseWriter, r *http.Request) {
	v := projectCategoriesView{Notice: r.URL.Query().Get("notice")}
	if p := r.URL.Query().Get("parent"); p != "" {
		v.Edit.ParentID = p
	}
	if id := r.URL.Query().Get("edit"); id != "" {
		cats, err := s.store.ListProjectCategories(r.Context())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, c := range cats {
			if c.ID == id {
				v.Edit = c
			}
		}
	}
	s.projectCategoriesPage(w, r, v, http.StatusOK)
}

func (s *Server) projectCategorySave(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	in := store.ProjectCategory{ID: id, ParentID: r.FormValue("parent"), Name: strings.TrimSpace(r.FormValue("name")),
		Description: strings.TrimSpace(r.FormValue("description"))}
	color, ok := formColor(r)
	in.Color = color
	var msg string
	switch {
	case in.Name == "":
		msg = "Enter a name."
	case strings.Contains(in.Name, "/"):
		msg = "A category's name can't contain /, which separates it from its parent."
	case !ok:
		msg = "Pick a color, or tick No color."
	}
	if msg == "" {
		_, err := s.store.SaveProjectCategory(r.Context(), s.actor(r), id, in)
		switch {
		case errors.Is(err, store.ErrConflict):
			msg = "There is already a category named " + in.Name + " there."
		case errors.Is(err, store.ErrCategoryCycle):
			msg = "A category can't go under itself or one of its subcategories."
		case errors.Is(err, store.ErrNotFound) && id != "":
			s.errorPage(w, r, http.StatusNotFound, "No such category.")
			return
		case errors.Is(err, store.ErrNotFound):
			msg = "That parent category no longer exists."
		case err != nil:
			s.serverError(w, r, err)
			return
		}
	}
	if msg != "" {
		s.projectCategoriesPage(w, r, projectCategoriesView{Edit: in, Error: msg}, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, s.url("/settings/project-categories?notice="+url.QueryEscape("Saved "+in.Name+".")), http.StatusSeeOther)
}

func (s *Server) projectCategoryDelete(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteProjectCategory(r.Context(), s.actor(r), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.errorPage(w, r, http.StatusNotFound, "No such category.")
	case errors.Is(err, store.ErrInUse):
		s.projectCategoriesPage(w, r, projectCategoriesView{
			Error: "That category has subcategories: move or delete them first."}, http.StatusConflict)
	case err != nil:
		s.serverError(w, r, err)
	default:
		http.Redirect(w, r, s.url("/settings/project-categories?notice="+
			url.QueryEscape("Deleted. Its projects are uncategorized now.")), http.StatusSeeOther)
	}
}

// Tags ------------------------------------------------------------------------------

type projectTagsView struct {
	Tags   []store.ProjectTag
	Edit   store.ProjectTag // the form: empty ID for a new tag
	Notice string
	Error  string
}

func (s *Server) projectTagsPage(w http.ResponseWriter, r *http.Request, v projectTagsView, status int) {
	var err error
	if v.Tags, err = s.store.ListProjectTags(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.pages.render(w, status, "project_tags", s.data(r, "Project tags", v))
}

func (s *Server) projectTags(w http.ResponseWriter, r *http.Request) {
	v := projectTagsView{Notice: r.URL.Query().Get("notice")}
	if id := r.URL.Query().Get("edit"); id != "" {
		tags, err := s.store.ListProjectTags(r.Context())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, t := range tags {
			if t.ID == id {
				v.Edit = t
			}
		}
	}
	s.projectTagsPage(w, r, v, http.StatusOK)
}

func (s *Server) projectTagSave(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	in := store.ProjectTag{ID: id, Name: strings.TrimSpace(r.FormValue("name")),
		Description: strings.TrimSpace(r.FormValue("description"))}
	color, ok := formColor(r)
	in.Color = color
	var msg string
	switch {
	case in.Name == "":
		msg = "Enter a name."
	case !ok:
		msg = "Pick a color, or tick No color."
	}
	if msg == "" {
		_, err := s.store.SaveProjectTag(r.Context(), s.actor(r), id, in)
		switch {
		case errors.Is(err, store.ErrConflict):
			msg = "There is already a tag named " + in.Name + "."
		case errors.Is(err, store.ErrNotFound):
			s.errorPage(w, r, http.StatusNotFound, "No such tag.")
			return
		case err != nil:
			s.serverError(w, r, err)
			return
		}
	}
	if msg != "" {
		s.projectTagsPage(w, r, projectTagsView{Edit: in, Error: msg}, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, s.url("/settings/project-tags?notice="+url.QueryEscape("Saved "+in.Name+".")), http.StatusSeeOther)
}

func (s *Server) projectTagDelete(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteProjectTag(r.Context(), s.actor(r), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.errorPage(w, r, http.StatusNotFound, "No such tag.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		http.Redirect(w, r, s.url("/settings/project-tags?notice="+url.QueryEscape("Deleted, and taken off its projects.")), http.StatusSeeOther)
	}
}
