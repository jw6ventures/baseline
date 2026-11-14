package server

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jw6ventures/baseline/internal/store"
)

type inventorySettingsView struct {
	RetireDays int // 0: never
	MaxDays    int
	Error      string
	Notice     string
}

// inventorySettings is Settings > Inventory: what happens to what
// discovery stops seeing.
func (s *Server) inventorySettings(w http.ResponseWriter, r *http.Request) {
	days, err := s.store.RetireMissingStacksDays(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	q := r.URL.Query()
	s.pages.render(w, http.StatusOK, "inventory_settings", s.data(r, "Inventory", inventorySettingsView{
		RetireDays: days, MaxDays: store.MaxRetireMissingDays, Error: q.Get("error"), Notice: q.Get("notice")}))
}

func (s *Server) backToInventorySettings(w http.ResponseWriter, r *http.Request, kind, msg string) {
	http.Redirect(w, r, s.url("/settings/inventory?"+kind+"="+url.QueryEscape(msg)), http.StatusSeeOther)
}

// inventorySettingsSave sets how many days a Compose stack can be missing
// before it is retired: blank or 0 is never.
func (s *Server) inventorySettingsSave(w http.ResponseWriter, r *http.Request) {
	days := 0
	if r.FormValue("retire_stacks") == "on" {
		raw := strings.TrimSpace(r.FormValue("retire_days"))
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > store.MaxRetireMissingDays {
			s.backToInventorySettings(w, r, "error", "Enter a whole number of days from 1 to "+strconv.Itoa(store.MaxRetireMissingDays)+".")
			return
		}
		days = n
	}
	if err := s.store.SetRetireMissingStacksDays(r.Context(), s.actor(r), days); err != nil {
		s.serverError(w, r, err)
		return
	}
	if days == 0 {
		s.backToInventorySettings(w, r, "notice", "Missing stacks stay missing until you retire or delete them.")
		return
	}
	if s.checker != nil {
		s.checker.Trigger()
	}
	s.backToInventorySettings(w, r, "notice", "Compose stacks missing for more than "+plural(days, "day")+" are now retired as they pass it.")
}
