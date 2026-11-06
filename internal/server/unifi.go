package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/unifi"
)

// UniFiPoller polls UniFi consoles (internal/unifipoll).
type UniFiPoller interface {
	Trigger()
	PollNow(ctx context.Context, id string) error
}

func (s *Server) SetUniFi(p UniFiPoller) { s.unifi = p }

type unifiHost struct {
	ID, Name string
	Capable  bool // its agent reports it can poll a console
}

type unifiView struct {
	Consoles []unifiConsoleView
	Hosts    []unifiHost
	Edit     store.UniFiController // the console being edited; zero for a new one
	Error    string
	Notice   string
}

type unifiConsoleView struct {
	store.UniFiController
	Fingerprint string // pinned, as browsers show it
	NoteLines   []string
}

// unifiSettings is Settings → UniFi: the consoles Baseline reads devices,
// clients and Protect cameras from, and where each is polled from.
func (s *Server) unifiSettings(w http.ResponseWriter, r *http.Request) {
	cs, err := s.store.ListUniFiControllers(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	hosts, err := s.store.ListHosts(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	q := r.URL.Query()
	v := unifiView{Error: q.Get("error"), Notice: q.Get("notice")}
	for _, h := range hosts {
		if !h.Revoked && !h.ClusterAgent() {
			v.Hosts = append(v.Hosts, unifiHost{ID: h.ID, Name: h.Hostname, Capable: slices.Contains(h.Capabilities, model.CapUniFi)})
		}
	}
	for _, c := range cs {
		cv := unifiConsoleView{UniFiController: c, Fingerprint: unifi.FormatFingerprint(c.Config.TLSFingerprint)}
		if c.Notes != "" {
			cv.NoteLines = strings.Split(c.Notes, "\n")
		}
		v.Consoles = append(v.Consoles, cv)
		if id := r.PathValue("id"); id != "" && id == c.ID {
			v.Edit = c
		}
	}
	if r.PathValue("id") != "" && v.Edit.ID == "" {
		s.backToUniFi(w, r, "error", "That console was removed.")
		return
	}
	s.pages.render(w, http.StatusOK, "unifi", s.data(r, "UniFi", v))
}

func (s *Server) backToUniFi(w http.ResponseWriter, r *http.Request, kind, msg string) {
	http.Redirect(w, r, s.url("/settings/unifi?"+kind+"="+url.QueryEscape(msg)), http.StatusSeeOther)
}

func (s *Server) unifiSave(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c := store.UniFiController{ID: id, Name: strings.TrimSpace(r.FormValue("name")), RunOn: r.FormValue("run_on"),
		Enabled: r.FormValue("enabled") != ""}
	cfg, err := unifi.Config{URL: r.FormValue("url"), TLSFingerprint: r.FormValue("tls_fingerprint"),
		Sites: strings.Split(r.FormValue("sites"), ","), Protect: r.FormValue("protect") != ""}.Check()
	if err == nil && c.Name == "" {
		err = errors.New("enter a name")
	}
	if err == nil && c.RunOn != "" {
		hosts, herr := s.store.ListHosts(r.Context())
		if herr != nil {
			s.serverError(w, r, herr)
			return
		}
		if !slices.ContainsFunc(hosts, func(h store.Host) bool { return h.ID == c.RunOn && !h.Revoked && !h.ClusterAgent() }) {
			err = errors.New("pick a host to poll from, or the server")
		}
	}
	key := strings.TrimSpace(r.FormValue("api_key"))
	if err == nil && id == "" && key == "" {
		err = errors.New("enter the API key made on the console (UniFi Network → Settings → Control Plane → Integrations)")
	}
	if err != nil {
		back := "/settings/unifi"
		if id != "" {
			back += "/" + id
		}
		http.Redirect(w, r, s.url(back+"?error="+url.QueryEscape(err.Error())), http.StatusSeeOther)
		return
	}
	c.Config = cfg
	if key != "" {
		if c.APIKeyEnc, err = s.secrets.Seal(key, 0); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	if _, err := s.store.SaveUniFiController(r.Context(), s.actor(r), c); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.backToUniFi(w, r, "error", "That console was removed.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	if s.unifi != nil {
		s.unifi.Trigger()
	}
	s.backToUniFi(w, r, "notice", "Saved "+c.Name+". It is polled within a minute.")
}

func (s *Server) unifiDelete(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteUniFiController(r.Context(), s.actor(r), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.backToUniFi(w, r, "error", "That console was already removed.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToUniFi(w, r, "notice", "Console removed. The CIs it reported stay, and turn missing within the hour.")
	}
}

func (s *Server) unifiPoll(w http.ResponseWriter, r *http.Request) {
	if s.unifi == nil {
		s.backToUniFi(w, r, "error", "Polling isn't running on this server.")
		return
	}
	if err := s.unifi.PollNow(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.backToUniFi(w, r, "error", "That console was removed.")
			return
		}
		s.backToUniFi(w, r, "error", "The poll failed: "+err.Error())
		return
	}
	s.backToUniFi(w, r, "notice", "Polled. The console's devices and clients are up to date.")
}
