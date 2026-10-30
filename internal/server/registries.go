package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/jw6ventures/jw6-go-utils/oidc"

	"github.com/jw6ventures/baseline/internal/registry"
	"github.com/jw6ventures/baseline/internal/store"
)

// RegistryCredentials opens the stored registry logins for the checker:
// host -> {username, secret}. A login that no longer opens (BASELINE_SECRET_KEY
// changed) is skipped, and the registry is asked anonymously.
func RegistryCredentials(ctx context.Context, st *store.Store, secrets *oidc.CookieCodec) (map[string][2]string, error) {
	creds, err := st.ListRegistryCreds(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][2]string{}
	for _, c := range creds {
		var secret string
		if secrets.Open(c.SecretEnc, &secret) == nil {
			out[c.Registry] = [2]string{c.Username, secret}
		}
	}
	return out, nil
}

type registriesView struct {
	Creds  []store.RegistryCred
	Error  string
	Notice string
}

// registries is Settings → Registries: logins for private registries and
// for Docker Hub's higher rate limits. Anonymous is the default.
func (s *Server) registries(w http.ResponseWriter, r *http.Request) {
	creds, err := s.store.ListRegistryCreds(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	q := r.URL.Query()
	s.pages.render(w, http.StatusOK, "registries", s.data(r, "Registries", registriesView{Creds: creds, Error: q.Get("error"), Notice: q.Get("notice")}))
}

func (s *Server) backToRegistries(w http.ResponseWriter, r *http.Request, kind, msg string) {
	http.Redirect(w, r, s.url("/settings/registries?"+kind+"="+url.QueryEscape(msg)), http.StatusSeeOther)
}

func (s *Server) saveRegistry(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.TrimSpace(r.FormValue("registry")))
	user := strings.TrimSpace(r.FormValue("username"))
	secret := r.FormValue("secret")
	// Normalize the way image references do, so "index.docker.io" or a
	// pasted URL lands on the host the checker asks for.
	host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://"), "/")
	if strings.ContainsAny(host, ".:") || host == "localhost" {
		if ref, err := registry.ParseRef(host + "/x/y"); err == nil {
			host = ref.Registry
		}
	}
	if host == "" || user == "" || secret == "" || strings.ContainsAny(host, "/ ") {
		s.backToRegistries(w, r, "error", "Enter a registry host (e.g. ghcr.io), a username and a password or token.")
		return
	}
	sealed, err := s.secrets.Seal(secret, 0)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.SaveRegistryCred(r.Context(), s.actor(r), host, user, sealed); err != nil {
		s.serverError(w, r, err)
		return
	}
	if s.checker != nil {
		s.checker.Trigger()
	}
	s.backToRegistries(w, r, "notice", "Saved the login for "+host+". Its images are checked again now.")
}

func (s *Server) deleteRegistry(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteRegistryCred(r.Context(), s.actor(r), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.backToRegistries(w, r, "error", "That login was already removed.")
	case err != nil:
		s.serverError(w, r, err)
	default:
		s.backToRegistries(w, r, "notice", "Login removed. That registry is asked anonymously from now on.")
	}
}
