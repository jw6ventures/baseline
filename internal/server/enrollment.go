package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/jw6ventures/baseline/internal/pki"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/web"
)

type enrollmentView struct {
	Tokens     []store.EnrollmentToken
	HostGroups []store.HostGroup
	Error      string
	Notice     string
	// Set once, right after creating a token: it is never shown again.
	NewToken   string
	NewName    string
	InstallCmd string
	Gateway    string
	PublicURL  string
	Lifetimes  []lifetime
}

type lifetime struct {
	Value string
	Label string
}

var tokenLifetimes = []lifetime{{"1h", "1 hour"}, {"24h", "1 day"}, {"168h", "7 days"}, {"720h", "30 days"}, {"8760h", "1 year"}}

func (s *Server) enrollment(w http.ResponseWriter, r *http.Request) {
	s.renderEnrollment(w, r, http.StatusOK, enrollmentView{Error: r.URL.Query().Get("error"), Notice: r.URL.Query().Get("notice")})
}

func (s *Server) renderEnrollment(w http.ResponseWriter, r *http.Request, status int, v enrollmentView) {
	var err error
	if v.Tokens, err = s.store.ListEnrollmentTokens(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	if v.HostGroups, err = s.store.ListHostGroups(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	v.Gateway, v.PublicURL, v.Lifetimes = s.cfg.GRPCPublicAddr, s.cfg.PublicURL.String(), tokenLifetimes
	s.pages.render(w, status, "enrollment", s.data(r, "Enrollment", v))
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, http.StatusBadRequest, "Bad form.")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	life, err := time.ParseDuration(r.FormValue("lifetime"))
	if name == "" || err != nil || !slices.ContainsFunc(tokenLifetimes, func(l lifetime) bool { return l.Value == r.FormValue("lifetime") }) {
		s.renderEnrollment(w, r, http.StatusBadRequest, enrollmentView{Error: "Give the token a name and pick how long it lasts."})
		return
	}
	maxUses := 0
	if v := strings.TrimSpace(r.FormValue("max_uses")); v != "" {
		if maxUses, err = strconv.Atoi(v); err != nil || maxUses < 1 {
			s.renderEnrollment(w, r, http.StatusBadRequest, enrollmentView{Error: "Max uses must be a positive number, or empty for unlimited."})
			return
		}
	}
	secret := pki.NewTokenSecret()
	_, err = s.store.CreateEnrollmentToken(r.Context(), s.actor(r), principal(r).User.ID, store.EnrollmentToken{
		Name: name, MaxUses: maxUses, ExpiresAt: time.Now().Add(life), DefaultGroups: r.Form["group"],
	}, pki.HashTokenSecret(secret))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	token := pki.FormatToken(secret, s.caFP)
	s.renderEnrollment(w, r, http.StatusOK, enrollmentView{
		NewToken: token, NewName: name,
		InstallCmd: fmt.Sprintf("curl -fsSL %s/install.sh | sudo sh -s -- --token %s", s.cfg.PublicURL, token),
	})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	err := s.store.RevokeEnrollmentToken(r.Context(), s.actor(r), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.Redirect(w, r, s.url("/settings/enrollment?error="+urlQueryEscape("That token was already revoked.")), http.StatusSeeOther)
	case err != nil:
		s.serverError(w, r, err)
	default:
		http.Redirect(w, r, s.url("/settings/enrollment?notice="+urlQueryEscape("Token revoked. Hosts it already enrolled keep working.")), http.StatusSeeOther)
	}
}

// install.sh and agent downloads ---------------------------------------------

var installTmpl = template.Must(template.ParseFS(web.FS, "install.sh.tmpl"))

// installScript serves the installer with this server's addresses baked in.
func (s *Server) installScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	installTmpl.Execute(w, map[string]string{
		"PublicURL": s.cfg.PublicURL.String(),
		"Gateway":   s.cfg.GRPCPublicAddr,
		"Version":   s.version,
	})
}

// agentFiles serves the agent binaries shipped in the server image, plus a
// SHA256SUMS that install.sh checks them against.
type agentFiles struct {
	dir  string
	once sync.Once
	sums []byte
}

const agentPrefix = "baseline-agent-linux-"

func (a *agentFiles) checksums() []byte {
	a.once.Do(func() {
		names, _ := filepath.Glob(filepath.Join(a.dir, agentPrefix+"*"))
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			f, err := os.Open(n)
			if err != nil {
				continue
			}
			h := sha256.New()
			_, err = io.Copy(h, f)
			f.Close()
			if err == nil {
				fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(h.Sum(nil)), filepath.Base(n))
			}
		}
		a.sums = []byte(b.String())
	})
	return a.sums
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	switch {
	case name == "SHA256SUMS":
		sums := s.agents.checksums()
		if len(sums) == 0 {
			http.Error(w, "no agent binaries in this server image", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(sums)
	case strings.HasPrefix(name, agentPrefix) && !strings.ContainsAny(name, `/\`) && !strings.Contains(name, ".."):
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, filepath.Join(s.agents.dir, name))
	default:
		http.NotFound(w, r)
	}
}
