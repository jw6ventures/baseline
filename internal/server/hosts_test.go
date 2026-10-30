package server

import (
	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/pki"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

// addHost enrolls a host straight through the store and gives it inventory.
func (h *harness) addHost(name string, groupIDs ...string) store.EnrollResult {
	h.t.Helper()
	ctx := context.Background()
	secret := pki.NewTokenSecret()
	if _, err := h.st.CreateEnrollmentToken(ctx, store.System, "", store.EnrollmentToken{
		Name: "t", ExpiresAt: time.Now().Add(time.Hour), DefaultGroups: groupIDs,
	}, pki.HashTokenSecret(secret)); err != nil {
		h.t.Fatal(err)
	}
	res, err := h.st.Enroll(ctx, store.EnrollRequest{SecretHash: pki.HashTokenSecret(secret), MachineID: name, Hostname: name},
		func(string) (string, time.Time, error) { return "serial-" + name, time.Now().Add(time.Hour), nil })
	if err != nil {
		h.t.Fatal(err)
	}
	for sec, v := range map[string]any{
		model.SectionOS:       model.OS{Hostname: name, PrettyName: "Rocky Linux 9.6 (Blue Onyx)", Kernel: "5.14.0-570"},
		model.SectionHardware: model.Hardware{CPU: model.CPU{Model: "EPYC 7302P", Cores: 16, Threads: 32}, Memory: model.Memory{TotalBytes: 64 << 30}, Disks: []model.Disk{{Name: "nvme0n1", Model: "Micron 7450", SizeBytes: 960 << 30}}},
		model.SectionPackages: model.Packages{Managers: []string{"dnf"}, Packages: []model.Package{{Manager: "dnf", Name: "openssl", Epoch: "1", Version: "3.2.2", Release: "6.el9", Arch: "x86_64"}}},
	} {
		b, hash, _ := model.Encode(v)
		if _, err := h.st.IngestSection(ctx, res.HostID, res.AgentID, sec, hash, b, ""); err != nil {
			h.t.Fatal(err)
		}
	}
	return res
}

func TestHostPagesRespectScope(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	media, _ := h.st.CreateHostGroup(ctx, store.System, "media", "")
	plex := h.addHost("plex", media.ID)
	dns := h.addHost("dns1")
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "media-ops", Role: rbac.Operator, ScopeGroupID: media.ID})

	ops := h.signIn("carl", "media-ops")
	_, body := h.do(ops, "GET", "/hosts", nil)
	if !strings.Contains(body, "plex") || strings.Contains(body, "dns1") {
		t.Fatalf("scoped list:\n%s", body)
	}
	// The audit log spans all groups, so scoped-only users can't read it.
	if resp, _ := h.do(ops, "GET", "/audit", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("scoped user audit: %d", resp.StatusCode)
	}
	// A host outside the user's scope looks like it doesn't exist.
	if resp, _ := h.do(ops, "GET", "/hosts/"+dns.HostID, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("out-of-scope host: %d", resp.StatusCode)
	}
	for _, tab := range []string{"overview", "hardware", "packages", "history", "settings"} {
		resp, body := h.do(ops, "GET", "/hosts/"+plex.HostID+"?tab="+tab, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d\n%s", tab, resp.StatusCode, body)
		}
		want := map[string]string{"overview": "Rocky Linux 9.6", "hardware": "Micron 7450", "packages": "1:3.2.2-6.el9", "history": "First inventory received", "settings": "High security"}[tab]
		if !strings.Contains(body, want) {
			t.Errorf("%s tab lacks %q", tab, want)
		}
	}

	// Operators can refresh; the hub is asked. Offline agents get a notice.
	h.hub.online[plex.AgentID] = true
	resp, _ := h.do(ops, "POST", "/hosts/"+plex.HostID+"/refresh", url.Values{})
	if resp.StatusCode != http.StatusSeeOther || len(h.hub.requested) != 1 || !strings.Contains(resp.Header.Get("Location"), "Refresh+requested") {
		t.Fatalf("refresh: %d %s %v", resp.StatusCode, resp.Header.Get("Location"), h.hub.requested)
	}
	// ...but not revoke, which is admin-only.
	if resp, _ := h.do(ops, "POST", "/hosts/"+plex.HostID+"/revoke", url.Values{}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator revoke: %d", resp.StatusCode)
	}
}

func TestViewerCannotRefresh(t *testing.T) {
	h := newHarness(t)
	host := h.addHost("web1")
	h.st.CreateRoleBinding(context.Background(), store.System, store.RoleBinding{IdPGroup: "viewers", Role: rbac.Viewer})
	v := h.signIn("vic", "viewers")
	if resp, _ := h.do(v, "POST", "/hosts/"+host.HostID+"/refresh", url.Values{}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer refresh: %d", resp.StatusCode)
	}
}

func TestAdminRevokesAndRegroupsHost(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	g, _ := h.st.CreateHostGroup(ctx, store.System, "prod", "")
	host := h.addHost("db1")
	admin := h.signIn("ann", "lab-admins")

	h.do(admin, "POST", "/hosts/"+host.HostID+"/groups", url.Values{"group": {g.ID}})
	if got, _ := h.st.GetHost(ctx, host.HostID); len(got.GroupNames) != 1 || got.GroupNames[0] != "prod" {
		t.Fatalf("groups = %v", got.GroupNames)
	}
	resp, _ := h.do(admin, "POST", "/hosts/"+host.HostID+"/revoke", url.Values{})
	if resp.StatusCode != http.StatusSeeOther || len(h.hub.disconnected) != 1 || h.hub.disconnected[0] != host.AgentID {
		t.Fatalf("revoke: %d %v", resp.StatusCode, h.hub.disconnected)
	}
	if got, _ := h.st.GetHost(ctx, host.HostID); !got.Revoked {
		t.Fatal("not revoked")
	}
	_, body := h.do(admin, "GET", "/hosts/"+host.HostID+"?tab=history", nil)
	if !strings.Contains(body, "groups") {
		t.Fatal("group change missing from history")
	}
}

func TestEnrollmentTokenShownOnce(t *testing.T) {
	h := newHarness(t)
	admin := h.signIn("ann", "lab-admins")
	resp, body := h.do(admin, "POST", "/settings/enrollment/tokens",
		url.Values{"name": {"media servers"}, "lifetime": {"24h"}, "max_uses": {"3"}})
	if resp.StatusCode != 200 {
		t.Fatalf("%d\n%s", resp.StatusCode, body)
	}
	tok := regexp.MustCompile(`baseline1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`).FindString(body)
	if tok == "" || !strings.Contains(body, "/install.sh | sudo sh -s -- --token "+tok) {
		t.Fatalf("token/install command missing:\n%s", body)
	}
	if _, _, err := pki.ParseToken(tok); err != nil {
		t.Fatal(err)
	}
	// The listing afterwards never shows it again.
	_, body = h.do(admin, "GET", "/settings/enrollment", nil)
	if strings.Contains(body, tok) || !strings.Contains(body, "media servers") || !strings.Contains(body, "0 / 3") {
		t.Fatalf("listing:\n%s", body)
	}
	resp, body = h.do(admin, "POST", "/settings/enrollment/tokens", url.Values{"name": {"x"}, "lifetime": {"9999h"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "how long it lasts") {
		t.Fatalf("bad lifetime accepted: %d", resp.StatusCode)
	}
}

func TestInstallScriptAndDownloads(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	resp, body := h.do(c, "GET", "/install.sh", nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "#!/bin/sh") ||
		!strings.Contains(body, `GATEWAY="agent.baseline.example:443"`) || !strings.Contains(body, `SERVER_URL="`+h.ts.URL+`"`) {
		t.Fatalf("install.sh: %d\n%s", resp.StatusCode, body)
	}
	if resp, _ := h.do(c, "GET", "/download/SHA256SUMS", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("sums without binaries: %d", resp.StatusCode)
	}

	os.WriteFile(filepath.Join(h.cfg.AgentDir, "baseline-agent-linux-amd64"), []byte("binary"), 0o755)
	// A new server: the checksum list is computed once per process.
	srv, _ := New(h.cfg, h.st, h.idp, h.hub, make([]byte, 32), &jw6_utils.Utils{LogLevel: jw6_utils.Fatal}, "test")
	// sha256("binary")
	if got := get(srv, "/download/SHA256SUMS"); got != "9a3a45d01531a20e89ac6ae10b0b0beb0492acd7216a368aa062d1a5fecaf9cd  baseline-agent-linux-amd64\n" {
		t.Fatalf("sums = %q", got)
	}
	if got := get(srv, "/download/baseline-agent-linux-amd64"); got != "binary" {
		t.Fatalf("binary = %q", got)
	}
	if got := get(srv, "/download/baseline-agent-linux-..%2f..%2fetc%2fpasswd"); got == "binary" || strings.Contains(got, "root:") {
		t.Fatal("path traversal")
	}
}

func get(srv *Server, path string) string {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
	srv.Handler().ServeHTTP(rec, req)
	return rec.Body.String()
}
