package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/unifi/unifitest"
	"github.com/jw6ventures/baseline/internal/unifipoll"
)

// unifiCI finds the CI a console's polls keep under a key.
func (h *harness) unifiCI(key string) (id, typ, status string) {
	h.t.Helper()
	err := h.st.DB().QueryRow(`SELECT id, type, status FROM ci WHERE source = 'unifi' AND source_key LIKE '%/' || $1`, key).Scan(&id, &typ, &status)
	if err != nil {
		h.t.Fatalf("CI %s: %v", key, err)
	}
	return id, typ, status
}

func (h *harness) rels(ciID string) string {
	h.t.Helper()
	rels, err := h.st.CIRelationships(context.Background(), ciID)
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, r := range rels {
		s := r.Kind + ">" + r.Other.Name
		if !r.Outgoing {
			s = r.Other.Name + ">" + r.Kind
		}
		if r.Note != "" {
			s += "(" + r.Note + ")"
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

func TestUniFiConsole(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	admin := h.signIn("admin", "lab-admins")
	con := unifitest.New(t)
	con.Lock()
	con.Clients = append(con.Clients, map[string]any{"type": "WIRED", "id": "cl-5", "name": "nas", "macAddress": "02:00:00:00:00:a3", "uplinkDeviceId": "dev-sw"})
	con.Unlock()

	// web1 is a host with the client's MAC on a NIC; the printer is an
	// agentless CI with its MAC typed in another way.
	web1 := h.addHost("web1")
	h.ingest(web1, model.SectionHardware, model.Hardware{NICs: []model.NIC{{Name: "eno1", MAC: "02:00:00:00:00:A1", Kind: "physical"}}})
	printer, err := h.st.CreateCI(ctx, store.System, store.CIInput{Type: "printer", Name: "Office printer", Status: "active", Attrs: map[string]string{"mac": "02-00-00-00-00-A2"}})
	if err != nil {
		t.Fatal(err)
	}

	poller := &unifipoll.Poller{Store: h.st, Open: h.srv.secrets.Open}
	h.srv.SetUniFi(poller)
	resp, body := h.do(admin, "POST", "/settings/unifi", url.Values{"name": {"UDM Pro"}, "url": {con.URL}, "api_key": {unifitest.Key},
		"tls_fingerprint": {con.Fingerprint}, "protect": {"1"}, "enabled": {"1"}})
	if resp.StatusCode != 303 || !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("save: %d %s %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	cs, _ := h.st.ListUniFiControllers(ctx)
	if len(cs) != 1 || cs[0].APIKeyEnc == "" || strings.Contains(cs[0].APIKeyEnc, unifitest.Key) || cs[0].Config.TLSFingerprint != con.Fingerprint {
		t.Fatalf("stored: %+v", cs)
	}
	id := cs[0].ID

	resp, _ = h.do(admin, "POST", "/settings/unifi/"+id+"/poll", url.Values{})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "notice=Polled") {
		t.Fatalf("poll: %s", loc)
	}

	site, typ, _ := h.unifiCI("site:site-1")
	gw, _, _ := h.unifiCI("mac:f4:e2:c6:00:00:01")
	sw, _, _ := h.unifiCI("mac:f4:e2:c6:00:00:02")
	ap, _, _ := h.unifiCI("mac:f4:e2:c6:00:00:03")
	cam, camType, _ := h.unifiCI("mac:02:00:00:00:00:c1")
	wcam, _, _ := h.unifiCI("mac:02:00:00:00:00:c2")
	nas, nasType, _ := h.unifiCI("mac:02:00:00:00:00:a3")
	if typ != "site" || camType != "camera" || nasType != "network_client" {
		t.Fatalf("types: %s %s %s", typ, camType, nasType)
	}
	var unifiCIs int
	h.st.DB().QueryRow(`SELECT count(*) FROM ci WHERE source = 'unifi'`).Scan(&unifiCIs)
	// site, 3 devices, 2 cameras, nas: web1 and the printer are matched,
	// and the phone, wireless and unknown, gets none.
	if unifiCIs != 7 {
		t.Fatalf("%d unifi CIs", unifiCIs)
	}
	if got := h.rels(sw); got != "connected_to>UDM Pro member_of>Default Front door>connected_to Garage AP>connected_to nas>connected_to Office printer>connected_to(port 12) web1>connected_to(port 7)" {
		t.Fatalf("switch relationships: %s", got)
	}
	// The wireless camera is linked to the access point it is on.
	if got := h.rels(ap); got != "connected_to>Rack switch member_of>Default Backyard>connected_to(wireless)" {
		t.Fatalf("access point relationships: %s", got)
	}
	if got := h.rels(wcam); got != "connected_to>Garage AP(wireless)" {
		t.Fatalf("wireless camera relationships: %s", got)
	}
	if got := h.rels(site); got != "Garage AP>member_of Rack switch>member_of UDM Pro>member_of" {
		t.Fatalf("site relationships: %s", got)
	}
	if h.rels(printer) != "connected_to>Rack switch(port 12)" || h.rels(cam) != "connected_to>Rack switch" || h.rels(gw) != "member_of>Default Rack switch>connected_to" {
		t.Fatalf("relationships: %s / %s / %s", h.rels(printer), h.rels(cam), h.rels(gw))
	}

	_, body = h.do(admin, "GET", "/settings/unifi", nil)
	for _, want := range []string{"UDM Pro", "Network 9.4.19", "Protect 6.1.79", "1 sites, 3 devices, 1 clients of their own, 2 Protect devices", "TLS pinned"} {
		if !strings.Contains(body, want) {
			t.Fatalf("settings page lacks %q", want)
		}
	}
	if strings.Contains(body, unifitest.Key) {
		t.Fatal("the API key is shown")
	}
	_, body = h.do(admin, "GET", "/cis/"+sw, nil)
	if !strings.Contains(body, "(port 7)") || !strings.Contains(body, "7.1.26") {
		t.Fatalf("switch page: %s", body)
	}

	// The switch has a firmware update; once it goes offline, it alerts.
	if conds, _ := h.st.UniFiFirmware(ctx); len(conds) != 1 || conds[0].CIID != sw {
		t.Fatalf("firmware: %+v", conds)
	}
	if conds, _ := h.st.UniFiDevicesOffline(ctx, 0); len(conds) != 0 {
		t.Fatalf("offline while online: %+v", conds)
	}
	con.Lock()
	con.Devices[1]["state"] = "OFFLINE"
	con.Clients = con.Clients[:len(con.Clients)-1] // the nas is gone
	con.Unlock()
	if err := poller.PollNow(ctx, id); err != nil {
		t.Fatal(err)
	}
	if conds, _ := h.st.UniFiDevicesOffline(ctx, 0); len(conds) != 1 || conds[0].CIID != sw || !strings.Contains(conds[0].Summary, "offline") {
		t.Fatalf("offline: %+v", conds)
	}
	if conds, _ := h.st.UniFiDevicesOffline(ctx, time.Hour); len(conds) != 0 {
		t.Fatalf("offline for an hour already: %+v", conds)
	}
	if got := h.rels(nas); got != "" {
		t.Fatalf("a gone client keeps its link: %s", got)
	}
	if _, err := h.st.MarkMissing(ctx, time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, status := h.unifiCI("mac:02:00:00:00:00:a3"); status != "missing" {
		t.Fatalf("gone client is %s", status)
	}
	if _, _, status := h.unifiCI("mac:f4:e2:c6:00:00:02"); status != "active" {
		t.Fatalf("switch is %s", status)
	}

	// A wrong key fails the poll and keeps what was found; a console that
	// can't be read alerts too.
	resp, _ = h.do(admin, "POST", "/settings/unifi/"+id, url.Values{"name": {"UDM Pro"}, "url": {con.URL}, "api_key": {"wrong"},
		"tls_fingerprint": {con.Fingerprint}, "protect": {"1"}, "enabled": {"1"}})
	if !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("edit: %s", resp.Header.Get("Location"))
	}
	resp, _ = h.do(admin, "POST", "/settings/unifi/"+id+"/poll", url.Values{})
	if loc, _ := url.QueryUnescape(resp.Header.Get("Location")); !strings.Contains(loc, "refused the API key") {
		t.Fatalf("bad key poll: %s", loc)
	}
	c, _ := h.st.GetUniFiController(ctx, id)
	if c.LastError == "" || c.Devices != 3 {
		t.Fatalf("after a failed poll: %+v", c)
	}
	if conds, _ := h.st.UniFiDevicesOffline(ctx, 0); len(conds) != 2 || conds[1].Key != "console:"+id {
		t.Fatalf("console alert: %+v", conds)
	}

	// Editing without a key keeps the saved one; the audit log has neither.
	h.do(admin, "POST", "/settings/unifi/"+id, url.Values{"name": {"UDM"}, "url": {con.URL}, "tls_fingerprint": {con.Fingerprint}, "enabled": {"1"}})
	if c2, _ := h.st.GetUniFiController(ctx, id); c2.APIKeyEnc != c.APIKeyEnc || c2.Name != "UDM" || c2.Config.Protect {
		t.Fatalf("edit without a key: %+v", c2)
	}
	if !strings.Contains(h.auditActions(), "unifi_controller.save") {
		t.Fatal("not audited")
	}

	resp, _ = h.do(admin, "POST", "/settings/unifi/"+id+"/delete", url.Values{})
	if !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("delete: %s", resp.Header.Get("Location"))
	}
	if _, err := h.st.MarkMissing(ctx, time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, status := h.unifiCI("mac:f4:e2:c6:00:00:02"); status != "missing" {
		t.Fatalf("switch of a removed console is %s", status)
	}
}

// A client found before the host with its MAC enrolled is merged into the
// host on the next poll, keeping what was linked to it by hand.
func TestUniFiClientMergesIntoHost(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	con := unifitest.New(t)
	con.Lock()
	con.Clients = append(con.Clients, map[string]any{"type": "WIRED", "id": "cl-5", "name": "nas", "macAddress": "02:00:00:00:00:a3", "uplinkDeviceId": "dev-sw"})
	con.Unlock()
	poller := &unifipoll.Poller{Store: h.st, Open: h.srv.secrets.Open}
	h.srv.SetUniFi(poller)
	admin := h.signIn("admin", "lab-admins")
	h.do(admin, "POST", "/settings/unifi", url.Values{"name": {"UDM Pro"}, "url": {con.URL}, "api_key": {unifitest.Key},
		"tls_fingerprint": {con.Fingerprint}, "enabled": {"1"}})
	cs, _ := h.st.ListUniFiControllers(ctx)
	if len(cs) != 1 {
		t.Fatalf("consoles: %+v", cs)
	}
	if err := poller.PollNow(ctx, cs[0].ID); err != nil {
		t.Fatal(err)
	}
	nas, typ, _ := h.unifiCI("mac:02:00:00:00:00:a3")
	if typ != "network_client" {
		t.Fatalf("nas is a %s", typ)
	}
	ups, err := h.st.CreateCI(ctx, store.System, store.CIInput{Type: "ups", Name: "UPS", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.st.AddRelationship(ctx, store.System, nas, ups, "depends_on"); err != nil {
		t.Fatal(err)
	}

	host := h.addHost("nas1")
	h.ingest(host, model.SectionHardware, model.Hardware{NICs: []model.NIC{{Name: "eth0", MAC: "02:00:00:00:00:A3", Kind: "physical"}}})
	if err := poller.PollNow(ctx, cs[0].ID); err != nil {
		t.Fatal(err)
	}
	var n int
	h.st.DB().QueryRow(`SELECT count(*) FROM ci WHERE id::text = $1`, nas).Scan(&n)
	if n != 0 {
		t.Fatal("the network_client is still there")
	}
	if got := h.rels(host.HostID); got != "connected_to>Rack switch depends_on>UPS" {
		t.Fatalf("host relationships: %s", got)
	}
	if !strings.Contains(h.auditActions(), "ci.merge") {
		t.Fatal("merge not audited")
	}
}

// The form refuses what can't work.
func TestUniFiConsoleForm(t *testing.T) {
	h := newHarness(t)
	admin := h.signIn("admin", "lab-admins")
	for _, f := range []url.Values{
		{"name": {"x"}, "url": {"http://192.168.1.1"}, "api_key": {"k"}},
		{"name": {"x"}, "url": {"https://192.168.1.1"}},
		{"name": {""}, "url": {"https://192.168.1.1"}, "api_key": {"k"}},
		{"name": {"x"}, "url": {"https://192.168.1.1"}, "api_key": {"k"}, "run_on": {"00000000-0000-0000-0000-000000000000"}},
		{"name": {"x"}, "url": {"https://192.168.1.1"}, "api_key": {"k"}, "tls_fingerprint": {"abc"}},
	} {
		resp, _ := h.do(admin, "POST", "/settings/unifi", f)
		if !strings.Contains(resp.Header.Get("Location"), "error=") {
			t.Errorf("%v accepted: %s", f, resp.Header.Get("Location"))
		}
	}
	viewer := h.signIn("viewer")
	if resp, _ := h.do(viewer, "GET", "/settings/unifi", nil); resp.StatusCode == 200 {
		t.Fatal("non-admin sees the UniFi settings")
	}
}
