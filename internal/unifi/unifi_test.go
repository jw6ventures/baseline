package unifi_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/unifi"
	"github.com/jw6ventures/baseline/internal/unifi/unifitest"
)

func TestPoll(t *testing.T) {
	con := unifitest.New(t)
	cfg := unifi.Config{URL: con.URL, TLSFingerprint: unifi.FormatFingerprint(con.Fingerprint), Protect: true}
	got, err := unifi.Poll(context.Background(), cfg, unifitest.Key)
	if err != nil {
		t.Fatal(err)
	}
	if got.NetworkVersion != "9.4.19" || got.ProtectVersion != "6.1.79" || len(got.Sites) != 1 {
		t.Fatalf("poll: %+v", got)
	}
	site := got.Sites[0]
	if site.ID != "site-1" || site.Ref != "default" || site.Name != "Default" || site.PortsError != "" {
		t.Fatalf("site: %+v", site)
	}
	want := []model.UniFiDevice{
		{ID: "dev-gw", Name: "UDM Pro", Model: "UDM Pro", MAC: "f4:e2:c6:00:00:01", IP: "192.168.1.1", State: "ONLINE", Firmware: "4.3.6",
			Features: []string{"gateway", "switching"}},
		{ID: "dev-sw", Name: "Rack switch", Model: "USW Pro 24", MAC: "f4:e2:c6:00:00:02", IP: "192.168.1.2", State: "ONLINE", Firmware: "7.1.26",
			FirmwareUpdatable: true, Features: []string{"switching"}, UplinkID: "dev-gw"},
		{ID: "dev-ap", Name: "Garage AP", Model: "U6 Pro", MAC: "f4:e2:c6:00:00:03", IP: "192.168.1.3", State: "ONLINE", Firmware: "6.6.77",
			Features: []string{"accessPoint"}, UplinkID: "dev-sw"},
	}
	if len(site.Devices) != len(want) {
		t.Fatalf("devices: %+v", site.Devices)
	}
	for i, d := range want {
		if !devEqual(site.Devices[i], d) {
			t.Errorf("device %d: %+v, want %+v", i, site.Devices[i], d)
		}
	}
	// Wired and wireless, not VPN; web1's port and switch, and the phone's
	// access point, come from the classic API.
	wantClients := []model.UniFiClient{
		{ID: "cl-1", Name: "web1", MAC: "02:00:00:00:00:a1", IP: "192.168.1.10", UplinkID: "dev-sw", Port: 7},
		{ID: "cl-2", Name: "printer", MAC: "02:00:00:00:00:a2", IP: "192.168.1.11", UplinkID: "dev-sw", Port: 12},
		{ID: "cl-4", Name: "phone", MAC: "02:00:00:00:00:b1", IP: "192.168.1.50", UplinkID: "dev-ap", Wireless: true},
		{ID: "cl-3", Name: "Front door", MAC: "02:00:00:00:00:c1", IP: "192.168.1.30", UplinkID: "dev-sw"},
		{ID: "cl-6", Name: "Backyard", MAC: "02:00:00:00:00:c2", IP: "192.168.1.31", UplinkID: "dev-ap", Wireless: true},
	}
	if len(site.Clients) != len(wantClients) {
		t.Fatalf("clients: %+v", site.Clients)
	}
	for i, c := range wantClients {
		if site.Clients[i] != c {
			t.Errorf("client %d: %+v, want %+v", i, site.Clients[i], c)
		}
	}
	if len(got.Protect) != 2 || got.Protect[0] != (model.UniFiCamera{Kind: "camera", ID: "cam-1", Name: "Front door", Model: "G4 Doorbell Pro",
		MAC: "02:00:00:00:00:c1", State: "CONNECTED"}) {
		t.Fatalf("protect: %+v", got.Protect)
	}
}

func devEqual(a, b model.UniFiDevice) bool {
	return a.ID == b.ID && a.Name == b.Name && a.Model == b.Model && a.MAC == b.MAC && a.IP == b.IP && a.State == b.State &&
		a.Firmware == b.Firmware && a.FirmwareUpdatable == b.FirmwareUpdatable && strings.Join(a.Features, ",") == strings.Join(b.Features, ",") &&
		a.UplinkID == b.UplinkID
}

// Protect and switch ports are read as far as they go; the rest of the poll
// still counts.
func TestPollWithoutProtectOrPorts(t *testing.T) {
	con := unifitest.New(t)
	con.Lock()
	con.Protect = false
	con.Classic = nil
	con.Unlock()
	cfg := unifi.Config{URL: con.URL, TLSFingerprint: con.Fingerprint, Protect: true}
	got, err := unifi.Poll(context.Background(), cfg, unifitest.Key)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProtectError == "" || got.Protect != nil || len(got.Sites[0].Clients) != 5 || got.Sites[0].Clients[0].Port != 0 {
		t.Fatalf("poll: %+v", got)
	}
	// Without the classic API, a wireless client keeps the Integration
	// API's uplink.
	if c := got.Sites[0].Clients[2]; c.ID != "cl-4" || c.UplinkID != "dev-gw" || !c.Wireless {
		t.Fatalf("phone: %+v", c)
	}
	// Protect isn't asked for unless wanted.
	cfg.Protect = false
	if got, err = unifi.Poll(context.Background(), cfg, unifitest.Key); err != nil || got.ProtectError != "" {
		t.Fatalf("without protect: %+v %v", got, err)
	}
}

func TestPollSites(t *testing.T) {
	con := unifitest.New(t)
	cfg := unifi.Config{URL: con.URL, TLSFingerprint: con.Fingerprint, Sites: []string{"default"}}
	if got, err := unifi.Poll(context.Background(), cfg, unifitest.Key); err != nil || len(got.Sites) != 1 {
		t.Fatalf("by reference: %+v %v", got, err)
	}
	cfg.Sites = []string{"Office"}
	if _, err := unifi.Poll(context.Background(), cfg, unifitest.Key); err == nil || !strings.Contains(err.Error(), "Office") {
		t.Fatalf("unknown site: %v", err)
	}
}

func TestPollErrors(t *testing.T) {
	con := unifitest.New(t)
	ctx := context.Background()

	// Unpinned, the self-signed certificate fails, and the error carries
	// its fingerprint to pin.
	_, err := unifi.Poll(ctx, unifi.Config{URL: con.URL}, unifitest.Key)
	var ue *unifi.UntrustedError
	if !errors.As(err, &ue) || ue.Fingerprint != con.Fingerprint || !strings.Contains(err.Error(), unifi.FormatFingerprint(con.Fingerprint)) {
		t.Fatalf("untrusted: %v", err)
	}
	// A different pin is refused.
	other := strings.Repeat("ab", 32)
	if _, err := unifi.Poll(ctx, unifi.Config{URL: con.URL, TLSFingerprint: other}, unifitest.Key); err == nil ||
		!strings.Contains(err.Error(), "certificate changed") {
		t.Fatalf("wrong pin: %v", err)
	}
	// A wrong key, and the key never shows in the error.
	_, err = unifi.Poll(ctx, unifi.Config{URL: con.URL, TLSFingerprint: con.Fingerprint}, "nope")
	if err == nil || !strings.Contains(err.Error(), "refused the API key") || strings.Contains(err.Error(), "nope") {
		t.Fatalf("bad key: %v", err)
	}
}

func TestConfigCheck(t *testing.T) {
	c, err := unifi.Config{URL: " 192.168.1.1/ ", TLSFingerprint: "AB:" + strings.Repeat("cd", 31), Sites: []string{" default", "", "default"}}.Check()
	if err != nil || c.URL != "https://192.168.1.1" || c.TLSFingerprint != "ab"+strings.Repeat("cd", 31) || len(c.Sites) != 1 {
		t.Fatalf("check: %+v %v", c, err)
	}
	for _, bad := range []unifi.Config{{URL: "http://192.168.1.1"}, {URL: "https://u:p@udm"}, {URL: "https://udm/x"}, {URL: ""},
		{URL: "https://udm", TLSFingerprint: "abcd"}, {URL: "https://udm", TLSFingerprint: strings.Repeat("zz", 32)}} {
		if _, err := bad.Check(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestNormalizeMAC(t *testing.T) {
	for in, want := range map[string]string{"F4E2C6A1B2C3": "f4:e2:c6:a1:b2:c3", "f4-e2-c6-a1-b2-c3": "f4:e2:c6:a1:b2:c3",
		"f4e2.c6a1.b2c3": "f4:e2:c6:a1:b2:c3", "": "", "f4e2c6": "", "zze2c6a1b2c3": ""} {
		if got := unifi.NormalizeMAC(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
