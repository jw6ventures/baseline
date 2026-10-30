package server

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/alert"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/notify"
	"github.com/jw6ventures/baseline/internal/rbac"
	"github.com/jw6ventures/baseline/internal/store"
)

func TestHighSecurityHardwareAlerts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	vault := h.addHost("vault")
	other := h.addHost("other")
	h.st.CreateRoleBinding(ctx, store.System, store.RoleBinding{IdPGroup: "ops", Role: rbac.Operator})
	admin := h.signIn("ann", "lab-admins")
	ops := h.signIn("oz", "ops")
	e := &alert.Evaluator{Store: h.st, PublicURL: h.cfg.PublicURL.String()}
	rule := ruleOfKind(t, h.st, "hardware_change")
	if !rule.Enabled || rule.Severity != "critical" || rule.Repeat != 15*time.Minute {
		t.Fatalf("default rule: %+v", rule)
	}
	hw := model.Hardware{CPU: model.CPU{Model: "EPYC 7302P", Cores: 16, Threads: 32}, Memory: model.Memory{TotalBytes: 64 << 30},
		Disks: []model.Disk{{Name: "nvme0n1", Model: "Micron 7450", SizeBytes: 960 << 30}},
		NICs:  []model.NIC{{Name: "eno1", MAC: "aa:00:00:00:00:01", Kind: "physical"}}}
	open := func() []store.Alert {
		t.Helper()
		if err := e.Pass(ctx); err != nil {
			t.Fatal(err)
		}
		as, err := h.st.ListAlerts(ctx, store.AlertFilter{Open: true})
		if err != nil {
			t.Fatal(err)
		}
		var out []store.Alert
		for _, a := range as {
			if a.RuleID == rule.ID {
				out = append(out, a)
			}
		}
		return out
	}

	// A disk added before the flag is on doesn't count, nor on other hosts.
	hw.Disks = append(hw.Disks, model.Disk{Name: "sdb", Model: "WD Red", Serial: "WD-1"})
	h.ingest(vault, model.SectionHardware, hw)
	h.ingest(other, model.SectionHardware, hw)

	if resp, _ := h.do(ops, "POST", "/hosts/"+vault.HostID+"/high-security", url.Values{"high_security": {"1"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator toggled it: %d", resp.StatusCode)
	}
	h.hub.online[vault.AgentID] = true
	resp, _ := h.do(admin, "POST", "/hosts/"+vault.HostID+"/high-security", url.Values{"high_security": {"1"}})
	if !strings.Contains(resp.Header.Get("Location"), "notice=") {
		t.Fatalf("turn on: %s", resp.Header.Get("Location"))
	}
	if set, ok := h.hub.configured[vault.AgentID]; !ok || !set.HighSecurity {
		t.Fatalf("agent not reconfigured: %v", h.hub.configured)
	}
	if hst, _ := h.st.GetHost(ctx, vault.HostID); !hst.HighSecurity || hst.HighSecuritySince.IsZero() {
		t.Fatalf("host: %+v", hst)
	}
	if !strings.Contains(h.auditActions(), "host.high_security") {
		t.Fatalf("audit: %s", h.auditActions())
	}
	if _, body := h.do(ops, "GET", "/hosts/"+vault.HostID, nil); !strings.Contains(body, ">high security</span>") ||
		strings.Contains(body, "/high-security\"") {
		t.Fatalf("operator's host page:\n%s", body)
	}
	if got := open(); len(got) != 0 {
		t.Fatalf("alerts for changes before the flag: %+v", got)
	}

	// Firmware and high security collection starting aren't changes.
	hw.Disks[0].Firmware = "E2MU200"
	hw.NICs[0].Link = "up"
	hw.Peripherals = &model.Peripherals{
		USB:      []model.USBDevice{{Name: "1-1", VendorID: "05e3", ProductID: "0610", Class: "Hub [09]"}},
		Displays: []model.Display{{Name: "card0-VGA-1", Status: "disconnected"}},
	}
	h.ingest(vault, model.SectionHardware, hw)
	if got := open(); len(got) != 0 {
		t.Fatalf("alerts: %+v", got)
	}

	// A USB stick plugged in, a disk pulled, a cable pulled and a monitor
	// plugged in: one alert each.
	hw.Peripherals.USB = append(hw.Peripherals.USB, model.USBDevice{Name: "1-1.2", VendorID: "0781", ProductID: "5581", Product: "Ultra", Serial: "4C53"})
	h.ingest(vault, model.SectionHardware, hw)
	hw.Disks = hw.Disks[:1]
	h.ingest(vault, model.SectionHardware, hw)
	h.ingest(other, model.SectionHardware, hw)
	hw.NICs[0].Link = "down"
	h.ingest(vault, model.SectionHardware, hw)
	hw.Peripherals.Displays[0] = model.Display{Name: "card0-VGA-1", Status: "connected", Monitor: "DEL DELL P2419H"}
	h.ingest(vault, model.SectionHardware, hw)
	got := open()
	if len(got) != 4 || got[0].State != store.AlertFiring || got[0].Severity != "critical" {
		t.Fatalf("alerts: %+v", got)
	}
	var usb, disk, cable, display store.Alert
	for _, a := range got {
		switch {
		case strings.Contains(a.Summary, "USB device 1-1.2 added (product Ultra"):
			usb = a
		case strings.Contains(a.Summary, "disk sdb removed (model WD Red, serial WD-1)"):
			disk = a
		case strings.Contains(a.Summary, "NIC eno1 link down (was up)"):
			cable = a
		case strings.Contains(a.Summary, "display connector card0-VGA-1 connected (monitor DEL DELL P2419H)"):
			display = a
		}
	}
	if usb.ID == "" || disk.ID == "" || cable.ID == "" || display.ID == "" || !strings.HasPrefix(usb.Key, "hardware:") ||
		usb.CIID != vault.HostID {
		t.Fatalf("alerts: %+v", got)
	}
	if _, body := h.do(admin, "GET", "/hosts/"+vault.HostID+"?tab=hardware", nil); !strings.Contains(body, "USB devices") ||
		!strings.Contains(body, "0781:5581") || !strings.Contains(body, "DEL DELL P2419H") || !strings.Contains(body, "link down") {
		t.Fatalf("hardware tab:\n%s", body)
	}

	// With a channel, it reminds every 15 minutes until acknowledged.
	ch, err := h.st.SaveChannel(ctx, store.System, store.NotifyChannel{Kind: notify.Ntfy, Name: "phone", Enabled: true, ConfigEnc: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	rule.Channels = []string{ch}
	if _, err := h.st.SaveAlertRule(ctx, store.System, rule); err != nil {
		t.Fatal(err)
	}
	firing := func(id string) (reminders int) {
		ns, _ := h.st.AlertNotifications(ctx, id)
		for _, n := range ns {
			if n.Event == store.EventReminder {
				reminders++
			}
		}
		return reminders
	}
	clock := time.Now()
	e.Now = func() time.Time { return clock }
	open()
	clock = clock.Add(16 * time.Minute)
	open()
	if n := firing(cable.ID); n != 1 {
		t.Fatalf("%d reminders", n)
	}
	e.Now = nil

	// Acknowledging one resolves it, for good; the other keeps firing.
	h.do(ops, "POST", "/alerts/"+usb.ID+"/ack", url.Values{"comment": {"my stick"}})
	for range 2 {
		if got = open(); len(got) != 3 || slices.ContainsFunc(got, func(a store.Alert) bool { return a.ID == usb.ID }) {
			t.Fatalf("after ack: %+v", got)
		}
	}
	if a, _ := h.st.GetAlert(ctx, usb.ID); a.State != store.AlertResolved {
		t.Fatalf("acked alert: %+v", a)
	}

	// Turning the flag off resolves the rest and tells the agent.
	h.do(admin, "POST", "/hosts/"+vault.HostID+"/high-security", url.Values{"high_security": {"0"}})
	if h.hub.configured[vault.AgentID].HighSecurity {
		t.Fatal("agent still configured for high security")
	}
	if got = open(); len(got) != 0 {
		t.Fatalf("after turning off: %+v", got)
	}
}
