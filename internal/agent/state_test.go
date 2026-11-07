package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/pki"
)

func TestConfigRoundTripKeepsOtherLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "agent.conf")
	if err := WriteConfig(path, Config{Server: "agent.example:443"}); err != nil {
		t.Fatal(err)
	}
	// An admin adds a setting; re-enrolling must keep it.
	b, _ := os.ReadFile(path)
	os.WriteFile(path, append(b, []byte("log_level = Debug\nfuture_key = x\n")...), 0o644)
	if err := WriteConfig(path, Config{Server: "new.example:8443"}); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "new.example:8443" || c.LogLevel != "Debug" || c.StateDir != FindStateDir() {
		t.Fatalf("config = %+v", c)
	}
	b, _ = os.ReadFile(path)
	if strings.Count(string(b), "server =") != 1 || !strings.Contains(string(b), "future_key = x") {
		t.Fatalf("file:\n%s", b)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadConfig(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}
	p := filepath.Join(dir, "bad.conf")
	os.WriteFile(p, []byte("# no server\nlog_level = Info\n"), 0o644)
	if _, err := LoadConfig(p); err == nil || !strings.Contains(err.Error(), "server is not set") {
		t.Errorf("err = %v", err)
	}
	os.WriteFile(p, []byte("server agent.example:443\n"), 0o644)
	if _, err := LoadConfig(p); err == nil || !strings.Contains(err.Error(), ":1:") {
		t.Errorf("err = %v", err)
	}
}

func TestLoadStateDetectsMismatchedKey(t *testing.T) {
	dir := t.TempDir()
	key, csr, _ := pki.GenerateKey()
	ca, _ := pki.Load(t.TempDir(), nil)
	cert, err := ca.IssueClient(csr, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	st := &State{Dir: dir}
	writeAtomic(st.path("ca.crt"), pki.EncodeCert(ca.CACert().Raw), 0o644)
	writeAtomic(st.path("agent-id"), []byte("agent-1\n"), 0o644)
	if err := st.SaveCert(key, cert.Raw); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err != nil {
		t.Fatal(err)
	}
	// A crash after writing a new key but before its cert.
	other, _, _ := pki.GenerateKey()
	kp, _ := pki.EncodeKey(other)
	writeAtomic(st.path("agent.key"), kp, 0o600)
	if _, err := LoadState(dir); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v", err)
	}
}

func TestStateNotEnrolled(t *testing.T) {
	if _, err := LoadState(t.TempDir()); err != ErrNotEnrolled {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadConfigPolicy(t *testing.T) {
	dir := t.TempDir()
	load := func(lines string) (Config, error) {
		p := filepath.Join(dir, "agent.conf")
		os.WriteFile(p, []byte("server = s:1\n"+lines), 0o644)
		return LoadConfig(p)
	}
	c, err := load("")
	if err != nil || !c.Policy.Jobs || !c.Policy.AllowScripts || !c.Policy.AllActions() {
		t.Fatalf("default: %+v %v", c.Policy, err)
	}
	// Only an explicit yes keeps scripts on: a typo turns them off.
	for v, want := range map[string]bool{"true": true, "yes": true, "1": true, "false": false, "no": false, "flase": false} {
		if c, _ := load("allow_scripts = " + v + "\n"); c.Policy.AllowScripts != want {
			t.Errorf("allow_scripts = %s: %v", v, c.Policy.AllowScripts)
		}
	}
	if c, _ = load("allow_actions = patch, reboot\n"); strings.Join(c.Policy.AllowActions, ",") != "patch,reboot" {
		t.Fatalf("list: %v", c.Policy.AllowActions)
	}
	if c, _ = load("allow_actions = none\n"); c.Policy.AllowActions == nil || len(c.Policy.AllowActions) != 0 {
		t.Fatalf("none: %#v", c.Policy.AllowActions)
	}
	// An unknown category refuses to start rather than allowing everything.
	if _, err := load("allow_actions = patch,everything\n"); err == nil || !strings.Contains(err.Error(), ":2: allow_actions") {
		t.Fatalf("unknown category: %v", err)
	}
	if c.Policy.SelfUpdateOff {
		t.Fatal("self-update off by default")
	}
	if c, _ = load("self_update = off\n"); !c.Policy.SelfUpdateOff {
		t.Fatal("self_update = off not read")
	}
	if c, _ = load("self_update = on\n"); c.Policy.SelfUpdateOff {
		t.Fatal("self_update = on read as off")
	}
	// Like allow_actions, anything but on or off refuses to start.
	for _, v := range []string{"of", "false", "approve", ""} {
		if _, err := load("self_update = " + v + "\n"); err == nil || !strings.Contains(err.Error(), ":2: self_update") {
			t.Errorf("self_update = %q: %v", v, err)
		}
	}
	// Integrations are on unless turned off, and a typo refuses to start.
	if c, _ = load(""); !c.Integrations {
		t.Fatal("integrations off by default")
	}
	if c, _ = load("integrations = off\n"); c.Integrations {
		t.Fatal("integrations = off not read")
	}
	if _, err := load("integrations = of\n"); err == nil || !strings.Contains(err.Error(), ":2: integrations") {
		t.Errorf("integrations = of: %v", err)
	}
	// So are container logs.
	if c, _ = load(""); !c.ContainerLogs {
		t.Fatal("container logs off by default")
	}
	if c, _ = load("container_logs = off\n"); c.ContainerLogs {
		t.Fatal("container_logs = off not read")
	}
	if _, err := load("container_logs = no\n"); err == nil || !strings.Contains(err.Error(), ":2: container_logs") {
		t.Errorf("container_logs = no: %v", err)
	}
}
