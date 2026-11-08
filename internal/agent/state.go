// Package agent is the Baseline agent: enrollment, the connection to the
// server, and scheduling of collectors.
package agent

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/pki"
)

const (
	DefaultConfigPath = "/etc/baseline/agent.conf"
	DefaultStateDir   = "/var/lib/baseline"

	// Hosts enrolled before the rename to Baseline keep their configuration
	// and state here, and the agent goes on using them (FindConfigPath,
	// FindStateDir): moving them would move the Compose stacks under it.
	LegacyConfigPath = "/etc/jcmdb/agent.conf"
	LegacyStateDir   = "/var/lib/jcmdb"
)

// FindConfigPath is DefaultConfigPath, or LegacyConfigPath on a host that
// has only that.
func FindConfigPath() string { return current(DefaultConfigPath, LegacyConfigPath) }

// FindStateDir is DefaultStateDir, or LegacyStateDir on a host that has
// only that.
func FindStateDir() string { return current(DefaultStateDir, LegacyStateDir) }

func current(path, legacy string) string {
	if _, err := os.Stat(path); err != nil {
		if _, err := os.Stat(legacy); err == nil {
			return legacy
		}
	}
	return path
}

// Config is /etc/baseline/agent.conf: "key = value" lines, '#' comments. A
// small format parsed with the stdlib, so the agent needs no YAML library.
type Config struct {
	Server   string // host:port of the agent gateway
	StateDir string
	LogLevel string
	// StartPodmanSocket starts podman.socket when it exists but isn't
	// running, so rootful Podman containers can be read.
	StartPodmanSocket bool
	// Policy is the host owner's limit on jobs (docs/architecture.md §5.3):
	// allow_scripts = false turns off library scripts, and allow_actions
	// lists the action categories the host accepts (all by default).
	// self_update = off stops the server replacing the agent binary.
	Policy action.Policy
	// ComposeRoot is where compose.deploy puts new stacks, a directory per
	// stack; "" is <state_dir>/stacks.
	ComposeRoot string
	// Integrations lets the server have this agent poll systems on its
	// network, such as a UniFi console (integrations = off stops it).
	Integrations bool
	// ContainerLogs lets the server read container logs through this
	// agent, on demand (container_logs = off stops it).
	ContainerLogs bool
}

func LoadConfig(path string) (Config, error) {
	c := Config{StateDir: FindStateDir(), LogLevel: "Info", Policy: action.Policy{Jobs: true, AllowScripts: true}, Integrations: true, ContainerLogs: true}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return c, fmt.Errorf("%s:%d: expected key = value", path, n)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "server":
			c.Server = v
		case "state_dir":
			c.StateDir = v
		case "log_level":
			c.LogLevel = v
		case "start_podman_socket":
			c.StartPodmanSocket = v == "true" || v == "yes" || v == "1"
		case "allow_scripts":
			// Anything but an explicit yes turns scripts off: a typo
			// mustn't open the host up.
			c.Policy.AllowScripts = v == "true" || v == "yes" || v == "1"
		case "allow_actions":
			a, err := action.ParseAllowActions(v)
			if err != nil {
				return c, fmt.Errorf("%s:%d: allow_actions: %w", path, n, err)
			}
			c.Policy.AllowActions = a
		case "compose_root":
			if !filepath.IsAbs(v) {
				return c, fmt.Errorf("%s:%d: compose_root must be an absolute path", path, n)
			}
			c.ComposeRoot = filepath.Clean(v)
		case "self_update":
			// Like allow_actions, an unknown value stops the agent: a
			// typo mustn't leave updates on when the owner meant off.
			switch v {
			case "on":
				c.Policy.SelfUpdateOff = false
			case "off":
				c.Policy.SelfUpdateOff = true
			default:
				return c, fmt.Errorf("%s:%d: self_update: %q is not on or off", path, n, v)
			}
		case "integrations":
			switch v {
			case "on":
				c.Integrations = true
			case "off":
				c.Integrations = false
			default:
				return c, fmt.Errorf("%s:%d: integrations: %q is not on or off", path, n, v)
			}
		case "container_logs":
			switch v {
			case "on":
				c.ContainerLogs = true
			case "off":
				c.ContainerLogs = false
			default:
				return c, fmt.Errorf("%s:%d: container_logs: %q is not on or off", path, n, v)
			}
		default:
			// Unknown keys are allowed so a newer config works with an
			// older agent until self-update catches up.
		}
	}
	if err := sc.Err(); err != nil {
		return c, err
	}
	if c.Server == "" {
		return c, fmt.Errorf("%s: server is not set", path)
	}
	if c.ComposeRoot == "" {
		c.ComposeRoot = filepath.Join(c.StateDir, "stacks")
	}
	return c, nil
}

// WriteConfig writes the settings enroll learned, keeping other lines.
func WriteConfig(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	set := map[string]string{"server": c.Server}
	if c.StateDir != "" && c.StateDir != FindStateDir() {
		set["state_dir"] = c.StateDir
	}
	var lines []string
	if b, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			k, _, ok := strings.Cut(line, "=")
			if v, managed := set[strings.TrimSpace(k)]; ok && managed {
				lines = append(lines, strings.TrimSpace(k)+" = "+v)
				delete(set, strings.TrimSpace(k))
				continue
			}
			lines = append(lines, line)
		}
	} else {
		lines = append(lines, "# Baseline agent configuration", "",
			"# Local policy: what jobs this host accepts, whatever the server asks.",
			"# allow_scripts = false turns off library scripts; allow_actions lists",
			"# the action categories allowed (patch, container, service, reboot),",
			"# or none. self_update = off stops the server replacing this agent;",
			"# update it by running install.sh again. Restart the agent after",
			"# changing them.",
			"#allow_scripts = true",
			"#allow_actions = all",
			"#self_update = on", "",
			"# Where Compose stacks deployed from Baseline live, a directory each.",
			"#compose_root = /var/lib/baseline/stacks", "",
			"# integrations = off stops the server having this agent poll systems",
			"# on its network for it, such as a UniFi console.",
			"#integrations = on", "",
			"# container_logs = off stops the server reading container logs",
			"# through this agent (operators view them on demand; they are never",
			"# stored).",
			"#container_logs = on", "")
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lines = append(lines, k+" = "+set[k])
	}
	return writeAtomic(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// State is what enrollment leaves in the state directory.
type State struct {
	Dir     string
	AgentID string
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CA      *x509.Certificate
}

func (s *State) path(name string) string { return filepath.Join(s.Dir, name) }

var ErrNotEnrolled = errors.New("agent is not enrolled; run `baseline-agent enroll`")

func LoadState(dir string) (*State, error) {
	s := &State{Dir: dir}
	id, err := os.ReadFile(s.path("agent-id"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	s.AgentID = strings.TrimSpace(string(id))
	if s.Cert, err = readCert(s.path("agent.crt")); err != nil {
		return nil, err
	}
	if s.CA, err = readCert(s.path("ca.crt")); err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(s.path("agent.key"))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(kb)
	if blk == nil {
		return nil, errors.New("agent.key: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	var ok bool
	if s.Key, ok = k.(*ecdsa.PrivateKey); !ok {
		return nil, errors.New("agent.key: not an ECDSA key")
	}
	if !s.Key.PublicKey.Equal(s.Cert.PublicKey) {
		return nil, errors.New("agent.key does not match agent.crt (interrupted certificate renewal?); re-enroll with --force")
	}
	return s, nil
}

// SaveCert stores a (new) key and cert. A crash between the two writes
// leaves a mismatched pair, which LoadState detects and reports.
func (s *State) SaveCert(key *ecdsa.PrivateKey, certDER []byte) error {
	kp, err := pki.EncodeKey(key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	if err := writeAtomic(s.path("agent.key"), kp, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(s.path("agent.crt"), pki.EncodeCert(certDER), 0o644); err != nil {
		return err
	}
	s.Key, s.Cert = key, cert
	return nil
}

// TLS is the client config for the mutually authenticated stream.
func (s *State) TLS(server string) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, fmt.Errorf("server %q: %w", server, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.CA)
	return &tls.Config{
		ServerName:   host,
		RootCAs:      pool,
		Certificates: []tls.Certificate{{Certificate: [][]byte{s.Cert.Raw}, PrivateKey: s.Key, Leaf: s.Cert}},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// RenewDue reports whether the cert has passed two thirds of its lifetime.
func (s *State) RenewDue(now time.Time) bool {
	life := s.Cert.NotAfter.Sub(s.Cert.NotBefore)
	return now.After(s.Cert.NotBefore.Add(life * 2 / 3))
}

func readCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
