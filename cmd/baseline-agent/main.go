// Command baseline-agent reports a Linux host's inventory to a Baseline server,
// or, in cluster mode, a Kubernetes cluster's.
//
// Usage:
//
//	baseline-agent enroll --server HOST:PORT --token TOKEN   enroll this host (once)
//	baseline-agent [run]                                     run the agent (systemd)
//	baseline-agent [run] --mode=k8s                          run the cluster agent (in a pod; see below)
//	baseline-agent collect [SECTION|metrics]...              print sections as JSON and exit
//	baseline-agent collect --mode=k8s                        print the cluster's "k8s" section (also: collect k8s)
//	baseline-agent guard                                     roll back a failed self-update (ExecStartPre)
//	baseline-agent version                                   print the version
//
// In cluster mode (deploy/k8s/baseline-agent.yaml) settings come from the
// environment, falling back to the config file when there is one:
// BASELINE_SERVER (gateway host:port), BASELINE_TOKEN (enrollment token, used
// only until the agent has enrolled), BASELINE_CLUSTER_NAME (default
// "kubernetes"), BASELINE_STATE_DIR (default /var/lib/baseline) and
// BASELINE_LOG_LEVEL. The API server is the pod's own, through its service
// account; outside a cluster set BASELINE_K8S_API (https://host:port),
// BASELINE_K8S_CA (PEM file) and BASELINE_K8S_TOKEN_FILE instead.
// It runs Kubernetes actions unless BASELINE_ALLOW_ACTIONS=none, never in
// the namespaces of BASELINE_DENY_NAMESPACES (default kube-system; "none" for
// none), and reads pod logs for the server unless BASELINE_K8S_LOGS=off.
// Changing workloads needs the ClusterRole in
// deploy/k8s/baseline-agent-manage.yaml too.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/agent"
	"github.com/jw6ventures/baseline/internal/agent/collect"
	"github.com/jw6ventures/baseline/internal/agent/kube"
	"github.com/jw6ventures/baseline/internal/agent/runner"
	"github.com/jw6ventures/baseline/internal/env"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/pki"
)

// Version is set at build time with -ldflags "-X main.Version=...": the
// release tag, or for a local build the git description (Makefile) or the
// newest schema migration (Dockerfile).
var Version = "dev"

func main() {
	cmd, args := "run", os.Args[1:]
	if len(args) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "version":
		fmt.Println(Version)
	case "enroll":
		err = enroll(ctx, args)
	case "run":
		err = run(ctx, args)
	case "collect":
		err = collectCmd(ctx, args)
	case "guard":
		err = guard(args)
	case "stackfile":
		// The agent runs this as a rootless Podman stack's user to read
		// and write the stack's files; it isn't meant to be run by hand.
		err = runner.ServeFileOp(os.Stdin, os.Stdout)
	default:
		err = fmt.Errorf("unknown command %q (enroll, run, collect, guard, version)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "baseline-agent:", err)
		os.Exit(1)
	}
}

func enroll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "agent gateway address, host:port")
	token := fs.String("token", "", "enrollment token from Settings → Enrollment (or set BASELINE_TOKEN, which keeps it out of ps)")
	config := fs.String("config", agent.FindConfigPath(), "config file to write")
	stateDir := fs.String("state-dir", agent.FindStateDir(), "where the key and certificates go")
	force := fs.Bool("force", false, "enroll again even if this host is already enrolled")
	fs.Parse(args)
	if *token == "" {
		*token = env.Get("BASELINE_TOKEN")
	}
	if *server == "" || *token == "" {
		return errors.New("enroll needs --server and --token")
	}
	if os.Geteuid() != 0 {
		return errors.New("enroll must run as root")
	}
	if _, err := agent.LoadState(*stateDir); err == nil && !*force {
		return fmt.Errorf("already enrolled (state in %s); use --force to enroll again", *stateDir)
	}
	id, err := agent.Enroll(ctx, *server, *token, *stateDir, Version, collect.Host())
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}
	if err := agent.WriteConfig(*config, agent.Config{Server: *server, StateDir: *stateDir}); err != nil {
		return err
	}
	fmt.Printf("Enrolled as agent %s. Start it with: systemctl enable --now baseline-agent\n", id)
	return nil
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	config := fs.String("config", agent.FindConfigPath(), "config file")
	mode := fs.String("mode", "host", "host: report this host; k8s: report the Kubernetes cluster this runs in")
	fs.Parse(args)
	switch *mode {
	case "host":
	case "k8s":
		return runCluster(ctx, *config)
	default:
		return fmt.Errorf("unknown mode %q (host, k8s)", *mode)
	}

	cfg, err := agent.LoadConfig(*config)
	if err != nil {
		return err
	}
	log := &jw6_utils.Utils{LogLevel: jw6_utils.LogLevelFromString(cfg.LogLevel)}
	st, err := agent.LoadState(cfg.StateDir)
	if err != nil {
		return err
	}
	env := collect.Host()
	log.Log("Agent", "run", jw6_utils.Info, fmt.Sprintf("baseline-agent %s, agent %s, server %s", Version, st.AgentID, cfg.Server))
	sampler := &collect.Sampler{Env: env}
	containers := &collect.ContainerCollector{Env: env, StartPodmanSocket: cfg.StartPodmanSocket}
	a := &agent.Agent{Server: cfg.Server, State: st, Env: env, Collectors: agent.Collectors(env, sampler, containers),
		Sampler: sampler, ContainerSampler: containers, Version: Version, Log: log, Integrations: cfg.Integrations,
		Runner: &runner.Runner{Dir: filepath.Join(cfg.StateDir, "jobs"), Env: env, Containers: containers, Policy: cfg.Policy, Log: log,
			ComposeRoot: cfg.ComposeRoot}}
	if cfg.ContainerLogs {
		a.ContainerLogs = containers
	}
	log.Log("Agent", "run", jw6_utils.Info, "Local policy: "+describePolicy(cfg.Policy))
	keys, err := pki.ReleaseKeys()
	if err == nil {
		a.Updater, err = agent.NewUpdater(cfg.StateDir, "", keys, env.Run)
	}
	if err != nil {
		log.Log("Agent", "run", jw6_utils.Warn, "self-update disabled: "+err.Error())
		a.Updater = nil
	} else {
		a.Updater.Off = cfg.Policy.SelfUpdateOff
	}
	err = a.Run(ctx)
	if errors.Is(err, agent.ErrRestart) {
		return nil // systemd (Restart=always) starts the new binary
	}
	return err
}

func describePolicy(p action.Policy) string {
	s := "scripts allowed"
	if !p.AllowScripts {
		s = "scripts off"
	}
	switch {
	case p.AllowActions == nil:
		s += ", all actions allowed"
	case len(p.AllowActions) == 0:
		s += ", no actions allowed"
	default:
		s += ", actions allowed: " + strings.Join(p.AllowActions, ", ")
	}
	if p.SelfUpdateOff {
		s += ", self-update off"
	}
	return s
}

// guard runs before every start, from the previous binary, to roll back an
// update that never reached the server. It never fails the start.
func guard(args []string) error {
	fs := flag.NewFlagSet("guard", flag.ExitOnError)
	config := fs.String("config", agent.FindConfigPath(), "config file")
	fs.Parse(args)
	stateDir := agent.FindStateDir()
	if cfg, err := agent.LoadConfig(*config); err == nil {
		stateDir = cfg.StateDir
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "baseline-agent guard:", err)
		return nil
	}
	msg, err := agent.Guard(stateDir, strings.TrimSuffix(exe, ".prev"), time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "baseline-agent guard:", err)
	} else if msg != "" {
		fmt.Fprintln(os.Stderr, "baseline-agent guard:", msg)
	}
	return nil
}

// clusterConfig is cluster mode's settings: the environment, over the
// config file if there is one.
type clusterConfig struct {
	agent.Config
	Token       string // enrollment token
	ClusterName string
	// Actions turns the Kubernetes actions on (BASELINE_ALLOW_ACTIONS).
	Actions []string
	// DenyNamespaces are off limits to them (BASELINE_DENY_NAMESPACES).
	DenyNamespaces []string
	// Logs lets the server read pod logs (BASELINE_K8S_LOGS).
	Logs bool
}

func loadClusterConfig(path string) (clusterConfig, error) {
	c := clusterConfig{Config: agent.Config{StateDir: agent.FindStateDir(), LogLevel: "Info"}}
	if _, err := os.Stat(path); err == nil {
		fc, err := agent.LoadConfig(path)
		// A file without a server is fine when the environment names one.
		if err != nil && (fc.Server != "" || env.Get("BASELINE_SERVER") == "") {
			return c, err
		}
		c.Config = fc
	}
	for _, v := range []struct {
		name string
		dst  *string
	}{
		{"BASELINE_SERVER", &c.Server}, {"BASELINE_TOKEN", &c.Token}, {"BASELINE_CLUSTER_NAME", &c.ClusterName},
		{"BASELINE_STATE_DIR", &c.StateDir}, {"BASELINE_LOG_LEVEL", &c.LogLevel},
	} {
		if s := strings.TrimSpace(env.Get(v.name)); s != "" {
			*v.dst = s
		}
	}
	if c.ClusterName == "" {
		c.ClusterName = "kubernetes"
	}
	var err error
	if c.Actions, err = action.ParseClusterAllowActions(env.Get("BASELINE_ALLOW_ACTIONS")); err != nil {
		return c, err
	}
	if c.DenyNamespaces, err = action.ParseDenyNamespaces(env.Get("BASELINE_DENY_NAMESPACES")); err != nil {
		return c, fmt.Errorf("BASELINE_DENY_NAMESPACES: %w", err)
	}
	switch v := strings.ToLower(strings.TrimSpace(env.Get("BASELINE_K8S_LOGS"))); v {
	case "off", "false", "no", "0":
	case "", "on", "true", "yes", "1":
		c.Logs = true
	default:
		return c, fmt.Errorf("BASELINE_K8S_LOGS takes on or off, not %q", v)
	}
	if c.Server == "" {
		return c, errors.New("BASELINE_SERVER (the agent gateway, host:port) is not set")
	}
	return c, nil
}

// kubeClient is the API server the cluster agent reads: the one named by
// BASELINE_K8S_API, or else the cluster its pod runs in.
func kubeClient() (*kube.Client, error) {
	api := env.Get("BASELINE_K8S_API")
	if api == "" {
		return kube.InCluster()
	}
	roots, err := x509.SystemCertPool()
	if ca := env.Get("BASELINE_K8S_CA"); ca != "" {
		roots, err = kube.LoadCA(ca)
	}
	if err != nil {
		return nil, err
	}
	c := kube.New(api, roots)
	c.TokenFile = env.Get("BASELINE_K8S_TOKEN_FILE")
	if c.TokenFile == "" {
		return nil, errors.New("BASELINE_K8S_API is set without BASELINE_K8S_TOKEN_FILE")
	}
	return c, nil
}

// runCluster runs the cluster agent: it enrolls on first start, with the
// cluster as its identity, and then sends only the "k8s" section. It runs
// only Kubernetes jobs, and those only unless BASELINE_ALLOW_ACTIONS=none,
// and doesn't update itself: it is updated by changing its image.
func runCluster(ctx context.Context, config string) error {
	cfg, err := loadClusterConfig(config)
	if err != nil {
		return err
	}
	log := &jw6_utils.Utils{LogLevel: jw6_utils.LogLevelFromString(cfg.LogLevel)}
	client, err := kubeClient()
	if err != nil {
		return err
	}
	self := kube.Self{Name: cfg.ClusterName, Logs: cfg.Logs}
	st, err := agent.LoadState(cfg.StateDir)
	if errors.Is(err, agent.ErrNotEnrolled) {
		if cfg.Token == "" {
			return fmt.Errorf("not enrolled (no state in %s) and BASELINE_TOKEN is not set", cfg.StateDir)
		}
		id, eerr := agent.Enroll(ctx, cfg.Server, cfg.Token, cfg.StateDir, Version, self)
		if eerr != nil {
			return fmt.Errorf("enrollment failed: %w", eerr)
		}
		log.Log("Agent", "run", jw6_utils.Info, fmt.Sprintf("Enrolled cluster %s as agent %s", cfg.ClusterName, id))
		st, err = agent.LoadState(cfg.StateDir)
	}
	if err != nil {
		return err
	}
	log.Log("Agent", "run", jw6_utils.Info, fmt.Sprintf("baseline-agent %s in cluster mode, cluster %s (%s), agent %s, server %s",
		Version, cfg.ClusterName, client.BaseURL, st.AgentID, cfg.Server))
	col := &kube.Collector{Client: client, ClusterName: cfg.ClusterName, DenyNamespaces: cfg.DenyNamespaces}
	mgr := &kube.Manager{Client: client, DenyNamespaces: cfg.DenyNamespaces}
	policy := action.Policy{Jobs: true, AllowActions: cfg.Actions, SelfUpdateOff: true}
	polls := map[string]agent.PollFunc{
		model.PollK8sPods: func(ctx context.Context, config []byte) (any, error) {
			var r model.K8sPodsRequest
			if err := json.Unmarshal(config, &r); err != nil {
				return nil, err
			}
			return mgr.Pods(ctx, r)
		},
	}
	if cfg.Logs {
		polls[model.PollK8sLogs] = func(ctx context.Context, config []byte) (any, error) {
			var r model.K8sLogsRequest
			if err := json.Unmarshal(config, &r); err != nil {
				return nil, err
			}
			return mgr.Logs(ctx, r)
		}
	}
	log.Log("Agent", "run", jw6_utils.Info, fmt.Sprintf("Kubernetes actions %s, off limits: %s, pod logs %s",
		map[bool]string{true: "on", false: "off"}[len(cfg.Actions) > 0], orNone(cfg.DenyNamespaces),
		map[bool]string{true: "on", false: "off"}[cfg.Logs]))
	a := &agent.Agent{Server: cfg.Server, State: st, Env: self, Version: Version, Log: log, Polls: polls,
		Collectors: map[string]agent.CollectFunc{
			model.SectionK8s: func(ctx context.Context) (any, error) { return col.Collect(ctx) },
		},
		Runner: &runner.Runner{Dir: filepath.Join(cfg.StateDir, "jobs"), Policy: policy, Log: log, Kube: mgr,
			BootID: func() string { return kube.BootID }}}
	return a.Run(ctx)
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

// collectCmd prints what the agent would send, for troubleshooting.
func collectCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	mode := fs.String("mode", "host", "host, or k8s for the cluster's section")
	fs.Parse(args)
	sections := fs.Args()
	switch {
	case *mode == "k8s":
		if len(sections) > 0 && (len(sections) > 1 || sections[0] != model.SectionK8s) {
			return errors.New("collect --mode=k8s takes no sections: the cluster agent has only k8s")
		}
		sections = []string{model.SectionK8s}
	case *mode != "host":
		return fmt.Errorf("unknown mode %q (host, k8s)", *mode)
	case len(sections) == 0:
		// Everything a host agent sends; the cluster's section is asked
		// for by name.
		for _, s := range model.Sections {
			if s != model.SectionK8s {
				sections = append(sections, s)
			}
		}
	}
	hostEnv := collect.Host()
	containers := &collect.ContainerCollector{Env: hostEnv}
	cols := agent.Collectors(hostEnv, nil, containers)
	cols[model.SectionK8s] = func(ctx context.Context) (any, error) {
		client, err := kubeClient()
		if err != nil {
			return nil, err
		}
		name := env.Get("BASELINE_CLUSTER_NAME")
		if name == "" {
			name = "kubernetes"
		}
		return (&kube.Collector{Client: client, ClusterName: name}).Collect(ctx)
	}
	out := map[string]any{}
	for _, s := range sections {
		if s == "metrics" {
			// Rates need two readings.
			sampler := &collect.Sampler{Env: hostEnv}
			sampler.Sample(time.Now())
			containers.Sample(ctx, time.Now())
			time.Sleep(time.Second)
			out[s] = append(sampler.Sample(time.Now()), containers.Sample(ctx, time.Now())...)
			continue
		}
		fn, ok := cols[s]
		if !ok {
			return fmt.Errorf("unknown section %q", s)
		}
		v, err := fn(ctx)
		if err != nil {
			out[s] = map[string]string{"error": err.Error()}
			continue
		}
		out[s] = v
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
