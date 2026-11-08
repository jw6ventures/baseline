// Command baseline-server is the Baseline server: web UI, API and the agent
// gateway.
//
// Usage:
//
//	baseline-server [serve]     run the server (default)
//	baseline-server healthcheck exit 0 if the local server answers /healthz
//	baseline-server version     print the version
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // BASELINE_TZ works in minimal container images

	jw6_utils "github.com/jw6ventures/jw6-go-utils"
	"github.com/jw6ventures/jw6-go-utils/oidc"

	"github.com/jw6ventures/baseline/internal/alert"
	"github.com/jw6ventures/baseline/internal/checks"
	"github.com/jw6ventures/baseline/internal/config"
	"github.com/jw6ventures/baseline/internal/env"
	"github.com/jw6ventures/baseline/internal/gateway"
	"github.com/jw6ventures/baseline/internal/jobs"
	"github.com/jw6ventures/baseline/internal/notify"
	"github.com/jw6ventures/baseline/internal/pki"
	"github.com/jw6ventures/baseline/internal/release"
	"github.com/jw6ventures/baseline/internal/server"
	"github.com/jw6ventures/baseline/internal/store"
	"github.com/jw6ventures/baseline/internal/unifipoll"
	"github.com/jw6ventures/baseline/internal/vuln"
)

// Version is set at build time with -ldflags "-X main.Version=...": the
// release tag, or for a local build the git description (Makefile) or the
// newest schema migration (Dockerfile).
var Version = "dev"

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "version":
		fmt.Println(Version)
		return
	case "healthcheck":
		os.Exit(healthcheck())
	case "serve":
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}

	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(2)
	}
	log := &jw6_utils.Utils{LogLevel: cfg.LogLevel}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := serve(ctx, cfg, log); err != nil {
		log.Log("Main", "serve", jw6_utils.Fatal, err.Error())
		os.Exit(1)
	}
}

func serve(ctx context.Context, cfg config.Config, log *jw6_utils.Utils) error {
	log.PrintBanner("Baseline", Version, "2026", 4, "James Williams")
	if legacy := env.Legacy(); len(legacy) > 0 {
		log.Log("Main", "serve", jw6_utils.Warn, fmt.Sprintf("Read %s as BASELINE_ variables; rename them to BASELINE_", strings.Join(legacy, ", ")))
	}

	st, err := store.Open(ctx, store.Options{
		URL:            cfg.DBURL,
		SchemaPath:     cfg.DBSchema,
		MigrationsPath: cfg.DBMigrations,
		Logger:         log,
	})
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer st.Close()

	auth := &server.LazyAuthenticator{Config: oidc.Config{
		Issuer:       cfg.OIDCIssuer,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
		Scopes:       []string{"openid", "profile", "email"},
		Logger:       log,
	}}
	if err := auth.Warm(ctx); err != nil {
		log.Log("Main", "serve", jw6_utils.Warn, "OIDC discovery failed, will retry on first sign-in: "+err.Error())
	}

	ca, err := pki.Load(filepath.Join(cfg.DataDir, "pki"), cfg.GatewayNames())
	if err != nil {
		return err
	}
	gw := gateway.New(st, ca, log)

	if keys, err := pki.ReleaseKeys(); err != nil {
		log.Log("Main", "serve", jw6_utils.Warn, "agent releases: "+err.Error())
	} else if pub, err := release.Publish(ctx, st, ca, keys, cfg.AgentDir, cfg.DataDir, Version); err != nil {
		log.Log("Main", "serve", jw6_utils.Warn, "agent releases: "+err.Error())
	} else if len(pub) > 0 {
		var arches, unsigned []string
		for _, p := range pub {
			if arches = append(arches, p.Arch); !p.Signed {
				unsigned = append(unsigned, p.Arch)
			}
		}
		log.Log("Main", "serve", jw6_utils.Info, fmt.Sprintf("Published agent %s for %v", Version, arches))
		if len(unsigned) > 0 {
			log.Log("Main", "serve", jw6_utils.Warn, fmt.Sprintf(
				"Agent %s for %v has no valid release signature; agents will refuse to update to it (only release builds are signed)", Version, unsigned))
		}
	}
	// Partitions must exist before the first agent sends metrics.
	if err := st.MaintainMetrics(ctx, time.Now()); err != nil {
		return fmt.Errorf("metric partitions: %w", err)
	}
	go maintainMetrics(ctx, st, log)

	srv, err := server.New(cfg, st, auth, gw, ca.CAFingerprint(), log, Version)
	if err != nil {
		return err
	}
	go srv.PurgeSessions(ctx, time.Hour)

	secrets, err := oidc.NewCookieCodec(cfg.SecretKey)
	if err != nil {
		return err
	}
	checker := &checks.Checker{Store: st, Log: log, Credentials: func(ctx context.Context) (map[string][2]string, error) {
		return server.RegistryCredentials(ctx, st, secrets)
	}}
	srv.SetChecker(checker)
	gw.Checker = checker
	go checker.Run(ctx)

	// OSV data: synced daily, and matched whenever a host's packages change.
	osvURL := cfg.OSVURL
	switch osvURL {
	case "":
		osvURL = vuln.DefaultURL
	case "off":
		osvURL = ""
	}
	tmp := filepath.Join(cfg.DataDir, "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return err
	}
	if old, _ := filepath.Glob(filepath.Join(tmp, "osv-*.zip")); len(old) > 0 {
		for _, f := range old {
			os.Remove(f) // left by a sync the server was stopped in
		}
	}
	syncer := &vuln.Syncer{Store: st, Log: log, URL: osvURL, TempDir: tmp}
	gw.Vulns = syncer
	if osvURL != "" {
		srv.SetVulns(syncer)
	}
	go syncer.Run(ctx)

	// Alerts: evaluated every minute, delivered through the outbox.
	notifier := &notify.Notifier{Store: st, Open: secrets.Open, Log: log}
	srv.SetNotifier(notifier)
	go notifier.Run(ctx)
	evaluator := &alert.Evaluator{Store: st, Log: log, PublicURL: cfg.PublicURL.String(), Nudge: notifier.Nudge}
	go evaluator.Run(ctx)

	// UniFi consoles: polled every 5 minutes, from here or through an agent.
	unifiPoller := &unifipoll.Poller{Store: st, Open: secrets.Open, Agents: gw, Log: log}
	srv.SetUniFi(unifiPoller)
	srv.SetAgentPolls(gw)
	srv.SetContainerLogs(gw)
	go unifiPoller.Run(ctx)

	dispatcher := jobs.New(st, gw, log)
	dispatcher.Secrets = secrets
	srv.SetJobs(dispatcher)
	gw.Jobs = dispatcher
	go dispatcher.Run(ctx)
	go dispatcher.Changes().Run(ctx)
	// Workflow migrations run in the background, batch by batch.
	srv.RunMigrations(ctx)

	httpSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 2)
	go func() { errc <- httpSrv.ListenAndServe() }()
	log.Log("Main", "serve", jw6_utils.Info, fmt.Sprintf("Web UI on %s, public URL %s", cfg.HTTPAddr, cfg.PublicURL))

	gwCtx, stopGateway := context.WithCancel(ctx)
	defer stopGateway()
	go func() {
		if err := gw.Serve(gwCtx, cfg.GRPCAddr); err != nil {
			errc <- fmt.Errorf("agent gateway: %w", err)
		}
	}()
	log.Log("Main", "serve", jw6_utils.Info, fmt.Sprintf("Agents dial %s (CA fingerprint %x)", cfg.GRPCPublicAddr, ca.CAFingerprint()[:8]))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	stopGateway()
	log.Log("Main", "serve", jw6_utils.Info, "Shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// maintainMetrics rolls metrics up every five minutes and manages their
// daily partitions every hour.
func maintainMetrics(ctx context.Context, st *store.Store, log *jw6_utils.Utils) {
	rollup := time.NewTicker(store.RollupStep)
	defer rollup.Stop()
	partitions := time.NewTicker(time.Hour)
	defer partitions.Stop()
	for {
		var err error
		select {
		case <-ctx.Done():
			return
		case now := <-rollup.C:
			err = st.RollupMetrics(ctx, now)
		case now := <-partitions.C:
			err = st.MaintainMetrics(ctx, now)
		}
		if err != nil && ctx.Err() == nil {
			log.Log("Main", "metrics", jw6_utils.Error, err.Error())
		}
	}
}

// healthcheck is for the container HEALTHCHECK: the distroless image has no
// curl.
func healthcheck() int {
	addr := env.Get("BASELINE_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "BASELINE_HTTP_ADDR:", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	addr = net.JoinHostPort(host, port)
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "status", resp.Status)
		return 1
	}
	return 0
}
