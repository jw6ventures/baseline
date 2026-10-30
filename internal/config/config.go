// Package config loads the server's infrastructure settings from the
// environment. Anything an admin changes at runtime (role bindings, windows,
// channels...) lives in the database instead.
package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/env"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"
)

type Config struct {
	HTTPAddr     string // BASELINE_HTTP_ADDR
	PublicURL    *url.URL
	DBURL        string // BASELINE_DB_URL
	DBSchema     string // BASELINE_DB_SCHEMA: base schema file
	DBMigrations string // BASELINE_DB_MIGRATIONS: migrations directory

	GRPCAddr string // BASELINE_GRPC_ADDR: agent gateway listen address
	// GRPCPublicAddr is the host:port agents dial (through Traefik's TLS
	// passthrough, or the VPN IP). Its host goes in the gateway's cert.
	GRPCPublicAddr string   // BASELINE_GRPC_PUBLIC_ADDR
	GRPCExtraNames []string // BASELINE_GRPC_EXTRA_NAMES: more cert names, comma-separated
	DataDir        string   // BASELINE_DATA_DIR: PKI and agent releases
	AgentDir       string   // BASELINE_AGENT_DIR: agent binaries served to install.sh

	OIDCIssuer       string // BASELINE_OIDC_ISSUER
	OIDCClientID     string // BASELINE_OIDC_CLIENT_ID
	OIDCClientSecret string // BASELINE_OIDC_CLIENT_SECRET
	OIDCRedirectURL  string // BASELINE_OIDC_REDIRECT_URL, default <public URL>/auth/callback
	GroupsClaim      string // BASELINE_OIDC_GROUPS_CLAIM

	// BootstrapAdminGroup is an IdP group that is always admin, so the first
	// login can create the real role bindings. BASELINE_BOOTSTRAP_ADMIN_GROUP.
	BootstrapAdminGroup string

	CookieKey []byte // BASELINE_COOKIE_KEY: base64, 32 bytes; seals the session cookie
	SecretKey []byte // BASELINE_SECRET_KEY: base64, 32 bytes; encrypts secrets at rest

	Location *time.Location // BASELINE_TZ: display timezone
	LogLevel jw6_utils.LogLevel

	// OSVURL is where OSV vulnerability data is downloaded from
	// (BASELINE_OSV_URL): "" for OSV's own bucket, a mirror's URL, or "off".
	OSVURL string
}

// SecureCookies reports whether cookies get the Secure flag. Only a plain
// http:// public URL (local development) turns it off.
func (c Config) SecureCookies() bool { return c.PublicURL.Scheme != "http" }

// FromEnv reads the process environment, where each BASELINE_ variable falls
// back to its JCMDB_ name (package env).
func FromEnv() (Config, error) { return load(env.Fallback(os.Getenv)) }

func load(getenv func(string) string) (Config, error) {
	get := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}
	c := Config{
		HTTPAddr:            get("BASELINE_HTTP_ADDR", ":8080"),
		DBURL:               get("BASELINE_DB_URL", ""),
		DBSchema:            get("BASELINE_DB_SCHEMA", "db/db.sql"),
		DBMigrations:        get("BASELINE_DB_MIGRATIONS", "db/migrations"),
		GRPCAddr:            get("BASELINE_GRPC_ADDR", ":8443"),
		GRPCPublicAddr:      get("BASELINE_GRPC_PUBLIC_ADDR", ""),
		DataDir:             get("BASELINE_DATA_DIR", "/data"),
		AgentDir:            get("BASELINE_AGENT_DIR", "/app/agent"),
		OIDCIssuer:          get("BASELINE_OIDC_ISSUER", ""),
		OIDCClientID:        get("BASELINE_OIDC_CLIENT_ID", ""),
		OIDCClientSecret:    get("BASELINE_OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:     get("BASELINE_OIDC_REDIRECT_URL", ""),
		GroupsClaim:         get("BASELINE_OIDC_GROUPS_CLAIM", "groups"),
		BootstrapAdminGroup: get("BASELINE_BOOTSTRAP_ADMIN_GROUP", ""),
		LogLevel:            jw6_utils.LogLevelFromString(get("BASELINE_LOG_LEVEL", "Info")),
		OSVURL:              get("BASELINE_OSV_URL", ""),
	}

	var missing []string
	for key, v := range map[string]string{
		"BASELINE_DB_URL":           c.DBURL,
		"BASELINE_OIDC_ISSUER":      c.OIDCIssuer,
		"BASELINE_OIDC_CLIENT_ID":   c.OIDCClientID,
		"BASELINE_PUBLIC_URL":       get("BASELINE_PUBLIC_URL", ""),
		"BASELINE_COOKIE_KEY":       get("BASELINE_COOKIE_KEY", ""),
		"BASELINE_SECRET_KEY":       get("BASELINE_SECRET_KEY", ""),
		"BASELINE_GRPC_PUBLIC_ADDR": c.GRPCPublicAddr,
	} {
		if v == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return c, fmt.Errorf("required settings not set: %s", strings.Join(missing, ", "))
	}

	u, err := url.Parse(get("BASELINE_PUBLIC_URL", ""))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return c, fmt.Errorf("BASELINE_PUBLIC_URL must be an absolute http(s) URL")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	c.PublicURL = u
	if c.OIDCRedirectURL == "" {
		c.OIDCRedirectURL = u.String() + "/auth/callback"
	}

	if c.CookieKey, err = key32("BASELINE_COOKIE_KEY", get("BASELINE_COOKIE_KEY", "")); err != nil {
		return c, err
	}
	if c.SecretKey, err = key32("BASELINE_SECRET_KEY", get("BASELINE_SECRET_KEY", "")); err != nil {
		return c, err
	}

	if _, port, err := net.SplitHostPort(c.GRPCPublicAddr); err != nil || port == "" {
		return c, fmt.Errorf("BASELINE_GRPC_PUBLIC_ADDR must be host:port, e.g. agent.baseline.example.com:443")
	}
	for _, n := range strings.Split(get("BASELINE_GRPC_EXTRA_NAMES", ""), ",") {
		if n = strings.TrimSpace(n); n != "" {
			c.GRPCExtraNames = append(c.GRPCExtraNames, n)
		}
	}

	if c.Location, err = time.LoadLocation(get("BASELINE_TZ", "UTC")); err != nil {
		return c, fmt.Errorf("BASELINE_TZ: %w", err)
	}
	if c.OSVURL != "" && c.OSVURL != "off" {
		if u, err := url.Parse(c.OSVURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return c, fmt.Errorf("BASELINE_OSV_URL must be an http(s) URL or \"off\"")
		}
	}
	return c, nil
}

// key32 decodes a base64 key, as printed by `openssl rand -base64 32`.
func key32(name, v string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("%s: not valid base64: %w", name, err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%s: must decode to 32 bytes, got %d (use `openssl rand -base64 32`)", name, len(b))
	}
	return b, nil
}

// GatewayNames are the names the gateway's server cert must cover.
func (c Config) GatewayNames() []string {
	host, _, _ := net.SplitHostPort(c.GRPCPublicAddr)
	return append([]string{host}, c.GRPCExtraNames...)
}
