package config

import (
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/env"
)

const testKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // 32 bytes

func vars(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func valid() map[string]string {
	return map[string]string{
		"BASELINE_DB_URL":           "postgres://x",
		"BASELINE_OIDC_ISSUER":      "https://auth.example/application/o/baseline/",
		"BASELINE_OIDC_CLIENT_ID":   "baseline",
		"BASELINE_PUBLIC_URL":       "https://baseline.example/",
		"BASELINE_COOKIE_KEY":       testKey,
		"BASELINE_SECRET_KEY":       testKey,
		"BASELINE_GRPC_PUBLIC_ADDR": "agent.baseline.example:443",
	}
}

func TestLoadDefaults(t *testing.T) {
	c, err := load(vars(valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c.OIDCRedirectURL != "https://baseline.example/auth/callback" {
		t.Errorf("redirect = %q", c.OIDCRedirectURL)
	}
	if !c.SecureCookies() {
		t.Error("https public URL should give secure cookies")
	}
	if c.HTTPAddr != ":8080" || c.GroupsClaim != "groups" || c.Location.String() != "UTC" {
		t.Errorf("defaults: %+v", c)
	}
}

func TestLoadListsAllMissing(t *testing.T) {
	_, err := load(vars(nil))
	if err == nil {
		t.Fatal("want error")
	}
	for _, k := range []string{"BASELINE_DB_URL", "BASELINE_COOKIE_KEY", "BASELINE_PUBLIC_URL"} {
		if !strings.Contains(err.Error(), k) {
			t.Errorf("error %q does not name %s", err, k)
		}
	}
}

func TestLoadRejectsShortKey(t *testing.T) {
	m := valid()
	m["BASELINE_SECRET_KEY"] = "c2hvcnQ="
	if _, err := load(vars(m)); err == nil || !strings.Contains(err.Error(), "BASELINE_SECRET_KEY") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadHTTPForDev(t *testing.T) {
	m := valid()
	m["BASELINE_PUBLIC_URL"] = "http://localhost:8080"
	c, err := load(vars(m))
	if err != nil {
		t.Fatal(err)
	}
	if c.SecureCookies() {
		t.Error("http public URL should not set Secure")
	}
}

func TestGatewaySettings(t *testing.T) {
	m := valid()
	m["BASELINE_GRPC_EXTRA_NAMES"] = "10.8.0.1, gw.lan"
	c, err := load(vars(m))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.GatewayNames(), ","); got != "agent.baseline.example,10.8.0.1,gw.lan" {
		t.Errorf("names = %s", got)
	}
	if c.GRPCAddr != ":8443" || c.DataDir != "/data" {
		t.Errorf("defaults: %+v", c)
	}
	m["BASELINE_GRPC_PUBLIC_ADDR"] = "agent.baseline.example"
	if _, err := load(vars(m)); err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Errorf("missing port: %v", err)
	}
}

// An environment from before the rename to Baseline still loads.
func TestLoadLegacyNames(t *testing.T) {
	legacy := map[string]string{}
	for k, v := range valid() {
		legacy["JCMDB_"+strings.TrimPrefix(k, "BASELINE_")] = v
	}
	legacy["JCMDB_TZ"] = "America/Chicago"
	legacy["BASELINE_TZ"] = "Europe/Berlin" // the new name wins
	c, err := load(env.Fallback(vars(legacy)))
	if err != nil {
		t.Fatal(err)
	}
	if c.DBURL != "postgres://x" || c.Location.String() != "Europe/Berlin" {
		t.Errorf("legacy: %+v", c)
	}
}
