package composefile

import (
	"errors"
	"strings"
	"testing"
)

const file = `# Duplicati with an Authentik outpost
services:
  duplicati:
    image: lscr.io/linuxserver/duplicati:latest   # nightly
    restart: unless-stopped
  "proxy":
    # keep with the server
    image: "ghcr.io/goauthentik/proxy:2026.8"
    environment:
      AUTHENTIK_HOST: https://auth.example.com
      image: not-this
  ldap:
    image: ${LDAP_IMAGE:-ghcr.io/goauthentik/ldap:2026.8}
  pinned:
    image: ghcr.io/goauthentik/rac@sha256:abc
  bare:
    image: localhost:5000/tool
  shared:
    <<: *defaults
volumes:
  data:
    image: no
`

func TestSetTag(t *testing.T) {
	out, old, err := SetTag([]byte(file), "proxy", "2026.9")
	if err != nil {
		t.Fatal(err)
	}
	if old != "ghcr.io/goauthentik/proxy:2026.8" {
		t.Errorf("old = %q", old)
	}
	want := strings.Replace(file, `"ghcr.io/goauthentik/proxy:2026.8"`, `"ghcr.io/goauthentik/proxy:2026.9"`, 1)
	if string(out) != want {
		t.Errorf("got\n%s", out)
	}

	out, _, err = SetTag([]byte(file), "duplicati", "2.1")
	if err != nil || !strings.Contains(string(out), "    image: lscr.io/linuxserver/duplicati:2.1   # nightly\n") {
		t.Errorf("comment kept: %v\n%s", err, out)
	}
	out, _, err = SetTag([]byte(file), "bare", "v2")
	if err != nil || !strings.Contains(string(out), "image: localhost:5000/tool:v2\n") {
		t.Errorf("registry port, no tag: %v\n%s", err, out)
	}
	for svc, want := range map[string]string{"ldap": "variable", "pinned": "digest", "shared": "no image", "nope": "no service"} {
		if _, _, err := SetTag([]byte(file), svc, "x"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", svc, err, want)
		}
	}
	if _, _, err := SetTag([]byte(file), "shared", "x"); !errors.Is(err, ErrNoImage) {
		t.Errorf("shared: %v", err)
	}
	crlf := strings.ReplaceAll(file, "\n", "\r\n")
	out, _, err = SetTag([]byte(crlf), "proxy", "2026.9")
	if err != nil || !strings.Contains(string(out), `"ghcr.io/goauthentik/proxy:2026.9"`+"\r\n") {
		t.Errorf("CRLF: %v", err)
	}
}

func TestWithTag(t *testing.T) {
	for in, want := range map[string]string{
		"nginx":                      "nginx:x",
		"nginx:1.27":                 "nginx:x",
		"localhost:5000/tool":        "localhost:5000/tool:x",
		"localhost:5000/tool:1":      "localhost:5000/tool:x",
		"ghcr.io/goauthentik/server": "ghcr.io/goauthentik/server:x",
	} {
		if got := WithTag(in, "x"); got != want {
			t.Errorf("WithTag(%q) = %q, want %q", in, got, want)
		}
	}
}
