package traefik

import (
	"reflect"
	"testing"
)

func TestParseRule(t *testing.T) {
	for _, tc := range []struct {
		rule string
		want []Match
	}{
		{"Host(`app.example.com`)", []Match{{Host, "app.example.com"}}},
		{`Host("App.Example.com.")`, []Match{{Host, "app.example.com"}}},
		// v2: several hosts in one matcher.
		{"Host(`a.example.com`, `b.example.com`)", []Match{{Host, "a.example.com"}, {Host, "b.example.com"}}},
		{"Host(`a.example.com`) || Host(`b.example.com`) && PathPrefix(`/api`)",
			[]Match{{Host, "a.example.com"}, {Host, "b.example.com"}}},
		{"(Host(`a.example.com`) || HostHeader(`b.example.com`)) && !Path(`/x`)",
			[]Match{{Host, "a.example.com"}, {Host, "b.example.com"}}},
		{"Host(`a.example.com`) && !Host(`b.example.com`)", []Match{{Host, "a.example.com"}}},
		{"!(Host(`a.example.com`) || Host(`b.example.com`)) || Host(`c.example.com`)", []Match{{Host, "c.example.com"}}},
		{"!!Host(`a.example.com`)", []Match{{Host, "a.example.com"}}},
		{"HostRegexp(`^(www|api)\\.example\\.com$`)", []Match{{HostRegexp, `^(www|api)\.example\.com$`}}},
		{"HostRegexp(`{sub:[a-z]+}.example.com`)", []Match{{HostRegexp, "{sub:[a-z]+}.example.com"}}},
		{"HostSNI(`agent.example.com`)", []Match{{HostSNI, "agent.example.com"}}},
		{"HostSNI(`*`)", nil},
		{"HostSNIRegexp(`^.+\\.example\\.com$`)", []Match{{HostSNIRegexp, `^.+\.example\.com$`}}},
		// A ")" inside a string doesn't end the matcher.
		{"Path(`/a)b`) && Host(`a.example.com`)", []Match{{Host, "a.example.com"}}},
		{"Host(`a.example.com`) || Host(`a.example.com`)", []Match{{Host, "a.example.com"}}},
		{`Host("a\x2eexample.com")`, []Match{{Host, "a.example.com"}}},
		{"PathPrefix(`/`)", nil},
		{"Host(", nil},
		{"Host(`unterminated", nil},
		{"", nil},
	} {
		if got := ParseRule(tc.rule); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParseRule(%q) = %v, want %v", tc.rule, got, tc.want)
		}
	}
}

func TestRouters(t *testing.T) {
	labels := map[string]string{
		"traefik.enable":                                            "true",
		"traefik.http.routers.app.rule":                             "Host(`app.example.com`)",
		"traefik.http.routers.app.entrypoints":                      "websecure, web",
		"traefik.http.routers.app.tls.certresolver":                 "le",
		"traefik.http.services.app.loadbalancer.server.port":        "8080",
		"traefik.http.routers.plain.rule":                           "Host(`plain.example.com`)",
		"traefik.http.routers.plain.service":                        "app@docker",
		"traefik.http.routers.notls.rule":                           "Host(`x.example.com`)",
		"traefik.http.routers.notls.tls":                            "false",
		"traefik.http.routers.norule.entrypoints":                   "web",
		"traefik.http.middlewares.redirect.redirectscheme.scheme":   "https",
		"traefik.tcp.routers.grpc.rule":                             "HostSNI(`agent.example.com`)",
		"traefik.tcp.routers.grpc.tls.passthrough":                  "true",
		"traefik.tcp.services.grpc.loadbalancer.server.port":        "8443",
		"traefik.udp.routers.dns.entrypoints":                       "dns",
		"com.docker.compose.project":                                "web",
		"traefik.http.routers.app.middlewares":                      "redirect",
		"traefik.http.services.app.loadbalancer.passhostheader":     "true",
		"traefik.http.routers.app.tls.domains[0].main":              "example.com",
		"traefik.http.routers.app.tls.domains[0].sans":              "*.example.com",
		"traefik.http.services.other.loadbalancer.server.scheme":    "http",
		"traefik.http.services.other.loadbalancer.healthcheck.path": "/",
	}
	got := Routers(labels)
	want := []Router{
		{Name: "app", Protocol: "http", Rule: "Host(`app.example.com`)", EntryPoints: []string{"web", "websecure"}, TLS: true,
			Matches: []Match{{Host, "app.example.com"}}}, // two services: Traefik needs it to name one
		{Name: "notls", Protocol: "http", Rule: "Host(`x.example.com`)", Matches: []Match{{Host, "x.example.com"}}},
		{Name: "plain", Protocol: "http", Rule: "Host(`plain.example.com`)", Service: "app@docker", Port: 8080,
			Matches: []Match{{Host, "plain.example.com"}}},
		{Name: "grpc", Protocol: "tcp", Rule: "HostSNI(`agent.example.com`)", TLS: true, Port: 8443,
			Matches: []Match{{HostSNI, "agent.example.com"}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Routers =\n%+v\nwant\n%+v", got, want)
	}

	// One service: routers without their own go there.
	delete(labels, "traefik.http.services.other.loadbalancer.server.scheme")
	delete(labels, "traefik.http.services.other.loadbalancer.healthcheck.path")
	if got := Routers(labels); got[0].Port != 8080 || got[1].Name != "notls" || got[1].Port != 8080 {
		t.Fatalf("one service: %+v", got)
	}

	labels["traefik.enable"] = "false"
	if got := Routers(labels); got != nil {
		t.Fatalf("disabled: %+v", got)
	}
	if got := Routers(nil); got != nil {
		t.Fatalf("no labels: %+v", got)
	}
}
