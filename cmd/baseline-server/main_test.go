package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestContainerHealthcheckWithPublicPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	t.Setenv("BASELINE_HTTP_ADDR", u.Host)
	t.Setenv("BASELINE_PUBLIC_URL", "https://example.com/cmdb")
	if code := healthcheck(); code != 0 {
		t.Fatalf("healthcheck exit = %d", code)
	}
}
