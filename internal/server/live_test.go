package server

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// A live status poll whose session has ended gets a 401 the page can show,
// not a redirect into the sign-in flow.
func TestLivePollSignedOut(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(h.client(), "GET", "/", nil, livePollHeader, "1")
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Location") != "" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// Polling doesn't keep a session alive; a page load does.
func TestLivePollDoesNotSlideSession(t *testing.T) {
	h := newHarness(t)
	c := h.signIn("ann", "lab-admins")
	back := func() {
		h.st.DB().Exec(`UPDATE session SET last_seen = now() - interval '10 minutes', expires_at = now() + interval '1 hour'`)
	}
	expiry := func() time.Duration {
		var exp time.Time
		h.st.DB().QueryRow(`SELECT expires_at FROM session`).Scan(&exp)
		return time.Until(exp)
	}
	back()
	if resp, _ := h.do(c, "GET", "/", nil, livePollHeader, "1"); resp.StatusCode != 200 {
		t.Fatalf("poll: %d", resp.StatusCode)
	}
	if d := expiry(); d > 61*time.Minute {
		t.Fatalf("a poll slid the session to %v", d)
	}
	if resp, _ := h.do(c, "GET", "/", nil); resp.StatusCode != 200 {
		t.Fatalf("load: %d", resp.StatusCode)
	}
	if d := expiry(); d < idleTimeout-time.Minute {
		t.Fatalf("a page load didn't slide the session: %v", d)
	}
}

// The dashboard and a host page mark the regions live.js refreshes, and a
// host tab other than the overview polls the overview for its header.
func TestLiveRegions(t *testing.T) {
	h := newHarness(t)
	res := h.addHost("web1")
	c := h.signIn("ann", "lab-admins")
	_, body := h.do(c, "GET", "/", nil)
	for _, want := range []string{`static/live.js`, `id="dashboard-live" data-live data-live-src="/"`, `id="live-note"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard lacks %s", want)
		}
	}
	id := res.HostID
	_, body = h.do(c, "GET", "/hosts/"+id, nil)
	for _, want := range []string{`data-live-src="/hosts/` + id + `"`, `id="host-status" data-live`, `id="host-notices" data-live`, `id="host-overview" data-live`, `id="tab-n-overview" data-live`} {
		if !strings.Contains(body, want) {
			t.Fatalf("host page lacks %s", want)
		}
	}
	_, body = h.do(c, "GET", "/hosts/"+id+"?tab=history", nil)
	if !strings.Contains(body, `data-live-src="/hosts/`+id+`"`) || strings.Contains(body, `id="host-overview"`) {
		t.Fatal("history tab should poll the overview for its header only")
	}
}
