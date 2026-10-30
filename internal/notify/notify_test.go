package notify

import (
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	for _, c := range []struct {
		kind string
		cfg  Config
		want string // "" for an error
	}{
		{Matrix, Config{Homeserver: "https://matrix.example.org", Room: "!abc:example.org", Token: "t"}, "!abc:example.org on matrix.example.org"},
		{Matrix, Config{Homeserver: "https://matrix.example.org", Room: "#ops:example.org", Token: "t"}, "#ops:example.org on matrix.example.org"},
		{Matrix, Config{Homeserver: "matrix.example.org", Room: "#ops:example.org", Token: "t"}, ""},
		{Matrix, Config{Homeserver: "https://m.example", Room: "ops", Token: "t"}, ""},
		{Matrix, Config{Homeserver: "https://m.example", Room: "#ops:m.example"}, ""},
		{Ntfy, Config{Server: "https://ntfy.sh/", Topic: "lab"}, "https://ntfy.sh/lab"},
		{Ntfy, Config{Server: "https://ntfy.sh", Topic: "a/b"}, ""},
		{Ntfy, Config{Topic: "lab"}, ""},
		{"email", Config{}, ""},
	} {
		got, err := Check(c.kind, c.cfg)
		if got != c.want || (err == nil) != (c.want != "") {
			t.Errorf("Check(%s, %+v) = %q, %v; want %q", c.kind, c.cfg, got, err, c.want)
		}
	}
}

func TestBackoff(t *testing.T) {
	var total time.Duration
	for n := 1; n < maxAttempts; n++ {
		total += backoff(n)
	}
	if backoff(1) != 30*time.Second || backoff(2) != time.Minute || backoff(20) != time.Hour || total < 8*time.Hour || total > 10*time.Hour {
		t.Fatalf("backoff: %v %v %v, total %v", backoff(1), backoff(2), backoff(20), total)
	}
}
