package container

import (
	"context"
	"encoding/binary"
	"net/http"
	"strings"
	"testing"
	"time"
)

// frame is one frame of the engines' multiplexed log stream.
func frame(stream byte, s string) string {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(s)))
	return string(h) + s
}

func collectLogs(t *testing.T, c *Client, id string, opt LogsOptions) ([]LogLine, error) {
	t.Helper()
	var out []LogLine
	err := c.Logs(context.Background(), id, opt, func(l LogLine) { out = append(out, l) })
	return out, err
}

// The framed stream is split into stdout and stderr lines, lines spanning
// frames are joined, and the request asks for timestamps and the tail.
func TestLogsMultiplexed(t *testing.T) {
	var query string
	sock := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/web/json":
			w.Write([]byte(`{"Id":"abc","Config":{"Tty":false}}`))
		case "/containers/web/logs":
			query = r.URL.RawQuery
			w.Write([]byte(frame(1, "2026-11-07T10:00:00Z GET / 200\n2026-11-07T10:00:01Z GET /a") +
				frame(2, "2026-11-07T10:00:01Z oops\r\n") + frame(1, "pi 404\n") + frame(1, "no newline")))
		default:
			http.NotFound(w, r)
		}
	}))
	lines, err := collectLogs(t, New(sock), "web", LogsOptions{Tail: 50})
	if err != nil {
		t.Fatal(err)
	}
	want := []LogLine{{"stdout", "2026-11-07T10:00:00Z GET / 200"}, {"stderr", "2026-11-07T10:00:01Z oops"},
		{"stdout", "2026-11-07T10:00:01Z GET /api 404"}, {"stdout", "no newline"}}
	if len(lines) != len(want) {
		t.Fatalf("lines %q", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("line %d: %q, want %q", i, lines[i], want[i])
		}
	}
	if !strings.Contains(query, "tail=50") || !strings.Contains(query, "timestamps=1") || strings.Contains(query, "follow") {
		t.Fatalf("query %s", query)
	}
}

// A container with a TTY has one raw stream; the media type wins over the
// TTY setting where the engine sends it. Overlong lines are cut.
func TestLogsRawAndLongLines(t *testing.T) {
	long := strings.Repeat("x", maxLogLine+100)
	sock := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/tty/json":
			w.Write([]byte(`{"Id":"t","Config":{"Tty":true}}`))
		case "/containers/tty/logs":
			w.Write([]byte("one\n" + long + "\ntwo\n"))
		case "/containers/typed/json":
			w.Write([]byte(`{"Id":"t","Config":{"Tty":false}}`))
		case "/containers/typed/logs":
			w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
			w.Write([]byte("raw line\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"No such container: gone"}`))
		}
	}))
	c := New(sock)
	lines, err := collectLogs(t, c, "tty", LogsOptions{})
	if err != nil || len(lines) != 3 || lines[0].Text != "one" || lines[2].Text != "two" ||
		!strings.HasSuffix(lines[1].Text, "…(line cut)") || len(lines[1].Text) > maxLogLine+20 {
		t.Fatalf("tty lines: %v %d", err, len(lines))
	}
	if lines, err := collectLogs(t, c, "typed", LogsOptions{}); err != nil || len(lines) != 1 || lines[0].Text != "raw line" {
		t.Fatalf("raw-stream lines %q %v", lines, err)
	}
	if _, err := collectLogs(t, c, "gone", LogsOptions{}); !IsNotFound(err) || !strings.Contains(err.Error(), "No such container") {
		t.Fatalf("missing container: %v", err)
	}
}

// A followed log streams until the context ends, which isn't an error.
func TestLogsFollow(t *testing.T) {
	sock := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/web/json" {
			w.Write([]byte(`{"Id":"abc"}`))
			return
		}
		if r.URL.Query().Get("follow") != "1" {
			t.Errorf("not followed: %s", r.URL.RawQuery)
		}
		w.Write([]byte(frame(1, "first\n")))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got := make(chan LogLine, 4)
	errc := make(chan error, 1)
	go func() {
		errc <- New(sock).Logs(ctx, "web", LogsOptions{Follow: true}, func(l LogLine) { got <- l })
	}()
	if l := <-got; l.Text != "first" {
		t.Fatalf("line %q", l)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("stopping a followed log: %v", err)
	}
}
