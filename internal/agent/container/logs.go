package container

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// LogLine is one line of a container's log: its stream (stdout or stderr)
// and the text, which starts with the engine's RFC 3339 timestamp.
type LogLine struct {
	Stream string
	Text   string
}

// maxLogLine caps one line; longer ones are cut and marked.
const maxLogLine = 16 << 10

// LogsOptions are what Logs reads.
type LogsOptions struct {
	Tail   int  // lines from the end; 0 reads none, only what follows
	Follow bool // keep reading new lines until ctx ends
}

// Logs reads a container's log and calls emit for each line, in order,
// until the log ends (or, with Follow, until ctx ends or the container is
// removed). It reads the engine's log endpoint, which Docker and Podman
// both serve; a container started with a TTY has one raw stream, reported
// as stdout. ctx alone bounds a followed read.
func (c *Client) Logs(ctx context.Context, id string, opt LogsOptions, emit func(LogLine)) error {
	in, err := c.Inspect(ctx, id)
	if err != nil {
		return err
	}
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"}, "tail": {strconv.Itoa(max(opt.Tail, 0))}}
	if opt.Follow {
		q.Set("follow", "1")
	}
	c.mu.Lock()
	prefix, kind := c.prefix, c.kind
	c.mu.Unlock()
	path := "/containers/" + url.PathEscape(id) + "/logs"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://engine"+prefix+path+"?"+q.Encode(), nil)
	if err != nil {
		return fmt.Errorf("%s: GET %s: %w", kind, path, err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("%s: GET %s: %w", kind, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		e := &Error{Engine: kind, Method: http.MethodGet, Path: path, Status: resp.StatusCode, Message: strings.ToLower(http.StatusText(resp.StatusCode))}
		if m := jsonMessage(body); m != "" {
			e.Message = m
		}
		return e
	}
	// The media type says how the body is framed where the engine sets
	// it (Docker API 1.42+); otherwise the container's TTY setting does.
	raw := in.Config.Tty
	switch resp.Header.Get("Content-Type") {
	case "application/vnd.docker.raw-stream":
		raw = true
	case "application/vnd.docker.multiplexed-stream":
		raw = false
	}
	if raw {
		err = splitLines(resp.Body, "stdout", emit)
	} else {
		err = demux(resp.Body, emit)
	}
	if err != nil && ctx.Err() != nil {
		return nil // stopped on purpose
	}
	return err
}

// demux reads the engines' framed stream: each frame is an 8-byte header
// (stream type, three zero bytes, big-endian length) and its payload.
// Lines may span frames, so each stream keeps its own partial line.
func demux(r io.Reader, emit func(LogLine)) error {
	br := bufio.NewReaderSize(r, 32<<10)
	var hdr [8]byte
	partial := map[string]*strings.Builder{"stdout": {}, "stderr": {}}
	flush := func() {
		for _, s := range []string{"stdout", "stderr"} {
			if b := partial[s]; b.Len() > 0 {
				emit(LogLine{Stream: s, Text: b.String()})
				b.Reset()
			}
		}
	}
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			flush()
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		stream := "stdout"
		if hdr[0] == 2 {
			stream = "stderr"
		}
		n := int64(binary.BigEndian.Uint32(hdr[4:]))
		b := partial[stream]
		if err := linesOf(io.LimitReader(br, n), b, stream, emit); err != nil {
			flush()
			return err
		}
	}
}

// splitLines reads an unframed stream line by line.
func splitLines(r io.Reader, stream string, emit func(LogLine)) error {
	var b strings.Builder
	err := linesOf(r, &b, stream, emit)
	if b.Len() > 0 {
		emit(LogLine{Stream: stream, Text: b.String()})
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// linesOf reads r to its end, emitting each complete line and keeping the
// rest in partial. A line longer than maxLogLine is cut there.
func linesOf(r io.Reader, partial *strings.Builder, stream string, emit func(LogLine)) error {
	buf := make([]byte, 8<<10)
	for {
		n, err := r.Read(buf)
		chunk := buf[:n]
		for len(chunk) > 0 {
			i := strings.IndexByte(string(chunk), '\n')
			part := chunk
			if i >= 0 {
				part = chunk[:i]
			}
			if room := maxLogLine - partial.Len(); room > 0 {
				partial.Write(part[:min(len(part), room)])
			}
			if i < 0 {
				break
			}
			text := strings.TrimSuffix(partial.String(), "\r")
			if partial.Len() >= maxLogLine {
				text += " …(line cut)"
			}
			emit(LogLine{Stream: stream, Text: text})
			partial.Reset()
			chunk = chunk[i+1:]
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func jsonMessage(body []byte) string {
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &m) == nil && m.Message != "" {
		if len(m.Message) > 200 {
			return m.Message[:200] + "…"
		}
		return m.Message
	}
	return ""
}
