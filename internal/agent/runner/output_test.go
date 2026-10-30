package runner

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
)

// outputRunner is a Runner with an outbox, for testing output directly.
func outputRunner(t *testing.T) *Runner {
	r := &Runner{Dir: t.TempDir()}
	r.setup()
	return r
}

// drain takes every waiting event.
func drain(r *Runner) []*agentv1.JobEvent {
	var evs []*agentv1.JobEvent
	for ev := r.Next(); ev != nil; ev = r.Next() {
		r.Sent(ev)
		evs = append(evs, ev)
	}
	return evs
}

// flush is a ticker flush.
func flush(o *output) {
	o.mu.Lock()
	o.flushLocked(false)
	o.mu.Unlock()
}

// checkChunks checks OUTPUT events are numbered from 1, valid UTF-8 and at
// most flushBytes each.
func checkChunks(t *testing.T, evs []*agentv1.JobEvent) {
	t.Helper()
	for i, ev := range evs {
		if ev.GetType() != agentv1.JobEvent_OUTPUT || ev.GetSeq() != uint64(i+1) || ev.GetJobId() != jobID(1) {
			t.Errorf("event %d = %v %d", i, ev.GetType(), ev.GetSeq())
		}
		if !utf8.Valid(ev.GetData()) {
			t.Errorf("event %d: invalid UTF-8 %q", i, ev.GetData())
		}
		if len(ev.GetData()) == 0 || len(ev.GetData()) > flushBytes {
			t.Errorf("event %d: %d bytes", i, len(ev.GetData()))
		}
	}
}

func TestOutputKeepsRunesWhole(t *testing.T) {
	text := []byte("héllo wörld € 𝄞 done")
	for cut := 1; cut < len(text); cut++ {
		r := outputRunner(t)
		o := newOutput(r, jobID(1))
		w := o.stream("stdout")
		w.Write(text[:cut])
		flush(o) // the ticker fires between the two writes
		w.Write(text[cut:])
		o.close()
		evs := drain(r)
		checkChunks(t, evs)
		if got := outputOf(evs, "stdout"); got != string(text) {
			t.Errorf("cut %d: %q", cut, got)
		}
	}
	// Split inside é: the first flush holds the lead byte back.
	r := outputRunner(t)
	o := newOutput(r, jobID(1))
	o.stream("stdout").Write([]byte("h\xc3"))
	flush(o)
	if evs := drain(r); len(evs) != 1 || string(evs[0].GetData()) != "h" {
		t.Errorf("first flush = %v", evs)
	}
	o.stream("stdout").Write([]byte("\xa9llo"))
	o.close()
	if evs := drain(r); len(evs) != 1 || string(evs[0].GetData()) != "éllo" || evs[0].GetSeq() != 2 {
		t.Errorf("second flush = %v", evs)
	}
}

// Only the last segment's incomplete tail is held back, so when stderr
// writes between the two halves of a stdout rune, the halves go out as
// separate, invalid chunks.
func TestOutputKeepsRunesWholeAcrossStreams(t *testing.T) {
	r := outputRunner(t)
	o := newOutput(r, jobID(1))
	o.stream("stdout").Write([]byte("h\xc3"))
	o.stream("stderr").Write([]byte("x"))
	flush(o)
	o.stream("stdout").Write([]byte("\xa9llo"))
	o.close()
	evs := drain(r)
	checkChunks(t, evs)
	if got := outputOf(evs, "stdout"); got != "héllo" {
		t.Errorf("stdout = %q", got)
	}
}

func TestOutputLargeChunks(t *testing.T) {
	r := outputRunner(t)
	o := newOutput(r, jobID(1))
	// ASCII, then two-byte runes that straddle every 32 KiB boundary.
	text := strings.Repeat("a", 100_001) + strings.Repeat("é", 40_000)
	o.stream("stdout").Write([]byte(text))
	o.stream("stderr").Write([]byte("tail"))
	o.close()
	evs := drain(r)
	checkChunks(t, evs)
	if got := outputOf(evs, "stdout"); got != text {
		t.Errorf("stdout: %d bytes, want %d", len(got), len(text))
	}
	if len(evs) < (len(text)+flushBytes-1)/flushBytes+1 {
		t.Errorf("%d events", len(evs))
	}
	if last := evs[len(evs)-1]; last.GetStream() != "stderr" || string(last.GetData()) != "tail" {
		t.Errorf("last = %v", last)
	}
}

func TestOutputManySmallWritesFlushAt32KiB(t *testing.T) {
	r := outputRunner(t)
	o := &output{r: r, job: jobID(1), done: make(chan struct{})} // no ticker
	line := []byte(strings.Repeat("x", 99) + "\n")
	for range 400 { // 40000 bytes
		o.stream("stdout").Write(line)
	}
	// One flush happened when 32 KiB were pending.
	evs := drain(r)
	if n := len(outputOf(evs, "")); n != 32800 { // the first write that reached 32 KiB
		t.Errorf("size-triggered flush sent %d bytes", n)
	}
	o.close()
	evs = append(evs, drain(r)...)
	checkChunks(t, evs)
	if got := outputOf(evs, "stdout"); got != strings.Repeat(string(line), 400) {
		t.Errorf("stdout: %d bytes", len(got))
	}
}

func TestOutputTickerFlushes(t *testing.T) {
	r := outputRunner(t)
	o := newOutput(r, jobID(1))
	defer o.close()
	o.stream("stdout").Write([]byte("hello\n"))
	select {
	case <-r.Ready():
	case <-time.After(5 * flushEvery):
		t.Fatal("not flushed")
	}
	if evs := drain(r); len(evs) != 1 || string(evs[0].GetData()) != "hello\n" {
		t.Errorf("events = %v", evs)
	}
}

func TestOutputTruncated(t *testing.T) {
	r := outputRunner(t)
	o := newOutput(r, jobID(1))
	w := o.stream("stdout")
	w.Write(bytes.Repeat([]byte("a"), maxOutput-10))
	w.Write(bytes.Repeat([]byte("b"), 100)) // over the cap: dropped, with a note
	w.Write([]byte("c"))
	o.info("agent line\n")
	o.close()
	o.info("after close\n")
	evs := drain(r)
	checkChunks(t, evs)
	if got := outputOf(evs, "stdout"); len(got) != maxOutput-10 || strings.ContainsAny(got, "bc") {
		t.Errorf("stdout: %d bytes", len(got))
	}
	if info := outputOf(evs, "info"); info != "\n[output truncated: the agent sends at most 6 MB per job]\n" {
		t.Errorf("info = %q", info)
	}
}

func TestOutputFinalFlushSendsIncompleteRune(t *testing.T) {
	r := outputRunner(t)
	o := newOutput(r, jobID(1))
	o.stream("stdout").Write([]byte("ab\xe2\x82"))
	o.close()
	if got := outputOf(drain(r), "stdout"); got != "ab\xe2\x82" {
		t.Errorf("stdout = %q", got)
	}
}

func TestUTF8Prefix(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"h\xc3", 1},
		{"hé", 3},
		{"€"[:2], 0},
		{"a" + "𝄞"[:3], 1},
		{"a𝄞", 5},
		{"\xa9\xa9", 2}, // stray continuation bytes are left alone
		{"a\xff", 2},
	} {
		if got := utf8Prefix([]byte(tc.in)); got != tc.want {
			t.Errorf("utf8Prefix(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestOutbox(t *testing.T) {
	o := newOutbox()
	out := func(n int) *agentv1.JobEvent {
		return &agentv1.JobEvent{JobId: jobID(1), Type: agentv1.JobEvent_OUTPUT, Data: make([]byte, n)}
	}
	big := out(maxOutbox)
	o.push(big)
	o.push(out(1)) // over the cap: dropped
	res := &agentv1.JobEvent{JobId: jobID(1), Type: agentv1.JobEvent_RESULT, State: "succeeded"}
	o.push(res) // results always fit
	select {
	case <-o.ready:
	default:
		t.Error("not ready")
	}
	if o.peek() != big {
		t.Fatal("first event")
	}
	o.pop(res) // not the head: ignored
	if o.peek() != big {
		t.Fatal("popped the wrong event")
	}
	o.pop(big)
	if o.peek() != res || o.bytes != 0 {
		t.Fatalf("after pop: %v %d", o.peek(), o.bytes)
	}
	// With room again, output is accepted.
	small := out(10)
	o.push(small)
	o.pop(res)
	if o.peek() != small || o.bytes != 10 {
		t.Errorf("after room: %v %d", o.peek(), o.bytes)
	}
	o.pop(small)
	if o.peek() != nil {
		t.Error("not empty")
	}
	o.pop(small) // empty: no-op
}
