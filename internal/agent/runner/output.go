package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
)

// Cmd is a command a job runs.
type Cmd struct {
	Name string
	Args []string
	Env  []string // added to BaseEnv
	Dir  string   // "" is /
}

func (c Cmd) String() string {
	return strings.TrimSpace(strings.Join(append(append([]string{}, c.Env...), append([]string{c.Name}, c.Args...)...), " "))
}

// ExecFunc runs a command to completion, streaming its output, and returns
// its exit code (-1 if it didn't run).
type ExecFunc func(ctx context.Context, c Cmd, stdout, stderr io.Writer) (int, error)

// BaseEnv is the environment jobs run with: the agent's own (from systemd)
// is minimal and not meant for them.
var BaseEnv = []string{
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"HOME=/root", "LANG=C.UTF-8", "TERM=dumb",
}

// Run is the real ExecFunc. The command gets its own process group, so
// cancelling the job stops everything it started.
func Run(ctx context.Context, c Cmd, stdout, stderr io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Env = append(append([]string{}, BaseEnv...), c.Env...)
	cmd.Dir = c.Dir
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	// Bounds the wait for output after the command ends (a daemon it
	// started may hold the pipes) and for the group to stop when cancelled.
	cmd.WaitDelay = 15 * time.Second
	err := cmd.Run()
	if cmd.Process != nil && ctx.Err() != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		if ctx.Err() != nil {
			return ee.ExitCode(), ctx.Err()
		}
		return ee.ExitCode(), nil
	case errors.Is(err, exec.ErrWaitDelay):
		return cmd.ProcessState.ExitCode(), nil
	}
	return -1, err
}

// output turns a job's stdout and stderr into numbered OUTPUT events, a few
// times a second, cut on UTF-8 boundaries.
type output struct {
	r   *Runner
	job string

	mu        sync.Mutex
	seq       uint64
	segs      []segment
	tails     map[string][]byte // an incomplete UTF-8 sequence, per stream
	pending   int
	sent      int
	truncated bool
	done      chan struct{}
	wg        sync.WaitGroup
}

type segment struct {
	stream string
	data   []byte
}

const (
	flushEvery = 300 * time.Millisecond
	flushBytes = 32 << 10
)

func newOutput(r *Runner, job string) *output {
	o := &output{r: r, job: job, done: make(chan struct{}), tails: map[string][]byte{}}
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		t := time.NewTicker(flushEvery)
		defer t.Stop()
		for {
			select {
			case <-o.done:
				return
			case <-t.C:
				o.mu.Lock()
				o.flushLocked(false)
				o.mu.Unlock()
			}
		}
	}()
	return o
}

// stream returns a writer for stdout or stderr.
func (o *output) stream(name string) io.Writer { return streamWriter{o, name} }

type streamWriter struct {
	o      *output
	stream string
}

func (w streamWriter) Write(p []byte) (int, error) {
	w.o.write(w.stream, p)
	return len(p), nil
}

// info adds a line from the agent itself ("$ apt-get ...").
func (o *output) info(format string, args ...any) {
	o.write("info", []byte(fmt.Sprintf(format, args...)))
}

func (o *output) write(stream string, p []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.truncated {
		return
	}
	if o.sent+o.pending+len(p) > maxOutput {
		o.flushLocked(true)
		o.truncated = true
		o.emit("info", []byte(fmt.Sprintf("\n[output truncated: the agent sends at most %d MB per job]\n", maxOutput>>20)))
		return
	}
	if n := len(o.segs); n > 0 && o.segs[n-1].stream == stream {
		o.segs[n-1].data = append(o.segs[n-1].data, p...)
	} else {
		o.segs = append(o.segs, segment{stream, append([]byte(nil), p...)})
	}
	o.pending += len(p)
	if o.pending >= flushBytes {
		o.flushLocked(false)
	}
}

// flushLocked emits what is buffered. Unless final, an incomplete UTF-8
// sequence at the end of a stream's output waits for the rest of it, even
// when the other stream writes in between.
func (o *output) flushLocked(final bool) {
	for _, s := range o.segs {
		data := append(o.tails[s.stream], s.data...)
		delete(o.tails, s.stream)
		if !final {
			if cut := utf8Prefix(data); cut < len(data) {
				o.tails[s.stream] = append([]byte(nil), data[cut:]...)
				data = data[:cut]
			}
		}
		if len(data) > 0 {
			o.emit(s.stream, data)
		}
	}
	o.segs = nil
	o.pending = 0
	for _, stream := range []string{"stdout", "stderr", "info"} {
		if t := o.tails[stream]; final && len(t) > 0 {
			o.emit(stream, t)
			delete(o.tails, stream)
		}
		o.pending += len(o.tails[stream])
	}
}

func (o *output) emit(stream string, data []byte) {
	for len(data) > 0 {
		n := min(len(data), flushBytes)
		if n < len(data) {
			n = max(utf8Prefix(data[:n]), 1)
		}
		o.seq++
		o.sent += n
		o.r.box.push(&agentv1.JobEvent{JobId: o.job, Type: agentv1.JobEvent_OUTPUT, Seq: o.seq, Stream: stream,
			Data: append([]byte(nil), data[:n]...)})
		data = data[n:]
	}
}

// close sends what's left; the output can't be written to afterwards.
func (o *output) close() {
	close(o.done)
	o.wg.Wait()
	o.mu.Lock()
	o.flushLocked(true)
	o.truncated = true
	o.mu.Unlock()
}

// utf8Prefix is the length of b without an incomplete UTF-8 sequence at
// its end.
func utf8Prefix(b []byte) int {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return i
			}
			break
		}
	}
	return len(b)
}
