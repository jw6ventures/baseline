package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
)

// exec runs a command into the job's output, echoing it first.
func (r *Runner) exec(ctx context.Context, c Cmd, out *output) (int, error) {
	out.info("$ %s\n", c)
	return r.Exec(ctx, c, out.stream("stdout"), out.stream("stderr"))
}

func (r *Runner) service(ctx context.Context, name, unit string, out *output) outcome {
	verb := strings.TrimPrefix(name, "service.")
	code, err := r.exec(ctx, Cmd{Name: "systemctl", Args: []string{verb, unit}}, out)
	if err != nil {
		return failed("systemctl: %v", err)
	}
	// What it looks like now, for the record; this one's exit code says
	// whether the unit is running, which isn't the job's business.
	r.exec(ctx, Cmd{Name: "systemctl", Args: []string{"status", "--no-pager", "--lines=10", unit}}, out)
	if code != 0 {
		return outcome{failed: true, exitCode: code, err: "systemctl " + verb + " failed"}
	}
	return outcome{}
}

func (r *Runner) restartContainer(ctx context.Context, p action.ContainerParams, out *output) outcome {
	if r.Containers == nil {
		return failed("containers can't be managed on this agent")
	}
	out.info("Restarting container %s (%s)\n", p.Name, p.Engine)
	if err := r.Containers.Restart(ctx, p.Engine, p.Name); err != nil {
		return failed("%v", err)
	}
	out.info("Restarted.\n")
	return outcome{}
}

// script runs a library script: the body must match its SHA-256 and declare
// a known interpreter. It is written to a root-only file and run with its
// arguments, parameters also in the environment.
func (r *Runner) script(ctx context.Context, s *agentv1.Script, out *output) outcome {
	if s == nil {
		return failed("the server sent no script")
	}
	sum := sha256.Sum256(s.GetBody())
	if hex.EncodeToString(sum[:]) != s.GetSha256() {
		return failed("the script doesn't match its SHA-256; refusing to run it")
	}
	if !slices.Contains(action.Interpreters, s.GetInterpreter()) {
		return failed("interpreter %q isn't allowed", s.GetInterpreter())
	}
	if _, err := os.Stat(s.GetInterpreter()); err != nil {
		return failed("%s isn't installed on this host", s.GetInterpreter())
	}
	f, err := os.CreateTemp(r.TempDir, "baseline-script-*")
	if err != nil {
		return failed("script file: %v", err)
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o700); err == nil {
		_, err = f.Write(s.GetBody())
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		f.Close()
		return failed("script file: %v", err)
	}
	var env []string
	keys := make([]string, 0, len(s.GetEnv()))
	for k := range s.GetEnv() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if (strings.HasPrefix(k, "BASELINE_") || strings.HasPrefix(k, "JCMDB_")) && !strings.ContainsAny(k, "=\x00") {
			env = append(env, k+"="+strings.ReplaceAll(s.GetEnv()[k], "\x00", ""))
		}
	}
	out.info("$ %s %s (sha256 %s)\n", s.GetInterpreter(), strings.Join(s.GetArgs(), " "), s.GetSha256()[:12])
	code, err := r.Exec(ctx, Cmd{Name: s.GetInterpreter(), Args: append([]string{f.Name()}, s.GetArgs()...), Env: env},
		out.stream("stdout"), out.stream("stderr"))
	switch {
	case err != nil && ctx.Err() == nil:
		return failed("%v", err)
	case code != 0:
		return outcome{failed: true, exitCode: code, err: "the script exited with status " + strconv.Itoa(code)}
	}
	return outcome{}
}
