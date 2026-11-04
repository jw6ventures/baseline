package runner

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/agent/collect"
)

// rollbackTimeout bounds a rollback, which runs even after the job was
// cancelled or timed out.
const rollbackTimeout = 10 * time.Minute

// compose is compose.pull and compose.update (docs/agent.md §5.1). The stack
// is named by engine and project; its directory, files and CLI come from the
// agent's own discovery, never from the job. An update that doesn't come up
// healthy is rolled back to the images the services ran before.
func (r *Runner) compose(ctx context.Context, name string, p action.ComposeParams, out *output) outcome {
	if r.Containers == nil {
		return failed("containers can't be managed on this agent")
	}
	// Two jobs on one stack would trip over each other; one at a time is
	// enough.
	unlock, ok := r.lockStacks(ctx, out)
	if !ok {
		return failed("stopped while waiting for another Compose job")
	}
	defer unlock()

	st, err := r.Containers.Stack(ctx, p.Engine, p.Project)
	if err != nil {
		return failed("%v", err)
	}
	if why := composeRefusal(st); why != "" {
		return failed("%s", why)
	}

	for _, s := range p.Services {
		if !slices.Contains(st.Services, s) {
			return failed("the stack %s has no service %q (it has %s)", st.Project, s, strings.Join(st.Services, ", "))
		}
	}
	services := p.Services
	if len(services) == 0 {
		services = st.Services
	}

	// The image each service runs now, by ID, and the reference it runs.
	// Services with nothing running (a one-off job that exited) aren't
	// expected to be running afterwards either.
	var res action.ComposeResult
	var watch []string
	for _, s := range services {
		cs := action.ComposeService{Service: s}
		running := false
		for _, c := range st.Containers {
			if c.ComposeService != s {
				continue
			}
			if cs.Image == "" {
				cs.Image, cs.From = c.Image, c.ImageID
			}
			running = running || c.State == "running"
		}
		res.Services = append(res.Services, cs)
		if running {
			watch = append(watch, s)
		}
	}

	out.info("Pulling images for %s (%s)…\n", st.Project, strings.Join(services, ", "))
	if code, err := r.exec(ctx, composeCmd(st, append([]string{"pull"}, p.Services...)...), out); err != nil || code != 0 {
		return outcome{failed: true, exitCode: code, result: &res, err: composeExit("pull", code, err)}
	}
	var changed []string
	for i := range res.Services {
		s := &res.Services[i]
		id, err := r.Containers.ImageID(ctx, p.Engine, s.Image)
		if err == nil && id == "" {
			err = fmt.Errorf("%s: the engine has no image %s after the pull", s.Service, s.Image)
		}
		if err != nil {
			o := failed("%v", err)
			o.result = &res
			return o
		}
		s.To, s.Changed = id, id != s.From
		if s.Changed {
			changed = append(changed, s.Service)
			out.info("%s: %s has a new image, %s → %s\n", s.Service, s.Image, shortID(s.From), shortID(s.To))
		}
	}
	switch {
	case len(changed) == 0:
		res.Current = true
		out.info("Already current: no service has a new image.\n")
		return outcome{result: &res}
	case name == action.ComposePull:
		out.info("Pulled new images for %s; nothing was restarted.\n", strings.Join(changed, ", "))
		return outcome{result: &res}
	}

	up := []string{"up", "-d"}
	if len(p.Services) > 0 {
		up = append(append(up, "--no-deps"), p.Services...)
	}
	var why string
	if code, err := r.exec(ctx, composeCmd(st, up...), out); err != nil || code != 0 {
		why = composeExit("up", code, err)
	} else if why = r.recreateStale(ctx, st, res.Services, false, out); why == "" {
		why = r.waitHealthy(ctx, p, watch, out, false)
	}
	if why != "" {
		return r.rollback(ctx, st, &res, changed, why, out)
	}
	out.info("Updated %s.\n", strings.Join(changed, ", "))
	return outcome{result: &res}
}

// composeRefusal says why a stack can't be driven, or "".
func composeRefusal(st collect.Stack) string {
	for _, f := range st.ConfigFiles {
		if f.Error != "" {
			return fmt.Sprintf("the stack %s can't be updated: its Compose file %s: %s", st.Project, f.Path, f.Error)
		}
		if !filepath.IsAbs(f.Path) {
			return fmt.Sprintf("the stack %s can't be updated: its Compose file %s isn't an absolute path", st.Project, f.Path)
		}
	}
	switch {
	case st.Orphaned || len(st.ConfigFiles) == 0:
		return fmt.Sprintf("the stack %s wasn't started from Compose files on this host (orphaned), so it can't be updated", st.Project)
	case st.CLI == "":
		return fmt.Sprintf("no Compose CLI for %s is installed on this host", st.Engine)
	case !filepath.IsAbs(st.WorkingDir):
		return fmt.Sprintf("the stack %s has no working directory", st.Project)
	}
	return ""
}

// composeCmd runs the stack's Compose CLI on its own files and directory,
// against the engine the stack runs on. A rootless Podman stack's commands
// run as its user.
func composeCmd(st collect.Stack, args ...string) Cmd {
	var name string
	var argv []string
	switch st.CLI {
	case "docker compose":
		name, argv = "docker", []string{"compose"}
	case "podman compose":
		name, argv = "podman", []string{"compose"}
	default: // docker-compose, podman-compose
		name = st.CLI
	}
	argv = append(argv, "-p", st.Project)
	for _, f := range st.ConfigFiles {
		argv = append(argv, "-f", f.Path)
	}
	// podman-compose has no --project-directory (nor, through it, podman
	// compose); it works from the directory it runs in.
	if st.CLI == "docker compose" || st.CLI == "docker-compose" {
		argv = append(argv, "--project-directory", st.WorkingDir)
	}
	argv = append(argv, args...)
	// docker-compose, and podman compose's providers, find the engine
	// through DOCKER_HOST; podman-compose runs podman, which ignores it.
	c := Cmd{Name: name, Args: argv, Env: []string{"DOCKER_HOST=unix://" + st.Socket}, Dir: st.WorkingDir}
	if st.User != "" {
		c.Name, c.Args = "runuser", append([]string{"-u", st.User, "--", name}, argv...)
		c.Env = append(c.Env, "XDG_RUNTIME_DIR=/run/user/"+st.UID, "HOME="+st.Home)
	}
	return c
}

func composeExit(cmd string, code int, err error) string {
	if err != nil {
		return fmt.Sprintf("compose %s: %v", cmd, err)
	}
	return fmt.Sprintf("compose %s exited with status %d", cmd, code)
}

// waitHealthy waits up to the health timeout for every container of these
// services to be running, and healthy if it has a healthcheck, on two checks
// in a row without restarting in between. It returns why not, or "". A
// container that exits or reports itself unhealthy fails at once; one whose
// healthcheck is still starting is waited for. With exitOK, a container
// that exited with status 0 counts as a one-off that did its job.
func (r *Runner) waitHealthy(ctx context.Context, p action.ComposeParams, services []string, out *output, exitOK bool) string {
	timeout := time.Duration(p.HealthTimeout) * time.Second
	every := r.pollEvery
	if every <= 0 {
		every = 2 * time.Second
	}
	if len(services) == 0 {
		return ""
	}
	out.info("Waiting up to %v for %s to be running and healthy…\n", timeout, strings.Join(services, ", "))
	deadline := time.Now().Add(timeout)
	var last map[string]string
	waiting := "nothing checked yet"
	for {
		st, err := r.Containers.Stack(ctx, p.Engine, p.Project)
		if err != nil {
			waiting, last = err.Error(), nil
		} else {
			ready, why, fatal := containersReady(st, services, exitOK)
			if fatal {
				return why
			}
			if ready != nil && maps.Equal(ready, last) {
				out.info("Running and healthy.\n")
				return ""
			}
			last, waiting = ready, why
			if ready != nil {
				waiting = "the containers had only just started"
			}
		}
		left := time.Until(deadline)
		if left <= 0 {
			return fmt.Sprintf("not running and healthy within %v: %s", timeout, waiting)
		}
		select {
		case <-ctx.Done():
			return "stopped while waiting for the containers to be healthy"
		case <-time.After(min(every, left)):
		}
	}
}

// containersReady checks the containers of services. ready identifies each
// container's run when all are ready (nil otherwise); why says what isn't,
// and fatal that waiting longer won't help.
func containersReady(st collect.Stack, services []string, exitOK bool) (ready map[string]string, why string, fatal bool) {
	ready = map[string]string{}
	var waiting []string
	for _, s := range services {
		n := 0
		for _, c := range st.Containers {
			if c.ComposeService != s {
				continue
			}
			n++
			switch {
			case exitOK && c.State == "exited" && c.ExitCode == 0:
				ready[c.Name] = c.ID + " done"
			case c.State == "exited" || c.State == "dead":
				return nil, fmt.Sprintf("%s exited with status %d", c.Name, c.ExitCode), true
			case c.State == "running" && c.Health == "unhealthy":
				return nil, c.Name + " is unhealthy", true
			case c.State != "running":
				waiting = append(waiting, c.Name+" is "+c.State)
			case c.Health == "starting":
				waiting = append(waiting, c.Name+" isn't healthy yet")
			default:
				ready[c.Name] = fmt.Sprintf("%s %s %d", c.ID, c.StartedAt, c.RestartCount)
			}
		}
		if n == 0 {
			waiting = append(waiting, s+" has no container")
		}
	}
	if len(waiting) > 0 {
		return nil, strings.Join(waiting, ", "), false
	}
	return ready, "", false
}

// rollback puts the changed services' previous images back: it tags their
// references to the old image IDs again and recreates them. Stopping the job
// mustn't leave a stack half-updated, so it runs on its own deadline. The
// new images are kept; nothing is pruned.
func (r *Runner) rollback(ctx context.Context, st collect.Stack, res *action.ComposeResult, changed []string,
	why string, out *output) outcome {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	out.info("\n%s. Rolling back %s.\n", upperFirst(why), strings.Join(changed, ", "))
	// What the new containers said, for the record; its exit status
	// doesn't matter.
	r.exec(rctx, composeCmd(st, append([]string{"logs", "--tail", "50"}, changed...)...), out)

	var errs []string
	for _, s := range res.Services {
		// A reference pinned by digest still names the old image.
		if !s.Changed || strings.Contains(s.Image, "@") {
			continue
		}
		out.info("Tagging %s as %s again\n", shortID(s.From), s.Image)
		if err := r.Containers.Tag(rctx, st.Engine, s.From, s.Image); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) == 0 {
		up := append([]string{"up", "-d", "--no-deps"}, changed...)
		if code, err := r.exec(rctx, composeCmd(st, up...), out); err != nil || code != 0 {
			errs = append(errs, composeExit("up", code, err))
		}
	}
	if len(errs) == 0 {
		// The containers should run the old images again.
		if why := r.recreateStale(rctx, st, res.Services, true, out); why != "" {
			errs = append(errs, why)
		}
	}
	if len(errs) > 0 {
		return outcome{failed: true, exitCode: -1, result: res,
			err: fmt.Sprintf("%s; rolling back failed too: %s", why, strings.Join(errs, "; "))}
	}
	res.RolledBack = true
	out.info("Rolled back: %s run their previous images again. The new images are kept.\n", strings.Join(changed, ", "))
	return outcome{failed: true, exitCode: -1, state: stateRolledBack, result: res, err: "rolled back: " + why}
}

// recreateStale checks that every container of a changed service runs the
// image the update moved it to (back to its old one when rollingBack), and
// recreates those that don't with --force-recreate. Podman's Compose CLIs
// often report a successful `up -d` without replacing containers whose
// image changed behind the same reference; without this check the update
// would pass its health wait on the old, still healthy containers. It
// returns which containers still run the wrong image, or "".
func (r *Runner) recreateStale(ctx context.Context, st collect.Stack, services []action.ComposeService,
	rollingBack bool, out *output) string {
	stale := func() ([]string, []string, error) {
		now, err := r.Containers.Stack(ctx, st.Engine, st.Project)
		if err != nil {
			return nil, nil, err
		}
		var svcs, wrong []string
		for _, s := range services {
			want := s.To
			if rollingBack {
				want = s.From
			}
			if !s.Changed {
				continue
			}
			for _, c := range now.Containers {
				if c.ComposeService == s.Service && c.ImageID != want {
					wrong = append(wrong, fmt.Sprintf("%s still runs %s", c.Name, shortID(c.ImageID)))
					if !slices.Contains(svcs, s.Service) {
						svcs = append(svcs, s.Service)
					}
				}
			}
		}
		return svcs, wrong, nil
	}
	svcs, _, err := stale()
	if err != nil {
		return err.Error()
	}
	if len(svcs) == 0 {
		return ""
	}
	out.info("Compose up left %s on the old image; recreating with --force-recreate.\n", strings.Join(svcs, ", "))
	up := append([]string{"up", "-d", "--no-deps", "--force-recreate"}, svcs...)
	if code, err := r.exec(ctx, composeCmd(st, up...), out); err != nil || code != 0 {
		return composeExit("up --force-recreate", code, err)
	}
	_, wrong, err := stale()
	if err != nil {
		return err.Error()
	}
	return strings.Join(wrong, "; ")
}

// shortID is an image ID as the engines show it: 12 hex digits.
func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
