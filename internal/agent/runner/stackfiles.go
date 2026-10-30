package runner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/agent/collect"
	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/stackenv"
)

// Files that Baseline writes (docs/agent.md §5.2): a new stack's Compose file
// is <root>/<project>/compose.yaml, and a stack's .env sits beside
// its Compose file, readable by root only. It isn't encrypted on the host:
// the engine hands the values to anyone who can inspect the containers
// anyway. An edited Compose file's previous version is kept beside it.
const (
	envFile      = ".env"
	prevSuffix   = ".baseline-prev"
	composeName  = "compose.yaml"
	maxComposeSz = 1 << 20
)

// lockStacks waits for any other Compose job on the host to finish: two
// jobs on one stack would trip over each other.
func (r *Runner) lockStacks(ctx context.Context, out *output) (func(), bool) {
	select {
	case r.stacks <- struct{}{}:
	default:
		out.info("Waiting for another Compose job on this host to finish…\n")
		select {
		case r.stacks <- struct{}{}:
		case <-ctx.Done():
			return nil, false
		}
	}
	return func() { <-r.stacks }, true
}

// stackFiles checks what the server sent with a compose.deploy or
// compose.edit job: the Compose file against its hash in the parameters,
// the .env for being one. It returns the new
// Compose file and .env, nil where they stay as they are.
func (r *Runner) stackFiles(p action.StackFileParams, files *agentv1.StackFiles) (compose, env []byte, err error) {
	if p.ComposeSHA256 != "" {
		compose = files.GetCompose()
		switch {
		case len(compose) == 0:
			return nil, nil, errors.New("the server sent no Compose file")
		case len(compose) > maxComposeSz:
			return nil, nil, errors.New("the Compose file is larger than 1 MiB")
		case stackenv.SHA256(compose) != p.ComposeSHA256:
			return nil, nil, errors.New("the Compose file doesn't match its SHA-256; refusing it")
		}
	}
	if p.Env {
		env = files.GetEnv()
		if env == nil {
			env = []byte{}
		}
		if _, err := stackenv.Check(env); err != nil {
			return nil, nil, err
		}
	}
	return compose, env, nil
}

// fileRefusal says why Baseline won't write a stack's files, or "".
func fileRefusal(st collect.Stack) string {
	switch {
	case st.CLI == "":
		return fmt.Sprintf("no Compose CLI for %s is installed on this host", st.Engine)
	case st.User != "" && (st.UID == "" || st.GID == ""):
		return fmt.Sprintf("%s: no uid and gid for %s", st.Engine, st.User)
	}
	return ""
}

// deploy is compose.deploy: a new stack under a Compose root (deployRoot), its
// files written there, pulled, started and checked. If it doesn't come up,
// it is taken down and its files removed again.
func (r *Runner) deploy(ctx context.Context, p action.StackFileParams, files *agentv1.StackFiles, out *output) outcome {
	if r.Containers == nil {
		return failed("containers can't be managed on this agent")
	}
	root, refusal := r.deployRoot(p.Root)
	if refusal != "" {
		return failed("%s", refusal)
	}
	compose, env, err := r.stackFiles(p, files)
	if err != nil {
		return failed("%v", err)
	}
	unlock, ok := r.lockStacks(ctx, out)
	if !ok {
		return failed("stopped while waiting for another Compose job")
	}
	defer unlock()

	st, err := r.Containers.Engine(ctx, p.Engine)
	if err != nil {
		return failed("%v", err)
	}
	if why := fileRefusal(st); why != "" {
		return failed("%s", why)
	}
	switch old, err := r.Containers.Stack(ctx, p.Engine, p.Project); {
	case err == nil && old.Stopped:
		return failed("a stack %s is in %s already, not running; edit or start it instead", p.Project, old.WorkingDir)
	case err == nil:
		return failed("a stack %s already runs on %s; edit it instead", p.Project, p.Engine)
	case !errors.Is(err, collect.ErrNoStack):
		return failed("%v", err)
	}
	fsys := r.files(ctx, st)
	dir := filepath.Join(root, p.Project)
	if _, err := fsys.lstat(dir); err == nil {
		return failed("%s already exists; remove it, or edit the stack that uses it", dir)
	}
	err = fsys.mkdirAll(root, 0o700)
	if err == nil {
		err = fsys.mkdir(dir, 0o700)
	}
	if errors.Is(err, fs.ErrPermission) && st.User != "" {
		// Its files are written as the user, who needs a root of their own.
		return failed("%s can't write to %s; pick a Compose root %s can write to: %v", st.User, root, st.User, err)
	}
	if err != nil {
		return failed("%v", err)
	}
	st.Project, st.WorkingDir = p.Project, dir
	file := filepath.Join(dir, composeName)
	st.ConfigFiles = []model.ComposeFile{{Path: file}}
	res := &action.StackFileResult{WorkingDir: dir, ComposeFile: file}
	remove := func() { fsys.removeAll(dir) }

	out.info("Writing %s\n", file)
	err = fsys.write(file, compose, 0o644)
	if err == nil && env != nil {
		out.info("Writing %s\n", filepath.Join(dir, envFile))
		err = fsys.write(filepath.Join(dir, envFile), env, 0o600)
	}
	if err != nil {
		remove()
		return failed("%v", err)
	}

	if why := r.composeCheck(ctx, st, out); why != "" {
		remove()
		return outcome{failed: true, exitCode: -1, result: res, err: why}
	}
	out.info("Pulling images for %s…\n", p.Project)
	why := ""
	if code, err := r.exec(ctx, composeCmd(st, "pull"), out); err != nil || code != 0 {
		why = composeExit("pull", code, err)
	} else if code, err := r.exec(ctx, composeCmd(st, "up", "-d"), out); err != nil || code != 0 {
		why = composeExit("up", code, err)
	} else {
		why = r.waitStack(ctx, p, out, res)
	}
	if why == "" {
		out.info("Deployed %s.\n", p.Project)
		return outcome{result: res}
	}

	// Take it down again: a half-started stack helps nobody, and leaving
	// its directory would stop a corrected deploy.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	out.info("\n%s. Taking %s down again.\n", upperFirst(why), p.Project)
	r.exec(rctx, composeCmd(st, "logs", "--tail", "50"), out)
	if code, err := r.exec(rctx, composeCmd(st, "down"), out); err != nil || code != 0 {
		return outcome{failed: true, exitCode: -1, result: res,
			err: fmt.Sprintf("%s; taking it down failed too: %s; its files are kept in %s", why, composeExit("down", code, err), dir)}
	}
	remove()
	res.RolledBack = true
	out.info("Took %s down and removed %s. Named volumes are kept.\n", p.Project, dir)
	return outcome{failed: true, exitCode: -1, state: stateRolledBack, result: res, err: "rolled back: " + why}
}

// deployRoot is the directory compose.deploy puts the stack under: the
// Compose root the server picked from the host's, or the agent's own
// compose_root. The agent checks the server's pick itself, and keeps it
// out of its own state directory but for its compose_root.
func (r *Runner) deployRoot(root string) (string, string) {
	if root == "" {
		if !filepath.IsAbs(r.ComposeRoot) {
			return "", "this agent has no Compose root (compose_root in agent.conf)"
		}
		return r.ComposeRoot, ""
	}
	if err := action.CheckComposeRoot(root); err != nil {
		return "", err.Error()
	}
	if r.Dir != "" && !within(root, r.ComposeRoot) && within(root, filepath.Dir(r.Dir)) {
		return "", root + " is in the agent's own state directory; pick another Compose root"
	}
	return root, ""
}

// within reports whether path is dir or lies under it.
func within(path, dir string) bool {
	if dir == "" {
		return false
	}
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// edit is compose.edit: a new Compose file, a new or changed .env, or both,
// for a stack that runs on the host, then `up -d`. The Compose file must
// still be the one the edit was made from. If the stack doesn't come up,
// the previous files are put back and it is started on them again.
func (r *Runner) edit(ctx context.Context, p action.StackFileParams, files *agentv1.StackFiles, out *output) outcome {
	if r.Containers == nil {
		return failed("containers can't be managed on this agent")
	}
	compose, env, err := r.stackFiles(p, files)
	if err != nil {
		return failed("%v", err)
	}
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
	if why := fileRefusal(st); why != "" {
		return failed("%s", why)
	}
	fsys := r.files(ctx, st)
	res := &action.StackFileResult{WorkingDir: st.WorkingDir}
	var file string
	var oldCompose []byte
	var mode os.FileMode = 0o644
	if compose != nil {
		if len(st.ConfigFiles) != 1 {
			return failed("the stack %s runs from %d Compose files; Baseline edits stacks that run from one", st.Project, len(st.ConfigFiles))
		}
		file = st.ConfigFiles[0].Path
		res.ComposeFile = file
		oldCompose, mode, err = fsys.read(file)
		if err != nil {
			return failed("%v", err)
		}
		if stackenv.SHA256(oldCompose) != p.BaseSHA256 {
			return failed("%s changed on the host since this edit was made from it; make the edit again from the file as it is now", file)
		}
	}

	// The .env as it is, to merge into and to put back; nil if there's none.
	envPath := filepath.Join(st.WorkingDir, envFile)
	var oldEnv []byte
	envMode := os.FileMode(0o600)
	if env != nil {
		fi, err := fsys.stat(envPath)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return failed("%v", err)
		case !fi.Regular:
			return failed("%s isn't a plain file", envPath)
		default:
			// Never looser than owner-only, now that Baseline writes secrets to it.
			var m os.FileMode
			if oldEnv, m, err = fsys.read(envPath); err != nil {
				return failed("%v", err)
			}
			envMode = m & 0o600
		}
	}

	// restore puts the files back as they were.
	restore := func() error {
		if compose != nil {
			if err := fsys.write(file, oldCompose, mode); err != nil {
				return err
			}
		}
		switch {
		case env == nil:
		case oldEnv == nil:
			if err := fsys.remove(envPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		default:
			return fsys.write(envPath, oldEnv, envMode)
		}
		return nil
	}

	if compose != nil {
		fsys.write(file+prevSuffix, oldCompose, mode)
		out.info("Writing %s\n", file)
		err = fsys.write(file, compose, mode)
	}
	if err == nil && env != nil {
		out.info("Writing %s\n", envPath)
		err = fsys.write(envPath, env, envMode)
	}
	if err != nil {
		restore()
		return failed("%v", err)
	}

	if why := r.composeCheck(ctx, st, out); why != "" {
		if err := restore(); err != nil {
			return failed("%s; putting the previous files back failed too: %v", why, err)
		}
		out.info("Put the previous files back; nothing was restarted.\n")
		return outcome{failed: true, exitCode: -1, result: res, err: why}
	}
	if st.Stopped {
		// Nothing of it runs, and an edit doesn't start it: compose.start does.
		out.info("Edited %s. It isn't running; start it to run on the new files.\n", st.Project)
		return outcome{result: res}
	}
	why := ""
	if code, err := r.exec(ctx, composeCmd(st, "up", "-d", "--remove-orphans"), out); err != nil || code != 0 {
		why = composeExit("up", code, err)
	} else {
		why = r.waitStack(ctx, p, out, res)
	}
	if why == "" {
		out.info("Edited %s.\n", st.Project)
		return outcome{result: res}
	}

	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	out.info("\n%s. Putting the previous files back.\n", upperFirst(why))
	r.exec(rctx, composeCmd(st, "logs", "--tail", "50"), out)
	err = restore()
	if err == nil {
		if code, xerr := r.exec(rctx, composeCmd(st, "up", "-d", "--remove-orphans"), out); xerr != nil || code != 0 {
			err = errors.New(composeExit("up", code, xerr))
		}
	}
	if err != nil {
		return outcome{failed: true, exitCode: -1, result: res, err: fmt.Sprintf("%s; rolling back failed too: %v", why, err)}
	}
	res.RolledBack = true
	out.info("Rolled back: %s runs on its previous files again.\n", st.Project)
	return outcome{failed: true, exitCode: -1, state: stateRolledBack, result: res, err: "rolled back: " + why}
}

// composeCheck has Compose read the files before anything is started:
// `config --quiet` fails on bad YAML and on unset required variables.
func (r *Runner) composeCheck(ctx context.Context, st collect.Stack, out *output) string {
	if code, err := r.exec(ctx, composeCmd(st, "config", "--quiet"), out); err != nil || code != 0 {
		return "the Compose file doesn't check out: " + composeExit("config", code, err)
	}
	return ""
}

// waitStack waits for every service the stack runs to be running and
// healthy. A one-off container that exited with status 0 did its job.
func (r *Runner) waitStack(ctx context.Context, p action.StackFileParams, out *output, res *action.StackFileResult) string {
	st, err := r.Containers.Stack(ctx, p.Engine, p.Project)
	if err != nil {
		return err.Error()
	}
	var services []string
	for _, c := range st.Containers {
		if c.ComposeService != "" && !slices.Contains(services, c.ComposeService) {
			services = append(services, c.ComposeService)
		}
	}
	slices.Sort(services)
	res.Services = services
	if len(services) == 0 {
		return "no container of the stack runs"
	}
	return r.waitHealthy(ctx, action.ComposeParams{Engine: p.Engine, Project: p.Project, HealthTimeout: p.HealthTimeout},
		services, out, true)
}

// writeFile replaces a file atomically with this mode.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".baseline-tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// start is compose.start: `up -d` for a stack none of whose containers
// run (one found under a Compose root, or one whose containers all
// stopped), then a wait for it to be running and healthy. If it doesn't
// come up, it is taken down again, back to not running.
func (r *Runner) start(ctx context.Context, p action.ComposeParams, out *output) outcome {
	if r.Containers == nil {
		return failed("containers can't be managed on this agent")
	}
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
	if slices.ContainsFunc(st.Containers, func(c model.Container) bool { return c.State == "running" }) {
		return failed("the stack %s is running already", st.Project)
	}
	res := &action.ComposeResult{}
	if why := r.composeCheck(ctx, st, out); why != "" {
		return outcome{failed: true, exitCode: -1, result: res, err: why}
	}
	out.info("Starting %s…\n", st.Project)
	why := ""
	if code, err := r.exec(ctx, composeCmd(st, "up", "-d"), out); err != nil || code != 0 {
		why = composeExit("up", code, err)
	} else {
		sp := action.StackFileParams{Engine: p.Engine, Project: p.Project, HealthTimeout: p.HealthTimeout}
		var fr action.StackFileResult
		why = r.waitStack(ctx, sp, out, &fr)
		for _, s := range fr.Services {
			res.Services = append(res.Services, action.ComposeService{Service: s})
		}
	}
	if why == "" {
		out.info("Started %s.\n", st.Project)
		return outcome{result: res}
	}

	// Back to how it was, not running: a stack that had containers keeps
	// them, stopped; one that had none is taken down. Named volumes are
	// kept either way.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	undo := "down"
	if len(st.Containers) > 0 {
		undo = "stop"
	}
	out.info("\n%s. Stopping %s again.\n", upperFirst(why), st.Project)
	r.exec(rctx, composeCmd(st, "logs", "--tail", "50"), out)
	if code, err := r.exec(rctx, composeCmd(st, undo), out); err != nil || code != 0 {
		return outcome{failed: true, exitCode: -1, result: res,
			err: fmt.Sprintf("%s; stopping it failed too: %s", why, composeExit(undo, code, err))}
	}
	res.RolledBack = true
	out.info("Stopped %s again (compose %s).\n", st.Project, undo)
	return outcome{failed: true, exitCode: -1, state: stateRolledBack, result: res, err: "rolled back: " + why}
}
