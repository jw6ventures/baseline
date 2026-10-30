package runner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/agent/collect"
	"github.com/jw6ventures/baseline/internal/model"
)

// archiveDir is where compose.archive puts a stack's directory: beside it,
// in <parent>/.archive/<project>-<UTC time>. No stack is ever listed from
// there: a directory starting with a dot isn't a project name.
const archiveDir = ".archive"

// dirRefusal says why Baseline won't move a stack's directory, or "": it must
// be a plain directory holding all of the stack's Compose files, and not
// lie in a system directory.
func dirRefusal(st collect.Stack) string {
	fi, err := os.Lstat(st.WorkingDir)
	switch {
	case err != nil:
		return err.Error()
	case !fi.IsDir():
		return st.WorkingDir + " isn't a directory"
	}
	for _, f := range st.ConfigFiles {
		if !within(f.Path, st.WorkingDir) {
			return fmt.Sprintf("its Compose file %s is outside %s; Baseline only moves stacks whose files are in their directory", f.Path, st.WorkingDir)
		}
	}
	if err := action.CheckComposeRoot(filepath.Dir(st.WorkingDir)); err != nil {
		return "the stack's directory can't be moved: " + err.Error()
	}
	return ""
}

// stackForDir checks a stack before compose.archive or compose.move, under
// the Compose lock.
func (r *Runner) stackForDir(ctx context.Context, p action.ComposeParams) (collect.Stack, string) {
	st, err := r.Containers.Stack(ctx, p.Engine, p.Project)
	if err != nil {
		return st, err.Error()
	}
	for _, why := range []func(collect.Stack) string{composeRefusal, fileRefusal, dirRefusal} {
		if s := why(st); s != "" {
			return st, s
		}
	}
	return st, ""
}

func running(st collect.Stack) bool {
	return slices.ContainsFunc(st.Containers, func(c model.Container) bool { return c.State == "running" })
}

// moveDir renames src to dst, or, across file systems, copies it with
// `cp -a` and removes src. A rootless stack's directory is moved as its
// user (stackFS), cp included.
func (r *Runner) moveDir(ctx context.Context, st collect.Stack, src, dst string, out *output) error {
	fsys := r.files(ctx, st)
	out.info("Moving %s to %s\n", src, dst)
	err := fsys.rename(src, dst)
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	out.info("%s is on another file system; copying.\n", filepath.Dir(dst))
	cp := Cmd{Name: "cp", Args: []string{"-a", "--", src, dst}}
	if st.User != "" {
		cp.Name, cp.Args = "runuser", append([]string{"-u", st.User, "--", "cp"}, cp.Args...)
	}
	if code, err := r.exec(ctx, cp, out); err != nil || code != 0 {
		fsys.removeAll(dst)
		if err == nil {
			err = fmt.Errorf("cp exited with status %d", code)
		}
		return err
	}
	if err := fsys.removeAll(src); err != nil {
		return fmt.Errorf("copied to %s, but removing %s failed: %w", dst, src, err)
	}
	return nil
}

// moved is the stack as it is once its directory is dir.
func moved(st collect.Stack, dir string) collect.Stack {
	files := slices.Clone(st.ConfigFiles)
	for i, f := range files {
		rel, _ := filepath.Rel(st.WorkingDir, f.Path)
		files[i].Path = filepath.Join(dir, rel)
	}
	st.WorkingDir, st.ConfigFiles = dir, files
	return st
}

// archive is compose.archive: `compose down` (named volumes and images
// are kept), then the stack's directory moved to <parent>/.archive, so
// nothing of it is deleted. If the directory can't be moved, a stack that
// ran is started again.
func (r *Runner) archive(ctx context.Context, p action.ComposeParams, out *output) outcome {
	if r.Containers == nil {
		return failed("containers can't be managed on this agent")
	}
	unlock, ok := r.lockStacks(ctx, out)
	if !ok {
		return failed("stopped while waiting for another Compose job")
	}
	defer unlock()

	st, why := r.stackForDir(ctx, p)
	if why != "" {
		return failed("%s", why)
	}
	parent := filepath.Join(filepath.Dir(st.WorkingDir), archiveDir)
	base := filepath.Join(parent, st.Project+"-"+time.Now().UTC().Format("20060102-150405"))
	fsys := r.files(ctx, st)
	dst := base
	for i := 2; ; i++ {
		if _, err := fsys.lstat(dst); errors.Is(err, fs.ErrNotExist) {
			break
		} else if err != nil {
			return failed("%v", err)
		}
		dst = fmt.Sprintf("%s-%d", base, i)
	}
	if err := fsys.mkdirAll(parent, 0o700); err != nil {
		return failed("%v", err)
	}
	res := &action.StackFileResult{WorkingDir: dst}
	wasRunning := running(st)
	if len(st.Containers) > 0 {
		out.info("Taking %s down…\n", st.Project)
		if code, err := r.exec(ctx, composeCmd(st, "down"), out); err != nil || code != 0 {
			return outcome{failed: true, exitCode: -1, result: res, err: composeExit("down", code, err)}
		}
	}
	if err := r.moveDir(ctx, st, st.WorkingDir, dst, out); err != nil {
		why := fmt.Sprintf("moving %s failed: %v", st.WorkingDir, err)
		if !wasRunning {
			return outcome{failed: true, exitCode: -1, result: res, err: why}
		}
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		out.info("\n%s. Starting %s again.\n", upperFirst(why), st.Project)
		if code, err := r.exec(rctx, composeCmd(st, "up", "-d"), out); err != nil || code != 0 {
			return outcome{failed: true, exitCode: -1, result: res,
				err: fmt.Sprintf("%s; starting it again failed too: %s", why, composeExit("up", code, err))}
		}
		res.RolledBack = true
		return outcome{failed: true, exitCode: -1, state: stateRolledBack, result: res, err: "rolled back: " + why}
	}
	out.info("Archived %s to %s. Named volumes and images are kept.\n", st.Project, dst)
	return outcome{result: res}
}

// move is compose.move: the stack taken down, its directory moved to
// <dest>/<project> under a Compose root (deployRoot), checked there, and a
// stack that ran started from there and waited for to be running and
// healthy. If any of that fails, it is moved back and started where it
// was. Named volumes keep their names: the project's name doesn't change.
func (r *Runner) move(ctx context.Context, p action.ComposeParams, out *output) outcome {
	if r.Containers == nil {
		return failed("containers can't be managed on this agent")
	}
	root, refusal := r.deployRoot(p.Dest)
	if refusal != "" {
		return failed("%s", refusal)
	}
	unlock, ok := r.lockStacks(ctx, out)
	if !ok {
		return failed("stopped while waiting for another Compose job")
	}
	defer unlock()

	st, why := r.stackForDir(ctx, p)
	if why != "" {
		return failed("%s", why)
	}
	dst := filepath.Join(root, st.Project)
	switch {
	case dst == st.WorkingDir:
		return failed("the stack %s is in %s already", st.Project, dst)
	case within(dst, st.WorkingDir):
		return failed("%s is inside the stack's own directory", dst)
	}
	fsys := r.files(ctx, st)
	if _, err := fsys.lstat(dst); err == nil {
		return failed("%s already exists; pick another Compose root, or archive the stack that uses it", dst)
	}
	if err := fsys.mkdirAll(root, 0o700); errors.Is(err, fs.ErrPermission) && st.User != "" {
		return failed("%s can't write to %s; pick a Compose root %s can write to: %v", st.User, root, st.User, err)
	} else if err != nil {
		return failed("%v", err)
	}
	to := moved(st, dst)
	res := &action.StackFileResult{WorkingDir: dst}
	if len(to.ConfigFiles) > 0 {
		res.ComposeFile = to.ConfigFiles[0].Path
	}
	wasRunning := running(st)
	if len(st.Containers) > 0 {
		out.info("Taking %s down…\n", st.Project)
		if code, err := r.exec(ctx, composeCmd(st, "down"), out); err != nil || code != 0 {
			return outcome{failed: true, exitCode: -1, result: res, err: composeExit("down", code, err)}
		}
	}
	if err := r.moveDir(ctx, st, st.WorkingDir, dst, out); err != nil {
		return r.unmove(ctx, st, to, wasRunning, false, fmt.Sprintf("moving %s failed: %v", st.WorkingDir, err), res, out)
	}
	if why := r.composeCheck(ctx, to, out); why != "" {
		return r.unmove(ctx, st, to, wasRunning, true, why, res, out)
	}
	if !wasRunning {
		out.info("Moved %s to %s. It isn't running; start it to run it from there.\n", st.Project, dst)
		return outcome{result: res}
	}
	why = ""
	if code, err := r.exec(ctx, composeCmd(to, "up", "-d"), out); err != nil || code != 0 {
		why = composeExit("up", code, err)
	} else {
		sp := action.StackFileParams{Engine: p.Engine, Project: p.Project, HealthTimeout: p.HealthTimeout}
		why = r.waitStack(ctx, sp, out, res)
	}
	if why == "" {
		out.info("Moved %s to %s.\n", st.Project, dst)
		return outcome{result: res}
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	r.exec(rctx, composeCmd(to, "logs", "--tail", "50"), out)
	if code, err := r.exec(rctx, composeCmd(to, "down"), out); err != nil || code != 0 {
		return outcome{failed: true, exitCode: -1, result: res,
			err: fmt.Sprintf("%s; taking it down failed too: %s; its files are in %s", why, composeExit("down", code, err), dst)}
	}
	return r.unmove(ctx, st, to, wasRunning, true, why, res, out)
}

// unmove undoes a failed compose.move: the directory back where it was
// (when it moved), and the stack started there again if it ran.
func (r *Runner) unmove(ctx context.Context, st, to collect.Stack, wasRunning, back bool, why string,
	res *action.StackFileResult, out *output) outcome {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	out.info("\n%s. Putting %s back.\n", upperFirst(why), st.Project)
	if back {
		if err := r.moveDir(rctx, st, to.WorkingDir, st.WorkingDir, out); err != nil {
			return outcome{failed: true, exitCode: -1, result: res,
				err: fmt.Sprintf("%s; moving it back failed too: %v; its files are in %s", why, err, to.WorkingDir)}
		}
	}
	res.WorkingDir, res.ComposeFile = st.WorkingDir, ""
	if wasRunning {
		if code, err := r.exec(rctx, composeCmd(st, "up", "-d"), out); err != nil || code != 0 {
			return outcome{failed: true, exitCode: -1, result: res,
				err: fmt.Sprintf("%s; starting it again failed too: %s", why, composeExit("up", code, err))}
		}
	}
	res.RolledBack = true
	out.info("Rolled back: %s is in %s again.\n", st.Project, st.WorkingDir)
	return outcome{failed: true, exitCode: -1, state: stateRolledBack, result: res, err: "rolled back: " + why}
}
