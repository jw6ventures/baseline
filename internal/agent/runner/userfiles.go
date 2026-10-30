package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/jw6ventures/baseline/internal/agent/collect"
)

// A rootless Podman stack belongs to its user, who also sets the labels
// its paths come from. Its files are read and written by a helper running
// as that user (`baseline-agent stackfile`, the agent's own binary), so the
// kernel decides what the job may touch, never root: a label pointing at
// /etc/shadow fails like it would for the user. Rootful stacks' files are
// handled in the agent itself.

// maxReadSz bounds a file read for a stack: Compose files and .env files
// are far smaller.
const maxReadSz = 4 << 20

// fileOpTimeout bounds one file operation run as a stack's user.
const fileOpTimeout = 30 * time.Second

// fileOp is one file operation on a stack's files.
type fileOp struct {
	Op   string      `json:"op"` // stat, lstat, read, write, remove, removeall, mkdir, mkdirall, rename
	Path string      `json:"path"`
	Dest string      `json:"dest,omitempty"` // rename's new path
	Data []byte      `json:"data,omitempty"`
	Mode os.FileMode `json:"mode,omitempty"`
}

// fileRes is what came of it. Errno is set when the error was a system
// call's, so that callers can tell a missing file from other errors.
type fileRes struct {
	Data    []byte      `json:"data,omitempty"`
	Mode    os.FileMode `json:"mode,omitempty"`
	Regular bool        `json:"regular,omitempty"`
	Dir     bool        `json:"dir,omitempty"`
	Err     string      `json:"err,omitempty"`
	Errno   int         `json:"errno,omitempty"`
}

// doFileOp runs a file operation as whoever this process is.
func doFileOp(op fileOp) fileRes {
	var res fileRes
	var err error
	switch op.Op {
	case "stat", "lstat":
		var fi os.FileInfo
		if op.Op == "stat" {
			fi, err = os.Stat(op.Path)
		} else {
			fi, err = os.Lstat(op.Path)
		}
		if err == nil {
			res.Mode, res.Regular, res.Dir = fi.Mode(), fi.Mode().IsRegular(), fi.IsDir()
		}
	case "read":
		res.Data, res.Mode, err = readFile(op.Path)
	case "write":
		err = writeFile(op.Path, op.Data, op.Mode)
	case "remove":
		err = os.Remove(op.Path)
	case "removeall":
		err = os.RemoveAll(op.Path)
	case "mkdir":
		err = os.Mkdir(op.Path, op.Mode)
	case "mkdirall":
		err = os.MkdirAll(op.Path, op.Mode)
	case "rename":
		err = os.Rename(op.Path, op.Dest)
	default:
		err = fmt.Errorf("unknown file operation %q", op.Op)
	}
	if err != nil {
		res.Err = err.Error()
		var errno syscall.Errno
		if errors.As(err, &errno) {
			res.Errno = int(errno)
		}
	}
	return res
}

// readFile reads a regular file of at most maxReadSz, with its permissions.
func readFile(path string) ([]byte, os.FileMode, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !fi.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%s isn't a plain file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxReadSz+1))
	if err == nil && len(b) > maxReadSz {
		err = fmt.Errorf("%s is larger than %d MiB", path, maxReadSz>>20)
	}
	return b, fi.Mode().Perm(), err
}

// ServeFileOp is `baseline-agent stackfile`: it reads one file operation
// from in, runs it, and writes what came of it to out.
func ServeFileOp(in io.Reader, out io.Writer) error {
	var op fileOp
	if err := json.NewDecoder(io.LimitReader(in, 2*maxReadSz)).Decode(&op); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(doFileOp(op))
}

// stackFS reads and writes one stack's files: in the agent for rootful
// engines, through the helper as the user for rootless Podman.
type stackFS struct {
	run func(fileOp) fileRes
}

// files is how a job handles this stack's files.
func (r *Runner) files(ctx context.Context, st collect.Stack) stackFS {
	if st.User == "" {
		return stackFS{run: doFileOp}
	}
	asUser := r.asUser
	if asUser == nil {
		asUser = runAsUser
	}
	// File operations aren't cut short by a cancel: a rollback needs them.
	ctx = context.WithoutCancel(ctx)
	return stackFS{run: func(op fileOp) fileRes {
		octx, cancel := context.WithTimeout(ctx, fileOpTimeout)
		defer cancel()
		res, err := asUser(octx, st, op)
		if err != nil {
			return fileRes{Err: fmt.Sprintf("%s %s as %s: %v", op.Op, op.Path, st.User, err)}
		}
		return res
	}}
}

// runAsUser runs a file operation in the helper, as the stack's user with
// their groups.
func runAsUser(ctx context.Context, st collect.Stack, op fileOp) (fileRes, error) {
	uid, err1 := strconv.ParseUint(st.UID, 10, 32)
	gid, err2 := strconv.ParseUint(st.GID, 10, 32)
	if err1 != nil || err2 != nil || uid == 0 {
		return fileRes{}, fmt.Errorf("no uid and gid for %s", st.User)
	}
	cred := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	if u, err := user.LookupId(st.UID); err == nil {
		gids, _ := u.GroupIds()
		for _, g := range gids {
			if n, err := strconv.ParseUint(g, 10, 32); err == nil {
				cred.Groups = append(cred.Groups, uint32(n))
			}
		}
	}
	in, err := json.Marshal(op)
	if err != nil {
		return fileRes{}, err
	}
	// The binary that runs, even if a self-update replaced the file.
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "stackfile")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	cmd.Env = []string{"HOME=" + st.Home, "PATH=/usr/bin:/bin"}
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(in)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		if msg := bytes.TrimSpace(stderr.Bytes()); len(msg) > 0 {
			return fileRes{}, fmt.Errorf("%v: %s", err, msg)
		}
		return fileRes{}, err
	}
	var res fileRes
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		return fileRes{}, fmt.Errorf("the helper answered %q: %v", out.String(), err)
	}
	return res, nil
}

func (f stackFS) do(op fileOp) (fileRes, error) {
	res := f.run(op)
	switch {
	case res.Errno != 0:
		return res, &fs.PathError{Op: op.Op, Path: op.Path, Err: syscall.Errno(res.Errno)}
	case res.Err != "":
		return res, errors.New(res.Err)
	}
	return res, nil
}

// stat follows links, lstat doesn't.
func (f stackFS) stat(path string) (fileRes, error) { return f.do(fileOp{Op: "stat", Path: path}) }
func (f stackFS) lstat(path string) (fileRes, error) {
	return f.do(fileOp{Op: "lstat", Path: path})
}

// read reads a regular file, with its permissions.
func (f stackFS) read(path string) ([]byte, os.FileMode, error) {
	res, err := f.do(fileOp{Op: "read", Path: path})
	if err == nil && res.Data == nil {
		res.Data = []byte{} // an empty file isn't a missing one
	}
	return res.Data, res.Mode, err
}

// write replaces a file atomically with this mode.
func (f stackFS) write(path string, data []byte, mode os.FileMode) error {
	_, err := f.do(fileOp{Op: "write", Path: path, Data: data, Mode: mode})
	return err
}

func (f stackFS) remove(path string) error {
	_, err := f.do(fileOp{Op: "remove", Path: path})
	return err
}

func (f stackFS) removeAll(path string) error {
	_, err := f.do(fileOp{Op: "removeall", Path: path})
	return err
}

func (f stackFS) mkdir(path string, mode os.FileMode) error {
	_, err := f.do(fileOp{Op: "mkdir", Path: path, Mode: mode})
	return err
}

func (f stackFS) mkdirAll(path string, mode os.FileMode) error {
	_, err := f.do(fileOp{Op: "mkdirall", Path: path, Mode: mode})
	return err
}

func (f stackFS) rename(from, to string) error {
	_, err := f.do(fileOp{Op: "rename", Path: from, Dest: to})
	var pe *fs.PathError
	if errors.As(err, &pe) {
		// What os.Rename returns, so that EXDEV can be told apart.
		err = &os.LinkError{Op: "rename", Old: from, New: to, Err: pe.Err}
	}
	return err
}
