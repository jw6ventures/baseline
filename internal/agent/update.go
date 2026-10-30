package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
	"github.com/jw6ventures/baseline/internal/pki"
)

// Self-update (docs/agent.md §5.2). The new binary is downloaded next to the
// running one, verified, and renamed into place; the old one stays as
// <binary>.prev. A marker file then holds the new version on probation: it
// must connect to the server within ProbationTime, or the startup guard
// (`baseline-agent.prev guard`, run by systemd before every start) puts the
// previous binary back.
const (
	ProbationTime = 5 * time.Minute
	maxAttempts   = 3         // starts of a new version before it's rolled back
	maxBinarySize = 256 << 20 // refuse anything bigger
	pendingFile   = "update-pending.json"
	failedFile    = "update-failed.json"
)

var (
	// ErrRestart ends Run after a new binary was installed; systemd starts it.
	ErrRestart = errors.New("restarting into the updated agent")
	// ErrSelfUpdateOff refuses an update the host owner turned off.
	ErrSelfUpdateOff = errors.New("self-update is off in this host's agent.conf (self_update = off); run install.sh on the host to update it")
	// ErrProbation ends Run when an updated agent couldn't reach the server
	// in time; the guard rolls it back on the next start.
	ErrProbation = errors.New("updated agent didn't connect in time")
)

type Updater struct {
	Binary   string // the installed binary, symlinks resolved
	StateDir string
	// Keys are the release keys built into this agent (pki.ReleaseKeys);
	// an update must be signed by one of them.
	Keys []ed25519.PublicKey
	// Off is agent.conf's self_update = off: Install refuses every release.
	// Probation and rollback of an update already installed still run.
	Off bool
	// Run runs a command; used to ask the new binary its version and to
	// restore SELinux labels.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// NewUpdater sets up self-update of binary ("" for the running one), trusting
// releases signed by one of keys. It fails without keys: then nothing can be
// verified, so nothing is installed.
//
// The server's own release key, pinned at enrollment by older agents
// (release.pub), is not trusted: whoever runs the server could sign with it.
func NewUpdater(stateDir, binary string, keys []ed25519.PublicKey, run func(context.Context, string, ...string) ([]byte, error)) (*Updater, error) {
	if len(keys) == 0 {
		return nil, errors.New("this build has no release keys, so it can't verify updates")
	}
	exe := binary
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return nil, err
		}
		if exe, err = filepath.EvalSymlinks(exe); err != nil {
			return nil, err
		}
	}
	return &Updater{Binary: exe, StateDir: stateDir, Keys: keys, Run: run}, nil
}

type pendingUpdate struct {
	From     string    `json:"from"`
	To       string    `json:"to"`
	Since    time.Time `json:"since"`
	Attempts int       `json:"attempts"`
}

type failedUpdate struct {
	Version string `json:"version"`
	Error   string `json:"error"`
}

// Install downloads, verifies and installs the release msg describes. On
// success the caller exits so systemd starts the new binary.
func (u *Updater) Install(ctx context.Context, client agentv1.AgentGatewayClient, msg *agentv1.UpdateAgent, current string) error {
	if u.Off {
		return ErrSelfUpdateOff
	}
	if msg.GetArch() != runtime.GOARCH {
		return fmt.Errorf("release is for %s, this agent is %s", msg.GetArch(), runtime.GOARCH)
	}
	if msg.GetSize() <= 0 || msg.GetSize() > maxBinarySize {
		return fmt.Errorf("release size %d is out of range", msg.GetSize())
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	stream, err := client.DownloadRelease(ctx, &agentv1.ReleaseRequest{Version: msg.GetVersion(), Arch: msg.GetArch()})
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	tmp := u.Binary + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	h := sha256.New()
	var n int64
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("download: %w", err)
		}
		if n += int64(len(chunk.GetData())); n > msg.GetSize() {
			return errors.New("download is larger than announced")
		}
		h.Write(chunk.GetData())
		if _, err := f.Write(chunk.GetData()); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if n != msg.GetSize() {
		return fmt.Errorf("download is %d bytes, expected %d", n, msg.GetSize())
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if sum != msg.GetSha256() {
		return fmt.Errorf("checksum mismatch: got %s, expected %s", sum, msg.GetSha256())
	}
	if !pki.VerifyRelease(u.Keys, msg.GetVersion(), msg.GetArch(), sum, msg.GetSignatures()) {
		return errors.New("no release signature verifies against the keys built into this agent")
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	// The binary must at least run here before it replaces a working one.
	out, err := u.Run(ctx, tmp, "version")
	if err != nil {
		return fmt.Errorf("new binary doesn't run: %w", err)
	}
	if v := strings.TrimSpace(string(out)); v != msg.GetVersion() {
		return fmt.Errorf("new binary reports version %q, expected %q", v, msg.GetVersion())
	}
	u.restoreLabels(ctx, tmp)

	prev := u.Binary + ".prev"
	os.Remove(prev)
	if err := os.Link(u.Binary, prev); err != nil {
		if err := copyFile(u.Binary, prev); err != nil {
			return fmt.Errorf("keeping the current binary: %w", err)
		}
	}
	// The marker goes first: if the rename never happens, the next start
	// finds it naming a version that isn't running and reports that.
	if err := u.save(pendingFile, pendingUpdate{From: current, To: msg.GetVersion(), Since: time.Now()}); err != nil {
		return err
	}
	if err := os.Rename(tmp, u.Binary); err != nil {
		os.Remove(filepath.Join(u.StateDir, pendingFile))
		return err
	}
	ok = true
	syncDir(filepath.Dir(u.Binary))
	return nil
}

// restoreLabels gives a file its SELinux default context (bin_t under
// /usr/local/libexec) where SELinux is enabled: Rocky and Bazzite enforce it.
func (u *Updater) restoreLabels(ctx context.Context, path string) {
	if _, err := os.Stat("/sys/fs/selinux/enforce"); err == nil {
		u.Run(ctx, "restorecon", path)
	}
}

// Probation reports whether this start is a freshly updated agent that
// still has to prove it can connect. A marker naming another version means
// the update never took effect; that is recorded as a failure.
func (u *Updater) Probation(version string) (from string, ok bool) {
	var p pendingUpdate
	if !u.load(pendingFile, &p) {
		return "", false
	}
	if p.To == version {
		return p.From, true
	}
	u.save(failedFile, failedUpdate{Version: p.To, Error: fmt.Sprintf("the update didn't take effect: still running %s", version)})
	os.Remove(filepath.Join(u.StateDir, pendingFile))
	return "", false
}

// Confirm ends probation: the new version reached the server.
func (u *Updater) Confirm() {
	os.Remove(filepath.Join(u.StateDir, pendingFile))
}

// Failure returns a failed update not yet reported to the server.
func (u *Updater) Failure() (version, msg string, ok bool) {
	var f failedUpdate
	if !u.load(failedFile, &f) {
		return "", "", false
	}
	return f.Version, f.Error, true
}

// ClearFailure is called once the server has the report.
func (u *Updater) ClearFailure() { os.Remove(filepath.Join(u.StateDir, failedFile)) }

// Guard runs before every start (ExecStartPre, from the previous binary).
// While an update is on probation it counts starts, and puts the previous
// binary back once the new one has had maxAttempts starts or ProbationTime
// without connecting. It returns what it did, for the journal.
func Guard(stateDir, binary string, now time.Time) (string, error) {
	u := &Updater{StateDir: stateDir, Binary: binary}
	var p pendingUpdate
	if !u.load(pendingFile, &p) {
		return "", nil
	}
	p.Attempts++
	if p.Attempts <= maxAttempts && now.Sub(p.Since) <= ProbationTime {
		return fmt.Sprintf("baseline-agent %s on probation, start %d of %d", p.To, p.Attempts, maxAttempts), u.save(pendingFile, p)
	}
	reason := fmt.Sprintf("%s didn't connect to the server within %v; rolled back to %s", p.To, ProbationTime, p.From)
	if p.Attempts > maxAttempts {
		reason = fmt.Sprintf("%s failed to start %d times; rolled back to %s", p.To, maxAttempts, p.From)
	}
	prev := binary + ".prev"
	if _, err := os.Stat(prev); err == nil {
		if err := os.Rename(prev, binary); err != nil {
			return "", fmt.Errorf("rollback: %w", err)
		}
		syncDir(filepath.Dir(binary))
	} else {
		reason += " (but no previous binary was found)"
	}
	if err := u.save(failedFile, failedUpdate{Version: p.To, Error: reason}); err != nil {
		return "", err
	}
	return reason, os.Remove(filepath.Join(stateDir, pendingFile))
}

func (u *Updater) load(name string, v any) bool {
	b, err := os.ReadFile(filepath.Join(u.StateDir, name))
	return err == nil && json.Unmarshal(b, v) == nil
}

func (u *Updater) save(name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(u.StateDir, name), b, 0o600)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
