package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/jw6ventures/baseline/api/agent/v1"
)

// installed lays out a binary dir after a self-update from 1.0 to 2.0.
func installed(t *testing.T) (stateDir, binary string, since time.Time) {
	stateDir, binDir := t.TempDir(), t.TempDir()
	binary = filepath.Join(binDir, "baseline-agent")
	os.WriteFile(binary, []byte("v2"), 0o755)
	os.WriteFile(binary+".prev", []byte("v1"), 0o755)
	since = time.Now()
	u := &Updater{StateDir: stateDir}
	if err := u.save(pendingFile, pendingUpdate{From: "1.0", To: "2.0", Since: since}); err != nil {
		t.Fatal(err)
	}
	return stateDir, binary, since
}

func read(t *testing.T, path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func TestGuardRollsBackAfterRepeatedStarts(t *testing.T) {
	stateDir, binary, since := installed(t)
	for i := 1; i <= maxAttempts; i++ {
		msg, err := Guard(stateDir, binary, since.Add(time.Duration(i)*time.Second))
		if err != nil || !strings.Contains(msg, "probation") || read(t, binary) != "v2" {
			t.Fatalf("start %d: %q %v", i, msg, err)
		}
	}
	msg, err := Guard(stateDir, binary, since.Add(10*time.Second))
	if err != nil || !strings.Contains(msg, "failed to start 3 times") {
		t.Fatalf("%q %v", msg, err)
	}
	if read(t, binary) != "v1" {
		t.Fatal("previous binary not restored")
	}
	u := &Updater{StateDir: stateDir}
	v, reason, ok := u.Failure()
	if !ok || v != "2.0" || !strings.Contains(reason, "rolled back to 1.0") {
		t.Fatalf("failure = %q %q %v", v, reason, ok)
	}
	// Nothing pending any more: further starts are left alone.
	if msg, _ := Guard(stateDir, binary, since.Add(time.Hour)); msg != "" {
		t.Fatalf("guard acted again: %q", msg)
	}
}

func TestGuardRollsBackAfterProbationTime(t *testing.T) {
	stateDir, binary, since := installed(t)
	Guard(stateDir, binary, since.Add(time.Second)) // the new version's first start
	// It ran but never reached the server, exited at the deadline, and
	// systemd starts it again.
	msg, err := Guard(stateDir, binary, since.Add(ProbationTime+10*time.Second))
	if err != nil || !strings.Contains(msg, "didn't connect") || read(t, binary) != "v1" {
		t.Fatalf("%q %v %q", msg, err, read(t, binary))
	}
}

func TestProbationAndConfirm(t *testing.T) {
	stateDir, _, _ := installed(t)
	u := &Updater{StateDir: stateDir}
	if from, ok := u.Probation("2.0"); !ok || from != "1.0" {
		t.Fatalf("probation = %q %v", from, ok)
	}
	u.Confirm()
	if _, ok := u.Probation("2.0"); ok {
		t.Fatal("still on probation after confirming")
	}
	if _, _, ok := u.Failure(); ok {
		t.Fatal("a confirmed update reported as failed")
	}
}

func TestProbationWrongVersionIsAFailure(t *testing.T) {
	stateDir, _, _ := installed(t)
	u := &Updater{StateDir: stateDir}
	// The old binary is running although 2.0 was installed.
	if _, ok := u.Probation("1.0"); ok {
		t.Fatal("old binary put on probation")
	}
	v, reason, ok := u.Failure()
	if !ok || v != "2.0" || !strings.Contains(reason, "still running 1.0") {
		t.Fatalf("%q %q %v", v, reason, ok)
	}
	u.ClearFailure()
	if _, _, ok := u.Failure(); ok {
		t.Fatal("failure not cleared")
	}
	if _, err := os.Stat(filepath.Join(stateDir, pendingFile)); !os.IsNotExist(err) {
		t.Fatal("marker left behind")
	}
}

func TestQueueMergesRequests(t *testing.T) {
	q := newQueue()
	q.add("packages", false, "")
	q.add("os", false, "")
	q.add("packages", true, "job-1")
	q.add("packages", false, "")
	ctx := t.Context()
	name, force, job, _ := q.next(ctx)
	if name != "packages" || !force || job != "job-1" {
		t.Fatalf("%s %v %q", name, force, job)
	}
	if name, force, job, _ = q.next(ctx); name != "os" || force || job != "" {
		t.Fatalf("%s %v %q", name, force, job)
	}
}

func TestMetricRingDropsOldest(t *testing.T) {
	r := newMetricRing(2)
	for i := range 3 {
		r.push(newBatch(int64(i)))
	}
	b := r.peek()
	if b.GetTsUnix() != 1 {
		t.Fatalf("oldest kept = %d", b.GetTsUnix())
	}
	r.pop(b)
	if r.peek().GetTsUnix() != 2 {
		t.Fatal("pop")
	}
}

func TestPendingFileFormat(t *testing.T) {
	// The guard in an older binary reads what a newer one wrote.
	stateDir, _, _ := installed(t)
	var raw map[string]any
	json.Unmarshal([]byte(read(t, filepath.Join(stateDir, pendingFile))), &raw)
	for _, k := range []string{"from", "to", "since", "attempts"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("missing %q in %v", k, raw)
		}
	}
}

func newBatch(ts int64) *agentv1.MetricBatch { return &agentv1.MetricBatch{TsUnix: ts} }

func TestInstallRefusedWhenOff(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "baseline-agent")
	os.WriteFile(binary, []byte("v1"), 0o755)
	u := &Updater{Binary: binary, StateDir: t.TempDir(), Off: true}
	// The refusal comes before any download, so no client is needed.
	err := u.Install(context.Background(), nil, &agentv1.UpdateAgent{Version: "2.0", Arch: "amd64", Size: 2}, "1.0")
	if !errors.Is(err, ErrSelfUpdateOff) {
		t.Fatalf("Install = %v", err)
	}
	if read(t, binary) != "v1" {
		t.Fatal("binary replaced")
	}
	if _, err := os.Stat(binary + ".new"); !os.IsNotExist(err) {
		t.Fatal("download started")
	}
}
