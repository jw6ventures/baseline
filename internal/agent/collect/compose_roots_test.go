package collect

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
)

func TestStoppedStacksUnderRoots(t *testing.T) {
	h := newCtrTestHost(t)
	ctx := context.Background()
	h.f.file("/opt/stacks/app/compose.yaml", "name: app\nservices:\n  web:\n    image: nginx:1.27\n    environment:\n      DB_PASSWORD: hunter2\n  worker:\n    image: busybox\nvolumes:\n  data:\n")
	h.f.file("/opt/stacks/app/compose.override.yaml", "services:\n  cron:\n    image: busybox\n")
	h.f.file("/opt/stacks/Bad Name/compose.yaml", "services:\n  x:\n    image: busybox\n")
	h.f.file("/opt/stacks/notes.txt", "")
	h.f.file("/opt/stacks/empty/README", "")
	h.f.file("/opt/stacks/old/docker-compose.yml", "services:\n  db:\n    image: postgres\n")

	if !h.c.SetComposeRoots([]string{"/srv", "/opt/stacks", "/etc", "/opt/stacks"}) || h.c.SetComposeRoots([]string{"/srv", "/opt/stacks"}) {
		t.Fatal("SetComposeRoots didn't report the change once")
	}
	got, err := h.c.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, st := range got.Stacks {
		keys = append(keys, st.Key())
	}
	// /srv/web runs; the rootful Podman can't be read, so Docker gets them.
	if strings.Join(keys, " ") != "docker/app docker/old docker/web podman:alice/blog" {
		t.Fatalf("stacks = %v", keys)
	}
	app := got.Stacks[0]
	if !app.Stopped || app.WorkingDir != "/opt/stacks/app" || app.CLI != "docker compose" || app.Orphaned ||
		strings.Join(app.Services, ",") != "cron,web,worker" || len(app.ConfigFiles) != 2 ||
		app.ConfigFiles[0].Path != "/opt/stacks/app/compose.yaml" || app.ConfigFiles[1].Path != "/opt/stacks/app/compose.override.yaml" {
		t.Fatalf("app = %+v", app)
	}
	if strings.Contains(app.ConfigFiles[0].Content, "hunter2") {
		t.Error("a secret left the host")
	}
	if got.Stacks[2].Stopped {
		t.Error("a running stack is marked stopped")
	}

	// Jobs find them too, without containers.
	st, err := h.c.Stack(ctx, "docker", "old")
	if err != nil || !st.Stopped || len(st.Containers) != 0 || st.Socket != "/var/run/docker.sock" ||
		st.ConfigFiles[0].Path != "/opt/stacks/old/docker-compose.yml" {
		t.Fatalf("Stack(old) = %+v, %v", st, err)
	}
	if _, err := h.c.Stack(ctx, "docker", "empty"); !errors.Is(err, ErrNoStack) {
		t.Errorf("Stack(empty): %v", err)
	}

	// Without roots, only what runs.
	h.c.SetComposeRoots(nil)
	if got, _ := h.c.Collect(ctx); len(got.Stacks) != 2 {
		t.Errorf("stacks without roots = %+v", got.Stacks)
	}
}

func TestComposeServices(t *testing.T) {
	for content, want := range map[string][]string{
		"services:\n  web:\n    image: x\n    ports:\n      - 80:80\n  \"db\":\n    image: y\n# c\nnetworks:\n  front:\n": {"web", "db"},
		"version: '3'\nservices: # the apps\n\n    a:\n        image: x\n    b: {image: y}\n":                             {"a", "b"},
		"name: x\nvolumes:\n  data:\n": nil,
	} {
		if got := composeServices(content); !slices.Equal(got, want) {
			t.Errorf("composeServices(%q) = %v, want %v", content, got, want)
		}
	}
}

func TestStoppedStacksOwnedByRootlessUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give alice a directory")
	}
	h := newCtrTestHost(t)
	ctx := context.Background()
	h.f.file("/home/alice/stacks/notes/compose.yaml", "services:\n  web:\n    image: nginx\n")
	h.f.file("/home/alice/stacks/root/compose.yaml", "services:\n  web:\n    image: nginx\n")
	h.f.file("/home/alice/stacks/peek/compose.yaml", "services:\n  web:\n    image: nginx\n")
	for _, d := range []string{"notes", "peek"} {
		os.Chown(filepath.Join(h.f.env.Root, "/home/alice/stacks", d), 4242, 4242)
	}
	// A root-only file in alice's directory isn't read for her stack.
	os.Chmod(filepath.Join(h.f.env.Root, "/home/alice/stacks/peek/compose.yaml"), 0o600)
	h.c.SetComposeRoots([]string{"/home/alice/stacks"})
	got, err := h.c.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stacks := map[string]model.ComposeStack{}
	for _, st := range got.Stacks {
		stacks[st.Key()] = st
	}
	if st, ok := stacks["podman:alice/notes"]; !ok || !st.Stopped || st.ConfigFiles[0].Error != "" {
		t.Errorf("alice's stack = %+v (stacks %v)", st, slices.Collect(maps.Keys(stacks)))
	}
	if _, ok := stacks["docker/root"]; !ok {
		t.Errorf("root's directory isn't Docker's stack: %v", slices.Collect(maps.Keys(stacks)))
	}
	if st := stacks["podman:alice/peek"]; len(st.ConfigFiles) != 1 || st.ConfigFiles[0].Error != "isn't the engine user's file" ||
		st.ConfigFiles[0].Content != "" || !st.Orphaned {
		t.Errorf("peek = %+v", st)
	}
	st, err := h.c.Stack(ctx, "podman:alice", "notes")
	if err != nil || st.User != "alice" || st.UID != "4242" || st.GID == "" || !st.Stopped {
		t.Errorf("Stack(podman:alice, notes) = %+v, %v", st, err)
	}
}
