package updategroup

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/store"
)

func stack(id, host, project, env string) store.Stack {
	return store.Stack{CIID: id, Hostname: host, Project: project, Present: true, Environment: env}
}

func ctr(st store.Stack, service string, drift bool, labels map[string]string) store.ContainerRow {
	return store.ContainerRow{Container: model.Container{Name: st.Project + "-" + service, ComposeProject: st.Project,
		ComposeService: service, Image: "img/" + service + ":2026.8", Labels: labels}, StackCI: st.CIID, Drift: drift}
}

func label(group string, order int) map[string]string {
	return map[string]string{LabelGroup: group, LabelOrder: fmt.Sprint(order)}
}

// show renders steps and held members compactly for comparison.
func show(steps []Step, held []Held) string {
	var out []string
	for _, s := range steps {
		x := s.Stack.Project
		if len(s.Services) > 0 {
			x += "[" + strings.Join(s.Services, ",") + "]"
		}
		if s.Group != "" {
			x += fmt.Sprintf("@%s/%d", s.Group, s.Order)
		}
		out = append(out, x)
	}
	for _, h := range held {
		out = append(out, "held "+h.Member.Stack.Project+"/"+h.Member.Service)
	}
	return strings.Join(out, " ")
}

func TestPlan(t *testing.T) {
	ak := stack("ak", "h1", "authentik", "")
	dup := stack("dup", "h1", "duplicati", "")
	other := stack("oth", "h2", "other", "")
	ak.UpdateGroups = map[string]store.UpdateGroup{"worker": {Group: "authentik", Order: 1}}
	rows := []store.ContainerRow{
		ctr(ak, "server", true, label("authentik", 1)),
		ctr(ak, "worker", true, nil),
		ctr(ak, "redis", true, nil),
		ctr(dup, "duplicati", true, nil),
		ctr(dup, "proxy", true, label("authentik", 2)),
		ctr(other, "proxy", false, label("authentik", 2)),
	}
	ix := New([]store.Stack{ak, dup, other}, rows)
	ok := func(Member, bool) string { return "" }

	g, found := ix.Group("authentik")
	if !found || len(g.Members) != 4 || len(g.Leaders()) != 2 {
		t.Fatalf("group: %+v", g)
	}

	// Updating the server's stack pulls in the outpost with a newer image,
	// after the server and worker; redis stays in a plain step first.
	steps, held := ix.Plan([]Target{{Stack: ak}}, ok)
	if got, want := show(steps, held), "authentik[redis] authentik[server,worker]@authentik/1 duplicati[proxy]@authentik/2"; got != want {
		t.Errorf("leader: %s, want %s", got, want)
	}

	// Updating Duplicati pulls the server in ahead of its outpost.
	steps, held = ix.Plan([]Target{{Stack: dup}}, ok)
	if got, want := show(steps, held), "duplicati[duplicati] authentik[server,worker]@authentik/1 duplicati[proxy]@authentik/2"; got != want {
		t.Errorf("dependent: %s, want %s", got, want)
	}

	// Asked for explicitly, a current member updates too.
	steps, held = ix.Plan([]Target{{Stack: other}}, ok)
	if got, want := show(steps, held), "authentik[server,worker]@authentik/1 duplicati[proxy]@authentik/2 other[proxy]@authentik/2"; got != want {
		t.Errorf("current member: %s, want %s", got, want)
	}

	// A stack with no members, or services picked outside the group, stays as asked.
	steps, held = ix.Plan([]Target{{Stack: dup, Services: []string{"duplicati"}}}, ok)
	if got := show(steps, held); got != "duplicati[duplicati]" {
		t.Errorf("services: %s", got)
	}

	// A leader that can't update holds back the later members, but not its peers.
	pinned := func(m Member, wanted bool) string {
		if m.Service == "server" {
			return "it's pinned"
		}
		return ""
	}
	steps, held = ix.Plan([]Target{{Stack: dup}}, pinned)
	if got, want := show(steps, held), "duplicati[duplicati] authentik[worker]@authentik/1 held authentik/server held duplicati/proxy"; got != want {
		t.Errorf("blocked: %s, want %s", got, want)
	}
	if !strings.Contains(held[1].Why, "waits for server in authentik on h1 (it's pinned)") {
		t.Errorf("why: %s", held[1].Why)
	}

	// A current leader that another change is updating holds them back too.
	busy := func(m Member, wanted bool) string {
		if m.Service == "server" && !wanted {
			return "another change on it is still open"
		}
		return ""
	}
	rows[0].Drift, rows[1].Drift = false, false
	ix = New([]store.Stack{ak, dup, other}, rows)
	steps, held = ix.Plan([]Target{{Stack: dup}}, busy)
	if got, want := show(steps, held), "duplicati[duplicati] held duplicati/proxy"; got != want {
		t.Errorf("busy: %s, want %s", got, want)
	}
}

func TestEnvironmentsAndLabels(t *testing.T) {
	dev, prod := stack("d", "h1", "dwi-auth", "Dev"), stack("p", "h2", "pwi-auth", "Prod")
	prod.UpdateGroups = map[string]store.UpdateGroup{"server": {Group: "ignored", Order: 5}}
	rows := []store.ContainerRow{
		ctr(dev, "server", true, label("authentik", 1)),
		ctr(prod, "server", true, label("authentik", 1)),
		ctr(prod, "proxy", true, map[string]string{LabelGroup: "authentik", LabelOrder: "two"}),
	}
	ix := New([]store.Stack{dev, prod}, rows)
	if len(ix.Groups) != 2 || ix.Groups[0].Key != "dev:authentik" || ix.Groups[1].Key != "prod:authentik" {
		t.Fatalf("groups: %+v", ix.Groups)
	}
	m, _ := ix.Of("p", "server")
	if m.Name != "authentik" || !m.Label {
		t.Errorf("the label wins over the setting: %+v", m)
	}
	m, _ = ix.Of("p", "proxy")
	if m.Order != DefaultOrder || m.Problem == "" {
		t.Errorf("bad order: %+v", m)
	}
}
