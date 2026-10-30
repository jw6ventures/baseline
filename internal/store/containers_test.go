package store_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
	"github.com/jw6ventures/baseline/internal/registry"
	"github.com/jw6ventures/baseline/internal/store"
)

const (
	nginxDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	newDigest   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func sampleContainers() model.Containers {
	return model.Containers{
		Engines: []model.ContainerEngine{{Name: "docker", Kind: "docker", Socket: "/var/run/docker.sock", Version: "28.0"}},
		Containers: []model.Container{
			{Engine: "docker", Name: "web-db-1", ID: "aaa", Image: "postgres:17", ImageID: "sha256:img-pg", State: "running",
				ComposeProject: "web", ComposeService: "db", Labels: map[string]string{"com.docker.compose.project": "web"}},
			{Engine: "docker", Name: "web-nginx-1", ID: "bbb", Image: "nginx:1.27", ImageID: "sha256:img-nginx", State: "running",
				Health: "healthy", ComposeProject: "web", ComposeService: "nginx",
				Ports: []model.ContainerPort{{HostPort: 8080, ContainerPort: 80, Proto: "tcp"}}},
			{Engine: "docker", Name: "tool", ID: "ccc", Image: "localbuild:dev", ImageID: "sha256:img-local", State: "exited", ExitCode: 1},
		},
		Images: []model.ContainerImage{
			{Engine: "docker", ID: "sha256:img-nginx", Tags: []string{"nginx:1.27"}, Digests: []string{"nginx@" + nginxDigest}},
			{Engine: "docker", ID: "sha256:img-pg", Tags: []string{"postgres:17"}, Digests: []string{"postgres@sha256:3333333333333333333333333333333333333333333333333333333333333333"}},
			{Engine: "docker", ID: "sha256:img-local", Tags: []string{"localbuild:dev"}},
		},
		Stacks: []model.ComposeStack{{Engine: "docker", Project: "web", WorkingDir: "/srv/web", Services: []string{"db", "nginx"},
			CLI: "docker compose", ConfigFiles: []model.ComposeFile{{Path: "/srv/web/compose.yaml", SHA256: "abc", Content: "services: {}"}}}},
	}
}

func ingestSection(t *testing.T, s *store.Store, r store.EnrollResult, section string, v any) {
	t.Helper()
	p, h := payload(t, v)
	if _, err := s.IngestSection(ctx, r.HostID, r.AgentID, section, h, p, ""); err != nil {
		t.Fatal(err)
	}
}

func TestContainersProjection(t *testing.T) {
	s := newTestStore(t)
	r := enroll(t, s, newToken(t, s, 0), "m1", "d1", "s1")
	c := sampleContainers()
	ingestSection(t, s, r, model.SectionContainers, c)

	rows, err := s.ListContainers(ctx, []string{r.HostID})
	if err != nil || len(rows) != 3 {
		t.Fatalf("containers = %+v %v", rows, err)
	}
	byName := map[string]store.ContainerRow{}
	for _, x := range rows {
		byName[x.Name] = x
	}
	nginx := byName["web-nginx-1"]
	if nginx.CheckRef != "docker.io/library/nginx:1.27" || !slices.Equal(nginx.ImageDigests, []string{nginxDigest}) ||
		nginx.StackCI == "" || nginx.Health != "healthy" || len(nginx.Ports) != 1 {
		t.Fatalf("nginx = %+v", nginx)
	}
	if byName["tool"].CheckRef != "" {
		t.Fatalf("a local image is checkable: %+v", byName["tool"])
	}
	h, _ := s.GetHost(ctx, r.HostID)
	if h.Containers != 3 || h.ContainersUp != 2 || h.ContainerUpdates != 0 {
		t.Fatalf("host counts %d/%d/%d", h.Containers, h.ContainersUp, h.ContainerUpdates)
	}

	// Relationships: containers run on the host and belong to the stack.
	rels, err := s.CIRelationships(ctx, nginx.CIID)
	if err != nil || len(rels) != 2 {
		t.Fatalf("relationships = %+v %v", rels, err)
	}

	// The registry has moved the tag on.
	refs, _ := s.ImageRefsToCheck(ctx, time.Now(), time.Now())
	if !slices.Equal(refs, []string{"docker.io/library/nginx:1.27", "docker.io/library/postgres:17"}) {
		t.Fatalf("refs to check = %v", refs)
	}
	s.SaveImageCheck(ctx, "docker.io/library/nginx:1.27", "docker.io", newDigest, "")
	s.SaveImageCheck(ctx, "docker.io/library/postgres:17", "docker.io", "", "rate limited (429)")
	if refs, _ := s.ImageRefsToCheck(ctx, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)); len(refs) != 0 {
		t.Fatalf("fresh checks are rechecked: %v", refs)
	}
	nginx, _ = s.GetContainer(ctx, nginx.CIID)
	if !nginx.Drift || nginx.LatestDigest != newDigest {
		t.Fatalf("no drift: %+v", nginx)
	}
	pg := byName["web-db-1"]
	pg, _ = s.GetContainer(ctx, pg.CIID)
	if pg.Drift || pg.CheckError == "" {
		t.Fatalf("failed check = %+v", pg)
	}
	// A failed recheck keeps the digest it knew.
	s.SaveImageCheck(ctx, "docker.io/library/nginx:1.27", "docker.io", "", "timeout")
	if nginx, _ = s.GetContainer(ctx, nginx.CIID); !nginx.Drift || nginx.CheckError != "timeout" {
		t.Fatalf("after failed recheck = %+v", nginx)
	}
	if h, _ = s.GetHost(ctx, r.HostID); h.ContainerUpdates != 1 {
		t.Fatalf("container updates = %d", h.ContainerUpdates)
	}

	// Pinning the stack silences it.
	if err := s.SetStackPinned(ctx, admin, nginx.StackCI, true); err != nil {
		t.Fatal(err)
	}
	if h, _ = s.GetHost(ctx, r.HostID); h.ContainerUpdates != 0 {
		t.Fatalf("pinned stack still counted: %d", h.ContainerUpdates)
	}

	// Semver rules: a Compose service's rule lives on its stack.
	rule := &registry.Rule{Track: "minor"}
	if err := s.SetSemverRule(ctx, admin, nginx.CIID, rule); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSemverRule(ctx, admin, byName["tool"].CIID, &registry.Rule{Track: "patch"}); err != nil {
		t.Fatal(err)
	}
	st, err := s.GetStack(ctx, nginx.StackCI)
	if err != nil || st.SemverRules["nginx"].Track != "minor" || !st.Pinned || st.Containers != 2 {
		t.Fatalf("stack = %+v %v", st, err)
	}
	tool, _ := s.GetContainer(ctx, byName["tool"].CIID)
	var tr registry.Rule
	if json.Unmarshal(tool.SemverRule, &tr); tr.Track != "patch" {
		t.Fatalf("container rule = %s", tool.SemverRule)
	}
	ruled, _ := s.RuledImageRefs(ctx)
	if !slices.Equal(ruled, []string{"docker.io/library/nginx:1.27"}) {
		t.Fatalf("ruled refs = %v", ruled) // tool's image can't be checked
	}
	if err := s.SetSemverRule(ctx, admin, nginx.CIID, nil); err != nil {
		t.Fatal(err)
	}
	if st, _ = s.GetStack(ctx, nginx.StackCI); len(st.SemverRules) != 0 {
		t.Fatalf("rule not cleared: %+v", st.SemverRules)
	}

	// Compose recreates nginx with a new ID and image: same CI, one history
	// entry for the image, none for state.
	c2 := sampleContainers()
	c2.Containers[1].ID, c2.Containers[1].ImageID, c2.Containers[1].Health = "ddd", "sha256:img-nginx2", "starting"
	c2.Images[0].ID = "sha256:img-nginx2"
	c2.Images[0].Digests = []string{"nginx@" + newDigest}
	ingestSection(t, s, r, model.SectionContainers, c2)
	again, _ := s.GetContainer(ctx, nginx.CIID)
	if again.ID != "ddd" || again.Drift {
		t.Fatalf("recreated = %+v", again)
	}
	hist, _ := s.HostHistory(ctx, r.HostID, 10)
	if len(hist) == 0 || hist[0].Section != model.SectionContainers ||
		!strings.Contains(string(hist[0].Diff), "containers[docker/web-nginx-1].image_id") ||
		strings.Contains(string(hist[0].Diff), "health") {
		t.Fatalf("history = %s", hist[0].Diff)
	}

	// The Docker daemon is restarting: its containers are kept.
	c3 := model.Containers{Engines: []model.ContainerEngine{{Name: "docker", Kind: "docker", Error: "connection refused"}}}
	ingestSection(t, s, r, model.SectionContainers, c3)
	if rows, _ = s.ListContainers(ctx, []string{r.HostID}); len(rows) != 3 {
		t.Fatalf("failed engine dropped containers: %d", len(rows))
	}

	// tool is removed: it turns missing an hour later, not before.
	c4 := sampleContainers()
	c4.Containers = c4.Containers[:2]
	ingestSection(t, s, r, model.SectionContainers, c4)
	if n, _ := s.MarkMissing(ctx, time.Now()); n != 0 {
		t.Fatalf("marked %d missing at once", n)
	}
	if n, _ := s.MarkMissing(ctx, time.Now().Add(2*time.Hour)); n != 1 {
		t.Fatalf("marked %d missing after an hour", n)
	}
	gone, err := s.GetCI(ctx, tool.CIID)
	if err != nil || gone.Status != "missing" || gone.HostID != r.HostID {
		t.Fatalf("tool CI = %+v %v", gone, err)
	}
	// It comes back: active again, same CI.
	ingestSection(t, s, r, model.SectionContainers, sampleContainers())
	if back, _ := s.GetCI(ctx, tool.CIID); back.Status != "active" {
		t.Fatalf("returned container = %+v", back)
	}

	// The stack goes away entirely: its settings stay.
	ingestSection(t, s, r, model.SectionContainers, model.Containers{Engines: c.Engines})
	if st, _ = s.GetStack(ctx, nginx.StackCI); st.Present || !st.Pinned {
		t.Fatalf("gone stack = %+v", st)
	}
	s.MarkMissing(ctx, time.Now().Add(2*time.Hour))
	if sc, _ := s.GetCI(ctx, nginx.StackCI); sc.Status != "missing" {
		t.Fatalf("stack CI = %+v", sc)
	}

	// Only missing discovered CIs can be deleted.
	if err := s.DeleteCI(ctx, admin, r.HostID); !errors.Is(err, store.ErrNotManual) {
		t.Fatalf("deleted a host: %v", err)
	}
	if err := s.DeleteCI(ctx, admin, nginx.StackCI); err != nil {
		t.Fatal(err)
	}

	// Revoking the host retires what runs on it.
	ingestSection(t, s, r, model.SectionContainers, sampleContainers())
	if err := s.RevokeHost(ctx, admin, r.HostID); err != nil {
		t.Fatal(err)
	}
	if ci, _ := s.GetCI(ctx, nginx.CIID); ci.Status != "retired" {
		t.Fatalf("container of revoked host = %s", ci.Status)
	}
}

func TestStackNameMetadata(t *testing.T) {
	s := newTestStore(t)
	r := enroll(t, s, newToken(t, s, 0), "m1", "d1", "s1")
	c := sampleContainers()
	c.Stacks = append(c.Stacks, model.ComposeStack{Engine: "docker", Project: "phi-healthrecords", Services: []string{"app"}})
	ingestSection(t, s, r, model.SectionContainers, c)

	stacks, err := s.ListStacks(ctx, []string{r.HostID})
	if err != nil || len(stacks) != 2 {
		t.Fatalf("stacks = %+v %v", stacks, err)
	}
	for _, st := range stacks {
		switch st.Project {
		case "phi-healthrecords":
			if st.Environment != "Prod" || st.Category != "Health" || st.Visibility != "Internal" || !st.Named() {
				t.Fatalf("named stack = %+v", st)
			}
			ci, err := s.GetCI(ctx, st.CIID)
			if err != nil || ci.Attr("environment") != "Prod" || ci.Attr("category") != "Health" || ci.Attr("visibility") != "Internal" {
				t.Fatalf("CI = %+v %v", ci, err)
			}
		case "web":
			if st.Named() || st.Category != "" || st.Visibility != "" {
				t.Fatalf("a stack without the pattern got metadata: %+v", st)
			}
		}
	}

	// The CI page lists the fields; they aren't on the form.
	types, err := s.CITypes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, ty := range types {
		if ty.Key == "compose_stack" && (len(ty.Fields) != 3 || !ty.Fields[0].Discovered) {
			t.Fatalf("compose_stack fields = %+v", ty.Fields)
		}
	}
}

func TestServicesPortsRebootCerts(t *testing.T) {
	s := newTestStore(t)
	r := enroll(t, s, newToken(t, s, 0), "m1", "d1", "s1")
	ingestSection(t, s, r, model.SectionServices, model.Services{Units: []model.Service{
		{Name: "nginx.service", Active: "active", Sub: "running", Load: "loaded", Enabled: "enabled"},
		{Name: "backup.service", Active: "failed", Sub: "failed", Load: "loaded", Enabled: "static"},
	}})
	ingestSection(t, s, r, model.SectionPorts, model.Ports{Listeners: []model.Listener{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 443, Process: "nginx", PID: 10, Unit: "nginx.service"},
		{Proto: "udp", Addr: "::", Port: 51820},
	}})
	ingestSection(t, s, r, model.SectionReboot, model.Reboot{Required: true, Reasons: []string{"the system asks for a reboot"}})
	soon := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	ingestSection(t, s, r, model.SectionCerts, model.Certs{Certs: []model.Cert{
		{Location: "/etc/letsencrypt/live/a/fullchain.pem", Subject: "CN=a", NotAfter: soon, Fingerprint: "f1"},
		{Location: "tcp:8443", Subject: "CN=b", NotAfter: time.Now().Add(200 * 24 * time.Hour).UTC().Format(time.RFC3339)},
	}})

	svcs, _ := s.HostServices(ctx, r.HostID)
	if len(svcs) != 2 || svcs[0].Name != "backup.service" {
		t.Fatalf("services = %+v", svcs)
	}
	ports, _ := s.HostPorts(ctx, r.HostID)
	if len(ports) != 2 || ports[0].Port != 443 || ports[0].Unit != "nginx.service" {
		t.Fatalf("ports = %+v", ports)
	}
	h, _ := s.GetHost(ctx, r.HostID)
	if !h.RebootRequired || len(h.RebootReasons) != 1 || h.FailedServices != 1 || h.CertsExpiring != 1 {
		t.Fatalf("host = reboot %v %v failed %d certs %d", h.RebootRequired, h.RebootReasons, h.FailedServices, h.CertsExpiring)
	}
	exp, err := s.ExpiringCerts(ctx, []string{r.HostID}, time.Now().Add(store.CertWarning))
	if err != nil || len(exp) != 1 || exp[0].DaysLeft() < 9 {
		t.Fatalf("expiring = %+v %v", exp, err)
	}
	if exp, _ := s.ExpiringCerts(ctx, nil, time.Now().Add(store.CertWarning)); len(exp) != 0 {
		t.Fatalf("another user's host certs leaked: %+v", exp)
	}

	// A service restart (new PID, active→activating) isn't history; a
	// service being disabled is.
	ingestSection(t, s, r, model.SectionServices, model.Services{Units: []model.Service{
		{Name: "nginx.service", Active: "activating", Sub: "start", Load: "loaded", Enabled: "disabled"},
		{Name: "backup.service", Active: "inactive", Sub: "dead", Load: "loaded", Enabled: "static"},
	}})
	ingestSection(t, s, r, model.SectionPorts, model.Ports{Listeners: []model.Listener{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 443, Process: "nginx", PID: 99, Unit: "nginx.service"},
		{Proto: "udp", Addr: "::", Port: 51820},
	}})
	ingestSection(t, s, r, model.SectionReboot, model.Reboot{})
	hist, _ := s.HostHistory(ctx, r.HostID, 20)
	var svcEntries, portEntries int
	for _, e := range hist {
		switch e.Section {
		case model.SectionServices:
			svcEntries++
			if !strings.Contains(string(e.Diff), "initial") && (!strings.Contains(string(e.Diff), "enabled") || strings.Contains(string(e.Diff), "active")) {
				t.Fatalf("services diff = %s", e.Diff)
			}
		case model.SectionPorts:
			portEntries++
		case model.SectionReboot:
			t.Fatalf("reboot recorded in history: %s", e.Diff)
		}
	}
	if svcEntries != 2 || portEntries != 1 {
		t.Fatalf("history: %d services, %d ports entries", svcEntries, portEntries)
	}
	if h, _ = s.GetHost(ctx, r.HostID); h.RebootRequired || h.FailedServices != 0 {
		t.Fatalf("after reboot: %+v", h)
	}
}

func TestManualCIsAndRelationships(t *testing.T) {
	s := newTestStore(t)
	types, err := s.CITypes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(types, func(t store.CIType) bool { return t.Key == "nas" })
	if i < 0 || len(types[i].Fields) == 0 || !types[i].Manual() {
		t.Fatalf("nas type = %+v", types)
	}
	nas, err := s.CreateCI(ctx, admin, store.CIInput{Type: "nas", Name: "nas1", Status: "active", Tags: []string{"storage"},
		Attrs: map[string]string{"vendor": "Synology", "tls_endpoint": "nas1.lan:5001", "model": " "}})
	if err != nil {
		t.Fatal(err)
	}
	sw, _ := s.CreateCI(ctx, admin, store.CIInput{Type: "network_device", Name: "switch1", Status: "active"})
	if err := s.AddRelationship(ctx, admin, nas, sw, "connected_to"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRelationship(ctx, admin, nas, sw, "connected_to"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate relationship: %v", err)
	}
	c, err := s.GetCI(ctx, nas)
	if err != nil || c.Attr("vendor") != "Synology" || c.Attr("model") != "" || c.Relation != 1 || !c.Manual() || c.HostID != "" {
		t.Fatalf("nas = %+v %v", c, err)
	}
	eps, _ := s.TLSEndpoints(ctx)
	if len(eps) != 1 || eps[0].Address != "nas1.lan:5001" {
		t.Fatalf("endpoints = %+v", eps)
	}

	if err := s.UpdateCI(ctx, admin, nas, store.CIInput{Type: "nas", Name: "nas1", Status: "active", Owner: "james",
		Tags: []string{"storage"}, Attrs: map[string]string{"vendor": "Synology", "firmware": "7.2"}}); err != nil {
		t.Fatal(err)
	}
	hist, _ := s.CIHistory(ctx, nas, 10)
	if len(hist) != 3 || !strings.Contains(string(hist[0].Diff), "attrs.firmware") ||
		!strings.Contains(string(hist[0].Diff), "attrs.tls_endpoint") || !strings.Contains(string(hist[1].Diff), "nas1 → switch1") {
		t.Fatalf("history = %+v", hist)
	}

	// Lists: agentless CIs are visible to everyone; discovered ones only
	// with their host.
	r := enroll(t, s, newToken(t, s, 0), "m1", "d1", "s1")
	all, _ := s.ListCIs(ctx, store.CIFilter{HostIDs: []string{r.HostID}})
	none, _ := s.ListCIs(ctx, store.CIFilter{})
	if len(all) != 3 || len(none) != 2 {
		t.Fatalf("lists: %d with the host, %d without", len(all), len(none))
	}
	if q, _ := s.ListCIs(ctx, store.CIFilter{Query: "storage"}); len(q) != 1 {
		t.Fatalf("tag search = %+v", q)
	}

	rels, _ := s.CIRelationships(ctx, sw)
	if len(rels) != 1 || rels[0].Outgoing || rels[0].Other.Name != "nas1" {
		t.Fatalf("switch relationships = %+v", rels)
	}
	if err := s.DeleteRelationship(ctx, admin, sw, rels[0].ID); err != nil {
		t.Fatal(err)
	}

	// Probes record the endpoint's certificate; failures keep the last one.
	cert := model.Cert{Location: "nas1.lan:5001", Subject: "CN=nas1", NotAfter: time.Now().Add(5 * 24 * time.Hour).UTC().Format(time.RFC3339)}
	if err := s.SaveProbeCert(ctx, nas, cert, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveProbeCert(ctx, nas, model.Cert{Location: "nas1.lan:5001"}, "connection refused"); err != nil {
		t.Fatal(err)
	}
	certs, _ := s.CICerts(ctx, nas)
	if len(certs) != 1 || certs[0].Subject != "CN=nas1" || certs[0].Error != "connection refused" {
		t.Fatalf("probe certs = %+v", certs)
	}
	if exp, _ := s.ExpiringCerts(ctx, nil, time.Now().Add(store.CertWarning)); len(exp) != 1 {
		t.Fatalf("endpoint cert not on the expiring list: %+v", exp)
	}
	s.ClearProbeCerts(ctx, nil)
	if certs, _ = s.CICerts(ctx, nas); len(certs) != 0 {
		t.Fatalf("probe certs kept: %+v", certs)
	}

	if err := s.DeleteCI(ctx, admin, nas); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCI(ctx, nas); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted CI: %v", err)
	}
}

func TestRegistryCreds(t *testing.T) {
	s := newTestStore(t)
	if err := s.SaveRegistryCred(ctx, admin, "ghcr.io", "me", "sealed1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRegistryCred(ctx, admin, "ghcr.io", "me2", "sealed2"); err != nil {
		t.Fatal(err)
	}
	creds, _ := s.ListRegistryCreds(ctx)
	if len(creds) != 1 || creds[0].Username != "me2" || creds[0].SecretEnc != "sealed2" {
		t.Fatalf("creds = %+v", creds)
	}
	if err := s.DeleteRegistryCred(ctx, admin, creds[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveTags(ctx, "docker.io/library/nginx", []string{"1.27", "1.28"}, ""); err != nil {
		t.Fatal(err)
	}
	s.SaveTags(ctx, "docker.io/library/nginx", nil, "rate limited")
	tags, _ := s.RepositoryTags(ctx, []string{"docker.io/library/nginx"})
	if len(tags["docker.io/library/nginx"]) != 2 {
		t.Fatalf("tags = %v", tags)
	}
}
