package collect

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/model"
)

// ctrTestEngine is a fake Docker or Podman engine on a real unix socket.
// Routes are keyed by request URI without the version prefix; a body of
// "500|{...}" answers with that status.
type ctrTestEngine struct {
	podman bool
	api    string

	mu     sync.Mutex
	routes map[string]string
	hits   map[string]int
}

var ctrTestVersionPrefix = regexp.MustCompile(`^/v[0-9][0-9.]*`)

func ctrTestServe(t *testing.T, sock string, podman bool) *ctrTestEngine {
	t.Helper()
	fe := &ctrTestEngine{podman: podman, api: "1.47", routes: map[string]string{}, hits: map[string]int{}}
	if podman {
		fe.api = "1.41"
	}
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: fe, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return fe
}

func (fe *ctrTestEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	uri := r.URL.RequestURI()
	if fe.podman {
		w.Header().Set("Libpod-Api-Version", "5.2.2")
	}
	if uri == "/version" {
		if fe.podman {
			w.Write([]byte(`{"Platform":{"Name":"linux/amd64/fedora-40"},"Components":[{"Name":"Podman Engine","Version":"5.2.2","Details":{"APIVersion":"5.2.2","MinAPIVersion":"4.0.0","Os":"linux"}}],"Version":"5.2.2","ApiVersion":"1.41","MinAPIVersion":"1.24","Os":"linux","Arch":"amd64"}`))
		} else {
			w.Write([]byte(`{"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine","Version":"27.3.1","Details":{"ApiVersion":"1.47","MinAPIVersion":"1.24"}}],"Version":"27.3.1","ApiVersion":"1.47","MinAPIVersion":"1.24","Os":"linux","Arch":"amd64"}`))
		}
		return
	}
	prefix := ctrTestVersionPrefix.FindString(uri)
	libpod := strings.HasPrefix(uri[len(prefix):], "/libpod/")
	if prefix != "/v"+fe.api && !(fe.podman && libpod && prefix == "/v5.2.2") {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"message":"unexpected version prefix in %s"}`, uri)
		return
	}
	uri = uri[len(prefix):]
	fe.mu.Lock()
	body, ok := fe.routes[uri]
	fe.hits[uri]++
	fe.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"No such container"}`))
		return
	}
	if code, rest, ok := strings.Cut(body, "|"); ok && len(code) == 3 {
		n, _ := strconv.Atoi(code)
		w.WriteHeader(n)
		body = rest
	}
	w.Write([]byte(body))
}

func (fe *ctrTestEngine) set(uri, body string) {
	fe.mu.Lock()
	fe.routes[uri] = body
	fe.mu.Unlock()
}

func (fe *ctrTestEngine) count(uri string) int {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	return fe.hits[uri]
}

var (
	ctrTestWebID = strings.Repeat("a1", 32)
	ctrTestDBID  = strings.Repeat("b2", 32)
	ctrTestGone  = strings.Repeat("c3", 32)
	ctrTestWPID  = strings.Repeat("d4", 32)
	ctrTestImg1  = strings.Repeat("e5", 32)
	ctrTestImg2  = strings.Repeat("f6", 32)
	ctrTestImg3  = strings.Repeat("07", 32)
)

func ctrTestDockerList(reversed bool) string {
	web := `{"Id":"` + ctrTestWebID + `","Names":["/web-nginx-1"],"Image":"nginx:1.27","ImageID":"sha256:` + ctrTestImg1 + `","Command":"/docker-entrypoint.sh nginx -g 'daemon off;'","Created":1727000000,"Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"}],"Labels":{"com.docker.compose.project":"web"},"State":"running","Status":"Up 2 hours (healthy)","HostConfig":{"NetworkMode":"web_default"},"Mounts":[]}`
	// The db container's tag has moved on: the list shows the bare image ID.
	db := `{"Id":"` + ctrTestDBID + `","Names":["/db"],"Image":"sha256:` + ctrTestImg2 + `","ImageID":"sha256:` + ctrTestImg2 + `","Command":"docker-entrypoint.sh postgres","Created":1726000000,"Ports":[],"Labels":{},"State":"exited","Status":"Exited (137) 3 days ago"}`
	gone := `{"Id":"` + ctrTestGone + `","Names":["/gone"],"Image":"busybox","ImageID":"sha256:` + ctrTestImg2 + `","State":"running"}`
	if reversed {
		return "[" + gone + "," + db + "," + web + "]"
	}
	return "[" + web + "," + db + "," + gone + "]"
}

var ctrTestWebInspect = `{"Id":"` + ctrTestWebID + `","Created":"2024-09-22T10:13:20.123456789Z","Path":"/docker-entrypoint.sh","Args":["nginx","-g","daemon off;"],
"State":{"Status":"running","Running":true,"Paused":false,"Restarting":false,"OOMKilled":false,"Dead":false,"Pid":4242,"ExitCode":0,"Error":"","StartedAt":"2024-09-22T10:13:21.5Z","FinishedAt":"0001-01-01T00:00:00Z","Health":{"Status":"healthy","FailingStreak":0,"Log":[]}},
"Image":"sha256:` + ctrTestImg1 + `","Name":"/web-nginx-1","RestartCount":1,
"HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"","HostPort":"8080"}]},"RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0}},
"Mounts":[{"Type":"volume","Name":"web_data","Source":"/var/lib/docker/volumes/web_data/_data","Destination":"/usr/share/nginx/html","Driver":"local","Mode":"z","RW":true,"Propagation":""},{"Type":"bind","Source":"/srv/web/nginx.conf","Destination":"/etc/nginx/nginx.conf","Mode":"ro","RW":false,"Propagation":"rprivate"}],
"Config":{"Hostname":"a1a1a1a1a1a1","Env":["NGINX_VERSION=1.27.2","API_TOKEN=s3cr3t-in-env"],"Cmd":["nginx","-g","daemon off;"],"Image":"nginx:1.27","Labels":{"com.docker.compose.project":"web","com.docker.compose.service":"nginx","com.docker.compose.project.working_dir":"/srv/web","com.docker.compose.project.config_files":"compose.yaml,/srv/web/compose.override.yaml","com.docker.compose.version":"2.29.7"}},
"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"},{"HostIp":"::","HostPort":"8080"},{"HostIp":"0.0.0.0","HostPort":"8080"}],"443/tcp":null,"53/udp":[{"HostIp":"127.0.0.1","HostPort":"5353"}]},"Networks":{"web_default":{"IPAddress":"172.18.0.2"},"proxy":{"IPAddress":"10.0.0.5"}}}}`

var ctrTestDBInspect = `{"Id":"` + ctrTestDBID + `","Created":"2024-09-10T08:00:00Z","Path":"docker-entrypoint.sh","Args":["postgres"],
"State":{"Status":"exited","Running":false,"Paused":false,"Restarting":false,"OOMKilled":false,"Dead":false,"Pid":0,"ExitCode":137,"Error":"","StartedAt":"2024-09-20T08:00:00Z","FinishedAt":"2024-09-21T08:00:00Z"},
"Image":"sha256:` + ctrTestImg2 + `","Name":"/db","RestartCount":0,
"HostConfig":{"RestartPolicy":{"Name":"","MaximumRetryCount":0}},"Mounts":[],
"Config":{"Env":["POSTGRES_PASSWORD=hunter2"],"Cmd":["postgres"],"Image":"postgres:16","Labels":null},
"NetworkSettings":{"Ports":{},"Networks":{"bridge":{}}}}`

var ctrTestDockerImages = `[{"Containers":-1,"Created":1726600000,"Id":"sha256:` + ctrTestImg1 + `","Labels":{},"ParentId":"","RepoDigests":["nginx@sha256:d2eb56950b84efe34f966a2b92efb1a1a2ea53e7e93b94cdf45a27cf3cd47fc0"],"RepoTags":["nginx:latest","nginx:1.27"],"SharedSize":-1,"Size":191670474},
{"Containers":-1,"Created":1725000000,"Id":"sha256:` + ctrTestImg2 + `","Labels":null,"ParentId":"","RepoDigests":["<none>@<none>"],"RepoTags":["<none>:<none>"],"SharedSize":-1,"Size":453000000}]`

var ctrTestWPList = `[{"Id":"` + ctrTestWPID + `","Names":["/blog_wp_1"],"Image":"docker.io/library/wordpress:6.6","ImageID":"sha256:` + ctrTestImg3 + `","Command":"apache2-foreground","Created":1726800000,"Ports":[{"IP":"","PrivatePort":80,"PublicPort":8081,"Type":"tcp"}],"Labels":{"io.podman.compose.project":"blog"},"State":"running","Status":"Up 3 hours"}]`

// Podman's compat inspect: the image ID comes without "sha256:", and there
// is no health check.
var ctrTestWPInspect = `{"Id":"` + ctrTestWPID + `","Created":"2024-09-20T03:00:00.123456789-05:00","Path":"docker-entrypoint.sh","Args":["apache2-foreground"],
"State":{"Status":"running","Running":true,"Paused":false,"Restarting":false,"OOMKilled":false,"Dead":false,"Pid":5151,"ExitCode":0,"Error":"","StartedAt":"2024-09-20T03:00:01-05:00","FinishedAt":"0001-01-01T00:00:00Z"},
"Image":"` + ctrTestImg3 + `","Name":"blog_wp_1","RestartCount":0,
"HostConfig":{"RestartPolicy":{"Name":"always","MaximumRetryCount":0}},
"Mounts":[{"Type":"bind","Source":"/home/alice/blog/wp","Destination":"/var/www/html","Driver":"","Mode":"","RW":true,"Propagation":"rprivate"}],
"Config":{"Env":["WORDPRESS_DB_PASSWORD=hunter3"],"Image":"docker.io/library/wordpress:6.6","Labels":{"com.docker.compose.project":"blog","com.docker.compose.service":"wp","com.docker.compose.project.working_dir":"/home/alice/blog","com.docker.compose.project.config_files":"/home/alice/blog/compose.yml","io.podman.compose.project":"blog"}},
"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"","HostPort":"8081"}]},"Networks":{"blog_default":{}}}}`

const ctrTestWebCompose = `services:
  nginx:
    image: nginx:1.27
    environment:
      POSTGRES_PASSWORD: hunter2
      DB_PASSWORD: ${DB_PASSWORD}
      DATABASE_URL: postgres://web:pw123@db/web
      - API_KEY=abc123
`

type ctrTestHost struct {
	f                        *fixture
	docker, podman, rootless *ctrTestEngine
	c                        *ContainerCollector
}

// newCtrTestHost is a host with Docker, an unhealthy rootful Podman and
// alice's rootless Podman. alice is uid 4242 rather than 1000: a stopped
// stack belongs to the rootless engine of its directory's owner, and the
// test's files belong to whoever runs it, often uid 1000.
func newCtrTestHost(t *testing.T) *ctrTestHost {
	f := newFixture(t)
	h := &ctrTestHost{f: f, c: &ContainerCollector{Env: f.env}}
	f.file("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:4242:4242:Alice:/home/alice:/bin/bash\n")
	f.file("/usr/libexec/docker/cli-plugins/docker-compose", "")
	f.cmds["podman"] = ""
	f.cmds["podman-compose"] = ""

	h.docker = ctrTestServe(t, filepath.Join(f.env.Root, "/var/run/docker.sock"), false)
	h.docker.set("/containers/json?all=1", ctrTestDockerList(false))
	h.docker.set("/containers/"+ctrTestWebID+"/json", ctrTestWebInspect)
	h.docker.set("/containers/"+ctrTestDBID+"/json", ctrTestDBInspect)
	h.docker.set("/images/json", ctrTestDockerImages)

	h.podman = ctrTestServe(t, filepath.Join(f.env.Root, "/run/podman/podman.sock"), true)
	h.podman.set("/containers/json?all=1", `500|{"cause":"database is locked","message":"database is locked","response":500}`)

	h.rootless = ctrTestServe(t, filepath.Join(f.env.Root, "/run/user/4242/podman/podman.sock"), true)
	h.rootless.set("/containers/json?all=1", ctrTestWPList)
	h.rootless.set("/containers/"+ctrTestWPID+"/json", ctrTestWPInspect)
	h.rootless.set("/libpod/containers/json?all=true", `[{"Id":"`+ctrTestWPID+`","Names":["blog_wp_1"],"Pod":"9a8b7c","PodName":"pod_blog","State":"running"}]`)
	h.rootless.set("/images/json", `[{"Id":"sha256:`+ctrTestImg3+`","ParentId":"","RepoTags":["docker.io/library/wordpress:6.6"],"RepoDigests":["docker.io/library/wordpress@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],"Created":1726500000,"Size":700000000,"SharedSize":0,"VirtualSize":700000000,"Labels":null,"Containers":1}]`)

	f.file("/srv/web/compose.yaml", ctrTestWebCompose)
	f.file("/home/alice/blog/compose.yml", "services:\n  wp:\n    image: wordpress:6.6\n")
	return h
}

func TestContainers(t *testing.T) {
	h := newCtrTestHost(t)
	got, err := h.c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	engines := map[string]model.ContainerEngine{}
	var names []string
	for _, e := range got.Engines {
		engines[e.Name] = e
		names = append(names, e.Name)
	}
	if strings.Join(names, ",") != "docker,podman,podman:alice" {
		t.Fatalf("engines = %+v", got.Engines)
	}
	if e := engines["docker"]; e.Kind != "docker" || e.Version != "27.3.1" || e.APIVersion != "1.47" || e.Socket != "/var/run/docker.sock" || e.Error != "" {
		t.Errorf("docker = %+v", e)
	}
	if e := engines["podman"]; e.Kind != "podman" || e.Error != "podman: GET /containers/json: 500 database is locked" {
		t.Errorf("rootful podman = %+v", e)
	}
	if e := engines["podman:alice"]; e.Kind != "podman" || e.Socket != "/run/user/4242/podman/podman.sock" || e.Error != "" {
		t.Errorf("rootless podman = %+v", e)
	}

	var keys []string
	ctrs := map[string]model.Container{}
	for _, c := range got.Containers {
		keys = append(keys, c.Key())
		ctrs[c.Key()] = c
	}
	if strings.Join(keys, " ") != "docker/db docker/web-nginx-1 podman:alice/blog_wp_1" {
		t.Fatalf("containers = %v", keys)
	}
	web := ctrs["docker/web-nginx-1"]
	wantPorts := []model.ContainerPort{
		{HostIP: "127.0.0.1", HostPort: 5353, ContainerPort: 53, Proto: "udp"},
		{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Proto: "tcp"},
		{HostIP: "::", HostPort: 8080, ContainerPort: 80, Proto: "tcp"},
		{ContainerPort: 443, Proto: "tcp"},
	}
	if web.ID != ctrTestWebID || web.Image != "nginx:1.27" || web.ImageID != "sha256:"+ctrTestImg1 ||
		web.Created != "2024-09-22T10:13:20Z" || web.StartedAt != "2024-09-22T10:13:21Z" || web.State != "running" ||
		web.Health != "healthy" || web.ExitCode != 0 || web.RestartCount != 1 || web.RestartPolicy != "unless-stopped" ||
		web.ComposeProject != "web" || web.ComposeService != "nginx" || web.Pod != "" ||
		fmt.Sprint(web.Ports) != fmt.Sprint(wantPorts) || strings.Join(web.Networks, ",") != "proxy,web_default" ||
		fmt.Sprint(web.Mounts) != "[{bind /srv/web/nginx.conf /etc/nginx/nginx.conf false} {volume web_data /usr/share/nginx/html true}]" ||
		web.Labels["com.docker.compose.version"] != "2.29.7" {
		t.Errorf("web = %+v", web)
	}
	db := ctrs["docker/db"]
	if db.Image != "postgres:16" || db.State != "exited" || db.ExitCode != 137 || db.RestartPolicy != "no" ||
		db.StartedAt != "2024-09-20T08:00:00Z" || db.Labels != nil || db.Ports != nil || db.Health != "" {
		t.Errorf("db = %+v", db)
	}
	wp := ctrs["podman:alice/blog_wp_1"]
	if wp.ImageID != "sha256:"+ctrTestImg3 || wp.Pod != "pod_blog" || wp.Created != "2024-09-20T08:00:00Z" ||
		wp.RestartPolicy != "always" || fmt.Sprint(wp.Ports) != "[{ 8081 80 tcp}]" {
		t.Errorf("wp = %+v", wp)
	}

	if len(got.Images) != 3 {
		t.Fatalf("images = %+v", got.Images)
	}
	if im := got.Images[0]; im.Engine != "docker" || im.ID != "sha256:"+ctrTestImg1 ||
		strings.Join(im.Tags, ",") != "nginx:1.27,nginx:latest" || len(im.Digests) != 1 ||
		im.SizeBytes != 191670474 || im.Created != "2024-09-17T19:06:40Z" {
		t.Errorf("image 0 = %+v", im)
	}
	if im := got.Images[1]; im.ID != "sha256:"+ctrTestImg2 || im.Tags != nil || im.Digests != nil {
		t.Errorf("dangling image = %+v", im)
	}
	if im := got.Images[2]; im.Engine != "podman:alice" || im.ID != wp.ImageID {
		t.Errorf("podman image = %+v", im)
	}

	if len(got.Stacks) != 2 {
		t.Fatalf("stacks = %+v", got.Stacks)
	}
	ws := got.Stacks[0]
	if ws.Key() != "docker/web" || ws.WorkingDir != "/srv/web" || strings.Join(ws.Services, ",") != "nginx" ||
		ws.CLI != "docker compose" || !ws.Orphaned || len(ws.ConfigFiles) != 2 {
		t.Fatalf("web stack = %+v", ws)
	}
	main, override := ws.ConfigFiles[0], ws.ConfigFiles[1]
	if main.Path != "/srv/web/compose.yaml" || main.Size != int64(len(ctrTestWebCompose)) ||
		main.SHA256 != model.Hash([]byte(ctrTestWebCompose)) || main.Error != "" || main.Truncated {
		t.Errorf("compose.yaml = %+v", main)
	}
	for _, leak := range []string{"hunter2", "pw123", "abc123"} {
		if strings.Contains(main.Content, leak) {
			t.Errorf("compose content leaks %q:\n%s", leak, main.Content)
		}
	}
	if !strings.Contains(main.Content, "DB_PASSWORD: ${DB_PASSWORD}") {
		t.Errorf("variable reference masked:\n%s", main.Content)
	}
	if override.Path != "/srv/web/compose.override.yaml" || override.Error != "not found" || override.SHA256 != "" {
		t.Errorf("override = %+v", override)
	}
	bs := got.Stacks[1]
	if bs.Key() != "podman:alice/blog" || bs.CLI != "podman compose" || bs.Orphaned || len(bs.ConfigFiles) != 1 || bs.ConfigFiles[0].Error != "" {
		t.Errorf("blog stack = %+v", bs)
	}

	// Never environment variables: they hold secrets.
	b, h1, err := model.Encode(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"s3cr3t-in-env", "hunter3", "NGINX_VERSION", "daemon off"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("section contains %q", leak)
		}
	}

	// Deterministic whatever order the engine lists things in.
	h.docker.set("/containers/json?all=1", ctrTestDockerList(true))
	again, err := h.c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, h2, _ := model.Encode(again); h2 != h1 {
		t.Error("hash changed between identical collections")
	}
}

func TestContainersNoEngines(t *testing.T) {
	f := newFixture(t)
	got, err := (&ContainerCollector{Env: f.env}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b, _, _ := model.Encode(got); string(b) != `{"engines":[],"containers":[],"images":[],"stacks":[]}` {
		t.Fatalf("got %s", b)
	}
}

func TestContainersPodmanDocker(t *testing.T) {
	// podman-docker links docker.sock to Podman's socket: one engine, named
	// for what it is.
	f := newFixture(t)
	fe := ctrTestServe(t, filepath.Join(f.env.Root, "/run/podman/podman.sock"), true)
	fe.set("/containers/json?all=1", "[]")
	fe.set("/images/json", "[]")
	fe.set("/libpod/containers/json?all=true", "[]")
	f.link("/var/run/docker.sock", filepath.Join(f.env.Root, "/run/podman/podman.sock"))
	got, err := (&ContainerCollector{Env: f.env}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Engines) != 1 || got.Engines[0].Name != "podman" || got.Engines[0].Socket != "/run/podman/podman.sock" {
		t.Fatalf("engines = %+v", got.Engines)
	}
	if caps := strings.Join(f.env.Capabilities(), ","); caps != "docker,podman,pkg-pin" {
		t.Errorf("caps = %s", caps)
	}

	// The compatible socket alone, without the rootful path, is still Podman.
	g := newFixture(t)
	fe2 := ctrTestServe(t, filepath.Join(g.env.Root, "/var/run/docker.sock"), true)
	fe2.set("/containers/json?all=1", "[]")
	fe2.set("/images/json", "[]")
	got, _ = (&ContainerCollector{Env: g.env}).Collect(context.Background())
	if len(got.Engines) != 1 || got.Engines[0].Name != "podman" || got.Engines[0].Kind != "podman" || got.Engines[0].Error != "" {
		t.Fatalf("engines = %+v", got.Engines)
	}
}

func TestContainersStartPodmanSocket(t *testing.T) {
	f := newFixture(t)
	f.file("/usr/lib/systemd/system/podman.socket", "[Socket]\n")
	f.cmds["systemctl"] = ""
	starts := 0
	f.env.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name+" "+strings.Join(args, " ") != "systemctl start podman.socket" {
			return nil, fmt.Errorf("unexpected %s %v", name, args)
		}
		starts++
		if starts == 1 {
			fe := ctrTestServe(t, filepath.Join(f.env.Root, "/run/podman/podman.sock"), true)
			fe.set("/containers/json?all=1", "[]")
			fe.set("/images/json", "[]")
		}
		return nil, nil
	}
	c := &ContainerCollector{Env: f.env, StartPodmanSocket: true}
	got, err := c.Collect(context.Background())
	if err != nil || len(got.Engines) != 1 || got.Engines[0].Name != "podman" {
		t.Fatalf("engines = %+v, %v", got.Engines, err)
	}
	os.Remove(filepath.Join(f.env.Root, "/run/podman/podman.sock"))
	c.Collect(context.Background())
	if starts != 1 {
		t.Errorf("started %d times", starts)
	}
}

func TestMaskComposeSecrets(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"  POSTGRES_PASSWORD: hunter2", "  POSTGRES_PASSWORD: ********"},
		{"  password: 'hunter2' # db", "  password: ********"},
		{`  "API_KEY": "abc"`, `  "API_KEY": ********`},
		{"  - DB_PASSWORD=hunter2", "  - DB_PASSWORD=********"},
		{`  - "JWT_SECRET=abc def"`, `  - "JWT_SECRET=********"`},
		{"GITHUB_TOKEN=ghp_123", "GITHUB_TOKEN=********"},
		{"  - Private-Key: x", "  - Private-Key: ********"},
		{"  # SMTP_PASSWD: old", "  # SMTP_PASSWD: ********"},
		{"  AWS_CREDENTIALS: x", "  AWS_CREDENTIALS: ********"},
		// Variable references and empty values hold nothing.
		{"  DB_PASSWORD: ${DB_PASSWORD}", "  DB_PASSWORD: ${DB_PASSWORD}"},
		{"  DB_PASSWORD: \"${DB_PASSWORD:?set it}\"", "  DB_PASSWORD: \"${DB_PASSWORD:?set it}\""},
		{"  - DB_PASSWORD=$DB_PASSWORD", "  - DB_PASSWORD=$DB_PASSWORD"},
		{"  DB_PASSWORD:", "  DB_PASSWORD:"},
		{"  DB_PASSWORD: ''", "  DB_PASSWORD: ''"},
		{"  - DB_PASSWORD=", "  - DB_PASSWORD="},
		{"  - DB_PASSWORD", "  - DB_PASSWORD"},
		{"secrets:", "secrets:"},
		// A default is a literal value.
		{"  DB_PASSWORD: ${DB_PASSWORD:-hunter2}", "  DB_PASSWORD: ********"},
		// Other keys are left alone, URL passwords aren't.
		{"    image: ghcr.io/org/auth-proxy:1.2", "    image: ghcr.io/org/auth-proxy:1.2"},
		{"      - 8080:80", "      - 8080:80"},
		{"  DATABASE_URL: postgres://app:pw123@db:5432/app", "  DATABASE_URL: postgres://app:********@db:5432/app"},
		{"  - REDIS_URL=redis://:pw123@cache", "  - REDIS_URL=redis://:********@cache"},
		{"  DATABASE_URL: postgres://app:${PW}@db/app", "  DATABASE_URL: postgres://app:${PW}@db/app"},
		// A Traefik router's name says nothing about its labels' values.
		{"      - \"traefik.http.routers.authentik.rule=Host(`auth.example.com`)\"", "      - \"traefik.http.routers.authentik.rule=Host(`auth.example.com`)\""},
		{"      traefik.http.routers.auth.rule: Host(`auth.example.com`)", "      traefik.http.routers.auth.rule: Host(`auth.example.com`)"},
		{"      - traefik.http.middlewares.auth.basicauth.users=admin:$$apr1$$x", "      - traefik.http.middlewares.auth.basicauth.users=********"},
	} {
		if got := maskComposeSecrets(tc.in + "\n"); got != tc.want+"\n" {
			t.Errorf("mask(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	block := "x:\n  SSH_PRIVATE_KEY: |\n    -----BEGIN KEY-----\n    abc\n\n  OTHER: 1\n"
	want := "x:\n  SSH_PRIVATE_KEY: |\n    ********\n    ********\n\n  OTHER: 1\n"
	if got := maskComposeSecrets(block); got != want {
		t.Errorf("block scalar: got %q", got)
	}
}

func TestComposeFileTruncated(t *testing.T) {
	f := newFixture(t)
	line := "# " + strings.Repeat("x", 97) + "\n" // 100 bytes
	big := strings.Repeat(line, 700) + "PASSWORD: tail-secret\n"
	f.file("/srv/big/compose.yaml", big)
	cf := f.env.composeFile("compose.yaml", "/srv/big", "")
	if !cf.Truncated || cf.Size != int64(len(big)) || cf.SHA256 != model.Hash([]byte(big)) ||
		len(cf.Content) != 655*100 || strings.Contains(cf.Content, "tail-secret") {
		t.Fatalf("truncated = %v size %d content %d", cf.Truncated, cf.Size, len(cf.Content))
	}
	if cf := f.env.composeFile("compose.yaml", "", ""); cf.Error == "" {
		t.Error("relative path without working dir read")
	}
}

// ctrTestCgroups lays out cgroup v2 files for the web and wp containers.
func ctrTestCgroups(f *fixture, webUsage, wpUsage int) {
	f.file("/sys/fs/cgroup/cgroup.controllers", "cpuset cpu io memory hugetlb pids rdma misc\n")
	web := "/sys/fs/cgroup/system.slice/docker-" + ctrTestWebID + ".scope"
	f.file("/proc/4242/cgroup", "0::/system.slice/docker-"+ctrTestWebID+".scope\n")
	f.file(web+"/cpu.stat", fmt.Sprintf("usage_usec %d\nuser_usec 1\nsystem_usec 1\nnr_periods 0\n", webUsage))
	f.file(web+"/memory.current", "104857600\n")
	f.file(web+"/memory.stat", "anon 50000000\nfile 40000000\ninactive_anon 1\nactive_anon 2\ninactive_file 20971520\nactive_file 3\n")
	f.file(web+"/memory.max", "536870912\n")
	// Podman runs the main process in a child cgroup of the container's.
	wp := "/sys/fs/cgroup/user.slice/user-4242.slice/user@4242.service/user.slice/libpod-" + ctrTestWPID + ".scope"
	f.file("/proc/5151/cgroup", "0::/user.slice/user-4242.slice/user@4242.service/user.slice/libpod-"+ctrTestWPID+".scope/container\n")
	f.file(wp+"/cpu.stat", fmt.Sprintf("usage_usec %d\n", wpUsage))
	f.file(wp+"/memory.current", "52428800\n")
	f.file(wp+"/memory.stat", "inactive_file 0\n")
	f.file(wp+"/memory.max", "max\n")
}

func TestContainerMetricsCgroupV2(t *testing.T) {
	h := newCtrTestHost(t)
	ctrTestCgroups(h.f, 5_000_000, 1_000_000)
	t0 := time.Date(2024, 9, 22, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	m := index(h.c.Sample(ctx, t0))
	want := map[string]float64{
		"container/mem_used/web-nginx-1":            104857600 - 20971520,
		"container/mem_limit/web-nginx-1":           536870912,
		"container/mem_used/podman:alice/blog_wp_1": 52428800,
	}
	if fmt.Sprint(m) != fmt.Sprint(want) {
		t.Fatalf("first sample = %v", m)
	}

	ctrTestCgroups(h.f, 14_000_000, 46_000_000)
	m = index(h.c.Sample(ctx, t0.Add(90*time.Second)))
	if m["container/cpu_pct/web-nginx-1"] != 10 || m["container/cpu_pct/podman:alice/blog_wp_1"] != 50 {
		t.Fatalf("second sample = %v", m)
	}
	if n := h.docker.count("/containers/" + ctrTestWebID + "/json"); n != 1 {
		t.Errorf("web inspected %d times; the cgroup path should be cached", n)
	}

	// web goes away; its state goes with it.
	h.docker.set("/containers/json?all=1", `[{"Id":"`+ctrTestDBID+`","Names":["/db"],"State":"exited"}]`)
	m = index(h.c.Sample(ctx, t0.Add(180*time.Second)))
	if _, ok := m["container/mem_used/web-nginx-1"]; ok {
		t.Error("vanished container sampled")
	}
	if _, ok := h.c.stats[ctrTestWebID]; ok {
		t.Error("vanished container's state kept")
	}
	if _, ok := h.c.stats[ctrTestWPID]; !ok || m["container/cpu_pct/podman:alice/blog_wp_1"] != 0 {
		t.Errorf("wp state lost: %v", m)
	}
}

func TestContainerMetricsCgroupV1(t *testing.T) {
	h := newCtrTestHost(t)
	h.f.file("/proc/meminfo", "MemTotal:       16384000 kB\nMemFree:         1000 kB\n")
	stats := func(totalNS int64, limit int64, inactiveKey string) string {
		return fmt.Sprintf(`{"read":"2024-09-22T12:00:00Z","cpu_stats":{"cpu_usage":{"total_usage":%d,"usage_in_kernelmode":0,"usage_in_usermode":0},"system_cpu_usage":1,"online_cpus":4},"memory_stats":{"usage":104857600,"max_usage":200000000,"stats":{"%s":10485760,"cache":20000000},"limit":%d}}`, totalNS, inactiveKey, limit)
	}
	const statsURI = "/stats?stream=false&one-shot=true"
	h.docker.set("/containers/"+ctrTestWebID+statsURI, stats(2e9, 16384000*1024, "total_inactive_file"))
	h.rootless.set("/containers/"+ctrTestWPID+statsURI, stats(1e9, 1<<30, "inactive_file"))
	t0 := time.Date(2024, 9, 22, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	m := index(h.c.Sample(ctx, t0))
	want := map[string]float64{
		"container/mem_used/web-nginx-1":             104857600 - 10485760,
		"container/mem_used/podman:alice/blog_wp_1":  104857600 - 10485760,
		"container/mem_limit/podman:alice/blog_wp_1": 1 << 30,
	}
	if fmt.Sprint(m) != fmt.Sprint(want) {
		t.Fatalf("first sample = %v", m)
	}
	h.docker.set("/containers/"+ctrTestWebID+statsURI, stats(2e9+4.5e9, 16384000*1024, "total_inactive_file"))
	m = index(h.c.Sample(ctx, t0.Add(90*time.Second)))
	if m["container/cpu_pct/web-nginx-1"] != 5 || m["container/cpu_pct/podman:alice/blog_wp_1"] != 0 {
		t.Fatalf("second sample = %v", m)
	}
}

func TestMaskLabelSecrets(t *testing.T) {
	in := map[string]string{
		"traefik.http.middlewares.a.basicauth.users":                          "admin:$apr1$xyz",
		"traefik.http.middlewares.b.forwardauth.address":                      "http://authentik:9000/outpost.goauthentik.io/auth/traefik",
		"org.opencontainers.image.authors":                                    "Jane",
		"com.example.api-key":                                                 "abc123",
		"com.example.token":                                                   "${TOKEN}",
		"com.example.db_password":                                             "********",
		"com.example.db":                                                      "postgres://app:hunter2@db:5432/app",
		"com.docker.compose.project":                                          "web",
		"traefik.http.routers.auth.rule":                                      "Host(`auth.example.com`)",
		"traefik.http.middlewares.token.headers.customrequestheaders.x-token": "abc",
	}
	got := maskLabelSecrets(in)
	want := map[string]string{
		"traefik.http.middlewares.a.basicauth.users":                          "********",
		"traefik.http.middlewares.b.forwardauth.address":                      "http://authentik:9000/outpost.goauthentik.io/auth/traefik",
		"org.opencontainers.image.authors":                                    "Jane",
		"com.example.api-key":                                                 "********",
		"com.example.token":                                                   "${TOKEN}",
		"com.example.db_password":                                             "********",
		"com.example.db":                                                      "postgres://app:********@db:5432/app",
		"com.docker.compose.project":                                          "web",
		"traefik.http.routers.auth.rule":                                      "Host(`auth.example.com`)",
		"traefik.http.middlewares.token.headers.customrequestheaders.x-token": "********",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if in["com.example.api-key"] != "abc123" {
		t.Error("the input map was changed")
	}
}

func TestComposeCapability(t *testing.T) {
	for _, tc := range []struct {
		files, cmds []string
		want        string
	}{
		{nil, nil, "pkg-pin"},
		// A Compose CLI without its engine is no use.
		{[]string{"/usr/libexec/docker/cli-plugins/docker-compose"}, nil, "pkg-pin"},
		{[]string{"/usr/libexec/docker/cli-plugins/docker-compose"}, []string{"docker"}, "docker,compose,compose-files,compose-roots,compose-start,compose-archive,compose-rootless,compose-retag,pkg-pin"},
		{nil, []string{"docker", "docker-compose"}, "docker,compose,compose-files,compose-roots,compose-start,compose-archive,compose-rootless,compose-retag,pkg-pin"},
		{nil, []string{"podman"}, "podman,pkg-pin"},
		{nil, []string{"podman", "podman-compose"}, "podman,compose,compose-files,compose-roots,compose-start,compose-archive,compose-rootless,compose-retag,pkg-pin"},
		{[]string{"/run/podman/podman.sock"}, []string{"podman-compose"}, "podman,compose,compose-files,compose-roots,compose-start,compose-archive,compose-rootless,compose-retag,pkg-pin"},
	} {
		f := newFixture(t)
		for _, p := range tc.files {
			f.file(p, "")
		}
		for _, c := range tc.cmds {
			f.cmds[c] = ""
		}
		if caps := strings.Join(f.env.Capabilities(), ","); caps != tc.want {
			t.Errorf("%v %v: caps = %s, want %s", tc.files, tc.cmds, caps, tc.want)
		}
	}
}

func TestStackImageIDAndTag(t *testing.T) {
	h := newCtrTestHost(t)
	ctx := context.Background()
	if caps := strings.Join(h.f.env.Capabilities(), ","); caps != "podman,docker,compose,compose-files,compose-roots,compose-start,compose-archive,compose-rootless,compose-retag,pkg-pin" {
		t.Errorf("caps = %s", caps)
	}

	st, err := h.c.Stack(ctx, "docker", "web")
	if err != nil {
		t.Fatal(err)
	}
	if st.Key() != "docker/web" || st.WorkingDir != "/srv/web" || st.CLI != "docker compose" || st.Socket != "/var/run/docker.sock" ||
		strings.Join(st.Services, ",") != "nginx" || st.User != "" || len(st.Containers) != 1 ||
		st.Containers[0].Name != "web-nginx-1" || st.Containers[0].Health != "healthy" {
		t.Fatalf("stack = %+v", st)
	}
	// The override file is missing, so the stack can't be driven.
	if !st.Orphaned || st.ConfigFiles[1].Error != "not found" {
		t.Errorf("files = %+v", st.ConfigFiles)
	}
	// Only the stack's containers are inspected.
	if h.docker.count("/containers/"+ctrTestDBID+"/json") != 0 {
		t.Error("inspected a container of no stack")
	}

	st, err = h.c.Stack(ctx, "podman:alice", "blog")
	if err != nil {
		t.Fatal(err)
	}
	if st.CLI != "podman compose" || st.Orphaned || st.User != "alice" || st.UID != "4242" || st.Home != "/home/alice" ||
		st.Socket != "/run/user/4242/podman/podman.sock" || len(st.Containers) != 1 || st.Containers[0].ComposeService != "wp" {
		t.Fatalf("rootless stack = %+v", st)
	}

	for _, tc := range []struct{ engine, project, err string }{
		{"docker", "nope", `no Compose stack "nope" on docker`},
		{"podman", "blog", "podman: GET /containers/json: 500 database is locked"},
		{"podman:bob", "blog", "no podman:bob engine on this host"},
	} {
		if _, err := h.c.Stack(ctx, tc.engine, tc.project); err == nil || err.Error() != tc.err {
			t.Errorf("%s/%s: %v", tc.engine, tc.project, err)
		}
	}

	h.docker.set("/images/nginx:1.27/json", `{"Id":"sha256:`+ctrTestImg1+`","RepoTags":["nginx:1.27"]}`)
	h.rootless.set("/images/docker.io/library/wordpress:6.6/json", `{"Id":"`+ctrTestImg3+`"}`)
	if id, err := h.c.ImageID(ctx, "docker", "nginx:1.27"); err != nil || id != "sha256:"+ctrTestImg1 {
		t.Errorf("image ID = %q, %v", id, err)
	}
	// Podman's bare IDs get "sha256:", as inventory reports them.
	if id, err := h.c.ImageID(ctx, "podman:alice", "docker.io/library/wordpress:6.6"); err != nil || id != "sha256:"+ctrTestImg3 {
		t.Errorf("podman image ID = %q, %v", id, err)
	}
	if id, err := h.c.ImageID(ctx, "docker", "nginx:9"); err != nil || id != "" {
		t.Errorf("missing image = %q, %v", id, err)
	}

	tag := "/images/sha256:" + ctrTestImg2 + "/tag?repo=nginx&tag=1.27"
	h.docker.set(tag, "201|")
	if err := h.c.Tag(ctx, "docker", "sha256:"+ctrTestImg2, "nginx:1.27"); err != nil || h.docker.count(tag) != 1 {
		t.Errorf("tag: %v (%d calls)", err, h.docker.count(tag))
	}
	if err := h.c.Tag(ctx, "docker", "sha256:"+ctrTestImg2, "nginx@sha256:d2eb"); err == nil || err.Error() != `"nginx@sha256:d2eb" can't be tagged` {
		t.Errorf("tag a digest: %v", err)
	}
	if err := h.c.Tag(ctx, "docker", "sha256:"+ctrTestImg1, "nginx:1.27"); !strings.Contains(fmt.Sprint(err), "404") {
		t.Errorf("tag an unknown image: %v", err)
	}
}

func TestStackRootlessUnknownUser(t *testing.T) {
	f := newFixture(t)
	f.file("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	fe := ctrTestServe(t, filepath.Join(f.env.Root, "/run/user/1001/podman/podman.sock"), true)
	fe.set("/containers/json?all=1", ctrTestWPList)
	fe.set("/containers/"+ctrTestWPID+"/json", ctrTestWPInspect)
	c := &ContainerCollector{Env: f.env}
	_, err := c.Stack(context.Background(), "podman:1001", "blog")
	if err == nil || err.Error() != "podman:1001: user 1001 (uid 1001) isn't in /etc/passwd" {
		t.Fatalf("err = %v", err)
	}
}
