package container

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serve runs handler on a unix socket in a temp dir and returns its path.
func serve(t *testing.T, handler http.Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "engine.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// canned serves fixed bodies by request URI, answering anything else with
// the engine's 404 document.
func canned(hdr map[string]string, bodies map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, ok := bodies[r.URL.RequestURI()]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"page not found"}`))
			return
		}
		if code, rest, ok := strings.Cut(body, "|"); ok && len(code) == 3 {
			var n int
			for _, c := range code {
				n = n*10 + int(c-'0')
			}
			w.WriteHeader(n)
			body = rest
		}
		w.Write([]byte(body))
	})
}

const dockerVersion = `{"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine","Version":"27.3.1","Details":{"ApiVersion":"1.47","Arch":"amd64","BuildTime":"2024-09-20T11:41:11.000000000+00:00","Experimental":"false","GitCommit":"41ca978","GoVersion":"go1.22.7","KernelVersion":"6.8.0-45-generic","MinAPIVersion":"1.24","Os":"linux"}},{"Name":"containerd","Version":"1.7.22","Details":{"GitCommit":"7f7fdf5fed64eb6a7caf99b3e12efcf9d60e311c"}},{"Name":"runc","Version":"1.1.14","Details":{"GitCommit":"v1.1.14-0-g2c9f560"}},{"Name":"docker-init","Version":"0.19.0","Details":{"GitCommit":"de40ad0"}}],"Version":"27.3.1","ApiVersion":"1.47","MinAPIVersion":"1.24","GitCommit":"41ca978","GoVersion":"go1.22.7","Os":"linux","Arch":"amd64","KernelVersion":"6.8.0-45-generic","BuildTime":"2024-09-20T11:41:11.000000000+00:00"}`

const dockerList = `[{"Id":"8dfafdbc3a40","Names":["/web-nginx-1"],"Image":"nginx:1.27","ImageID":"sha256:3b25b682ea82b2db3cc4fd48db818be788ee3f902ac7378090cf2624ec2442df","Command":"/docker-entrypoint.sh nginx -g 'daemon off;'","Created":1727000000,"Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"}],"Labels":{"com.docker.compose.project":"web"},"State":"running","Status":"Up 2 hours","HostConfig":{"NetworkMode":"web_default"},"NetworkSettings":{"Networks":{"web_default":{"NetworkID":"7ea29fc1412292a2d7bba362f9253545fecdfa8ce9a6e37dd10ba8bee7129812"}}},"Mounts":[]}]`

const dockerInspect = `{"Id":"8dfafdbc3a40","Created":"2024-09-22T10:13:20.123456789Z","Path":"/docker-entrypoint.sh","Args":["nginx","-g","daemon off;"],
"State":{"Status":"running","Running":true,"Paused":false,"Restarting":false,"OOMKilled":false,"Dead":false,"Pid":4242,"ExitCode":0,"Error":"","StartedAt":"2024-09-22T10:13:21.5Z","FinishedAt":"0001-01-01T00:00:00Z","Health":{"Status":"healthy","FailingStreak":0,"Log":[]}},
"Image":"sha256:3b25b682ea82b2db3cc4fd48db818be788ee3f902ac7378090cf2624ec2442df","Name":"/web-nginx-1","RestartCount":2,
"HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"","HostPort":"8080"}]},"RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0}},
"Mounts":[{"Type":"volume","Name":"web_data","Source":"/var/lib/docker/volumes/web_data/_data","Destination":"/usr/share/nginx/html","Driver":"local","Mode":"z","RW":true,"Propagation":""}],
"Config":{"Hostname":"8dfafdbc3a40","Env":["NGINX_VERSION=1.27.2","SECRET_TOKEN=hunter2"],"Cmd":["nginx","-g","daemon off;"],"Image":"nginx:1.27","Labels":{"com.docker.compose.project":"web"}},
"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"},{"HostIp":"::","HostPort":"8080"}],"443/tcp":null},"Networks":{"web_default":{"IPAddress":"172.18.0.2"}}}}`

const dockerImages = `[{"Containers":-1,"Created":1726600000,"Id":"sha256:3b25b682ea82b2db3cc4fd48db818be788ee3f902ac7378090cf2624ec2442df","Labels":{"maintainer":"NGINX Docker Maintainers <docker-maint@nginx.com>"},"ParentId":"","RepoDigests":["nginx@sha256:d2eb56950b84efe34f966a2b92efb1a1a2ea53e7e93b94cdf45a27cf3cd47fc0"],"RepoTags":["nginx:1.27"],"SharedSize":-1,"Size":191670474}]`

const dockerStats = `{"read":"2024-09-22T12:00:00.000000000Z","preread":"0001-01-01T00:00:00Z","pids_stats":{"current":5},"cpu_stats":{"cpu_usage":{"total_usage":123456789000,"usage_in_kernelmode":1000,"usage_in_usermode":2000},"system_cpu_usage":9999999999,"online_cpus":4},"precpu_stats":{"cpu_usage":{"total_usage":0}},"memory_stats":{"usage":73400320,"stats":{"total_inactive_file":4194304,"cache":8388608},"limit":2147483648},"name":"/web-nginx-1","id":"8dfafdbc3a40"}`

func TestDocker(t *testing.T) {
	sock := serve(t, canned(nil, map[string]string{
		"/version":                            dockerVersion,
		"/v1.47/containers/json?all=1":        dockerList,
		"/v1.47/containers/8dfafdbc3a40/json": dockerInspect,
		"/v1.47/containers/gone/json":         `404|{"message":"No such container: gone"}`,
		"/v1.47/images/json":                  `500|{"message":"layer does not exist"}`,
		"/v1.47/containers/8dfafdbc3a40/stats?stream=false&one-shot=true": dockerStats,
	}))
	c := New(sock)
	defer c.Close()
	ctx := context.Background()

	// Before version negotiation, requests aren't versioned.
	if _, err := c.ListContainers(ctx); err == nil || !IsNotFound(err) {
		t.Fatalf("unversioned list: %v", err)
	}
	v, err := c.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != "27.3.1" || v.APIVersion != "1.47" || v.Podman {
		t.Fatalf("version = %+v", v)
	}
	list, err := c.ListContainers(ctx)
	if err != nil || len(list) != 1 || list[0].Name() != "web-nginx-1" || list[0].State != "running" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	in, err := c.Inspect(ctx, "8dfafdbc3a40")
	if err != nil {
		t.Fatal(err)
	}
	if in.Config.Image != "nginx:1.27" || in.State.Pid != 4242 || in.HealthStatus() != "healthy" ||
		in.HostConfig.RestartPolicy.Name != "unless-stopped" || in.RestartCount != 2 ||
		len(in.NetworkSettings.Ports["80/tcp"]) != 2 || in.NetworkSettings.Ports["443/tcp"] != nil ||
		len(in.Mounts) != 1 || in.Mounts[0].Name != "web_data" {
		t.Fatalf("inspect = %+v", in)
	}
	_, err = c.Inspect(ctx, "gone")
	if !IsNotFound(err) || err.Error() != "docker: GET /containers/gone/json: 404 No such container: gone" {
		t.Fatalf("inspect gone: %v", err)
	}
	_, err = c.ListImages(ctx)
	if err == nil || err.Error() != "docker: GET /images/json: 500 layer does not exist" {
		t.Fatalf("images: %v", err)
	}
	st, err := c.Stats(ctx, "8dfafdbc3a40")
	if err != nil || st.CPUStats.CPUUsage.TotalUsage != 123456789000 || st.MemoryStats.Usage != 73400320 ||
		st.MemoryStats.Stats["total_inactive_file"] != 4194304 || st.MemoryStats.Limit != 2147483648 {
		t.Fatalf("stats = %+v, %v", st, err)
	}
	if _, err := c.PodNames(ctx); err == nil {
		t.Fatal("pod names from docker")
	}
}

const podmanVersion = `{"Platform":{"Name":"linux/amd64/fedora-40"},"Components":[{"Name":"Podman Engine","Version":"5.2.2","Details":{"APIVersion":"5.2.2","Arch":"amd64","BuildTime":"2024-08-21T00:00:00Z","Experimental":"false","GitCommit":"","GoVersion":"go1.22.6","KernelVersion":"6.10.6-200.fc40.x86_64","MinAPIVersion":"4.0.0","Os":"linux"}},{"Name":"Conmon","Version":"conmon version 2.1.10, commit: ","Details":{"Package":"conmon-2.1.10-1.fc40.x86_64"}},{"Name":"OCI Runtime (crun)","Version":"crun version 1.15","Details":{"Package":"crun-1.15-1.fc40.x86_64"}}],"Version":"5.2.2","ApiVersion":"1.41","MinAPIVersion":"1.24","GitCommit":"","GoVersion":"go1.22.6","Os":"linux","Arch":"amd64","KernelVersion":"6.10.6-200.fc40.x86_64","BuildTime":"2024-08-21T00:00:00+00:00"}`

const podmanLibpodList = `[{"AutoRemove":false,"Command":["sleep","inf"],"Created":"2024-09-20T08:00:00.000000000Z","CreatedAt":"","Exited":false,"ExitedAt":-62135596800,"ExitCode":0,"Id":"a1b2c3","Image":"docker.io/library/alpine:3.20","ImageID":"91ef0af61f39ece4d6710e465df5ed6ca12112358344fd51ae6a3b886634148b","IsInfra":false,"Labels":null,"Mounts":[],"Names":["app-worker"],"Namespaces":{},"Networks":[],"Pid":5151,"Pod":"0c9f9e1a","PodName":"app","Ports":null,"Size":null,"StartedAt":1726819200,"State":"running","Status":""},{"Id":"d4e5f6","Names":["solo"],"Pod":"","PodName":"","State":"exited"}]`

func TestPodman(t *testing.T) {
	sock := serve(t, canned(map[string]string{"Libpod-Api-Version": "5.2.2", "Api-Version": "1.41"}, map[string]string{
		"/version":                                podmanVersion,
		"/v1.41/containers/json?all=1":            `[{"Id":"a1b2c3","Names":["/app-worker"],"Image":"docker.io/library/alpine:3.20","ImageID":"sha256:91ef0af61f39","State":"running","Labels":{}}]`,
		"/v5.2.2/libpod/containers/json?all=true": podmanLibpodList,
	}))
	c := New(sock)
	ctx := context.Background()
	v, err := c.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Podman || v.Version != "5.2.2" || v.APIVersion != "1.41" || v.LibpodAPIVersion != "5.2.2" {
		t.Fatalf("version = %+v", v)
	}
	list, err := c.ListContainers(ctx)
	if err != nil || len(list) != 1 || list[0].Name() != "app-worker" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	pods, err := c.PodNames(ctx)
	if err != nil || len(pods) != 1 || pods["a1b2c3"] != "app" {
		t.Fatalf("pods = %v, %v", pods, err)
	}
	if _, err := c.ListImages(ctx); err == nil || !strings.HasPrefix(err.Error(), "podman: GET /images/json: 404") {
		t.Fatalf("images: %v", err)
	}
}

func TestPodmanByComponentsOnly(t *testing.T) {
	// A podman-docker socket seen through a proxy that drops headers is
	// still recognized from /version's components.
	sock := serve(t, canned(nil, map[string]string{"/version": podmanVersion}))
	v, err := New(sock).Version(context.Background())
	if err != nil || !v.Podman || v.LibpodAPIVersion != "5.2.2" {
		t.Fatalf("version = %+v, %v", v, err)
	}
}

func TestUnreachable(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "missing.sock"))
	_, err := c.Version(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "docker: GET /version: dial unix ") {
		t.Fatalf("err = %v", err)
	}
}

func TestBadJSONAndTimeout(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ApiVersion":"1.45"}`)) })
	mux.HandleFunc("/v1.45/images/json", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"not":"a list"}`)) })
	mux.HandleFunc("/v1.45/containers/json", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	})
	c := New(serve(t, mux))
	ctx := context.Background()
	if _, err := c.Version(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListImages(ctx); err == nil || !strings.HasPrefix(err.Error(), "docker: GET /images/json: json: ") {
		t.Fatalf("images: %v", err)
	}
	tctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := c.ListContainers(tctx); err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("list: %v", err)
	}
}

func TestImagesInspectAndTag(t *testing.T) {
	type call struct{ method, uri string }
	var calls []call
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, call{r.Method, r.URL.RequestURI()})
		switch uri := r.URL.RequestURI(); {
		case uri == "/version":
			w.Write([]byte(dockerVersion))
		case r.Method == http.MethodGet && uri == "/v1.47/images/ghcr.io/acme/app:2.1/json":
			w.Write([]byte(`{"Id":"sha256:3b25b682ea82","RepoTags":["ghcr.io/acme/app:2.1"],"RepoDigests":["ghcr.io/acme/app@sha256:d2eb"],"Config":{"Env":["SECRET=x"]}}`))
		case r.Method == http.MethodPost && uri == "/v1.47/images/sha256:3b25b682ea82/tag?repo=registry.lan%3A5000%2Fapp&tag=1.0":
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"No such image: x"}`))
		}
	})
	c := New(serve(t, mux))
	ctx := context.Background()
	if _, err := c.Version(ctx); err != nil {
		t.Fatal(err)
	}
	im, err := c.InspectImage(ctx, "ghcr.io/acme/app:2.1")
	if err != nil || im.ID != "sha256:3b25b682ea82" || len(im.RepoTags) != 1 || len(im.RepoDigests) != 1 {
		t.Fatalf("inspect = %+v, %v", im, err)
	}
	if _, err := c.InspectImage(ctx, "nginx:9"); !IsNotFound(err) || err.Error() != "docker: GET /images/nginx:9/json: 404 No such image: x" {
		t.Fatalf("inspect missing: %v", err)
	}
	if err := c.Tag(ctx, "sha256:3b25b682ea82", "registry.lan:5000/app", "1.0"); err != nil {
		t.Fatal(err)
	}
	if err := c.Tag(ctx, "sha256:gone", "app", "1.0"); !IsNotFound(err) || !strings.HasPrefix(err.Error(), "docker: POST /images/sha256:gone/tag: 404") {
		t.Fatalf("tag missing: %v", err)
	}
	if calls[3].method != http.MethodPost {
		t.Errorf("calls = %v", calls)
	}
}

func TestSplitRef(t *testing.T) {
	for _, tc := range []struct {
		ref, repo, tag string
		ok             bool
	}{
		{"nginx:1.27", "nginx", "1.27", true},
		{"nginx", "nginx", "latest", true},
		{"docker.io/library/wordpress:6.6", "docker.io/library/wordpress", "6.6", true},
		{"registry.lan:5000/app", "registry.lan:5000/app", "latest", true},
		{"registry.lan:5000/app:v2", "registry.lan:5000/app", "v2", true},
		{"nginx@sha256:d2eb", "", "", false},
		{"nginx:1.27@sha256:d2eb", "", "", false},
		{"nginx:", "nginx", "", false},
		{"", "", "", false},
	} {
		repo, tag, ok := SplitRef(tc.ref)
		if repo != tc.repo || tag != tc.tag || ok != tc.ok {
			t.Errorf("%q = %q %q %v, want %q %q %v", tc.ref, repo, tag, ok, tc.repo, tc.tag, tc.ok)
		}
	}
}
