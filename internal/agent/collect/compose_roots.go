package collect

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/jw6ventures/baseline/internal/action"
	"github.com/jw6ventures/baseline/internal/model"
)

// composeFileNames are the files Compose looks for in a project directory,
// in its order; the override is merged on top when there.
var composeFileNames = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

var composeOverrideNames = []string{"compose.override.yaml", "compose.override.yml",
	"docker-compose.override.yaml", "docker-compose.override.yml"}

// SetComposeRoots sets the directories to look for stacks that aren't
// running under (the server's Config). It reports whether they changed.
func (c *ContainerCollector) SetComposeRoots(roots []string) bool {
	var ok []string
	for _, r := range roots {
		if action.CheckComposeRoot(r) == nil && !slices.Contains(ok, r) {
			ok = append(ok, r)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if slices.Equal(c.roots, ok) {
		return false
	}
	c.roots = ok
	return true
}

func (c *ContainerCollector) composeRoots() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.roots
}

// rootEngine is the engine a stack found on disk is put under: its Compose
// file doesn't say. The host's only rootful engine, or Docker when it has
// both; "" when neither can be read.
func rootEngine(engines []model.ContainerEngine) model.ContainerEngine {
	var found []model.ContainerEngine
	for _, e := range engines {
		if e.Error == "" && (e.Name == "docker" || e.Name == "podman") {
			found = append(found, e)
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Name < found[j].Name }) // docker first
	if len(found) == 0 {
		return model.ContainerEngine{}
	}
	return found[0]
}

// stoppedStacks are the stacks in directories under the Compose roots that
// nothing runs from: no stack runs from that directory, and none of that
// name on the engine. A directory is a stack when it holds a Compose file
// and its name is a project name, which is how Baseline deploys them. A
// directory owned by a user with a rootless Podman engine is that
// engine's stack; any other is the rootful engine's (rootEngine).
func (e *Env) stoppedStacks(roots []string, running []model.ComposeStack, engines []model.ContainerEngine) []model.ComposeStack {
	rootful := rootEngine(engines)
	owners := rootlessEngines(engines)
	if (rootful.Name == "" && len(owners) == 0) || len(roots) == 0 {
		return nil
	}
	var out []model.ComposeStack
	for _, root := range roots {
		names := e.ReadDir(root)
		sort.Strings(names)
		for _, name := range names {
			dir := filepath.Join(root, name)
			if !action.ValidProject(name) {
				continue
			}
			fi, err := os.Lstat(e.path(dir))
			if err != nil || !fi.IsDir() {
				continue
			}
			eng := rootful
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				if o, ok := owners[strconv.FormatUint(uint64(st.Uid), 10)]; ok {
					eng = o
				}
			}
			if eng.Name == "" || slices.ContainsFunc(running, func(st model.ComposeStack) bool {
				return st.WorkingDir == dir || (st.Engine == eng.Name && st.Project == name)
			}) || slices.ContainsFunc(out, func(st model.ComposeStack) bool {
				return st.Engine == eng.Name && st.Project == name
			}) {
				continue
			}
			file := firstFile(e, dir, composeFileNames)
			if file == "" {
				continue
			}
			st := model.ComposeStack{Engine: eng.Name, Project: name, WorkingDir: dir, CLI: e.composeCLI(eng.Kind), Stopped: true}
			uid := engineUID(eng)
			st.ConfigFiles = []model.ComposeFile{e.composeFile(file, dir, uid)}
			if o := firstFile(e, dir, composeOverrideNames); o != "" {
				st.ConfigFiles = append(st.ConfigFiles, e.composeFile(o, dir, uid))
			}
			st.Services = []string{}
			for _, f := range st.ConfigFiles {
				for _, s := range composeServices(f.Content) {
					if !slices.Contains(st.Services, s) {
						st.Services = append(st.Services, s)
					}
				}
				if f.Error != "" {
					st.Orphaned = true
				}
			}
			sort.Strings(st.Services)
			out = append(out, st)
		}
	}
	return out
}

// rootlessEngines are the rootless Podman engines that can be read, by
// their user's uid (from the socket, /run/user/<uid>/podman/podman.sock).
func rootlessEngines(engines []model.ContainerEngine) map[string]model.ContainerEngine {
	m := map[string]model.ContainerEngine{}
	for _, e := range engines {
		if uid := engineUID(e); uid != "" && e.Error == "" {
			m[uid] = e
		}
	}
	return m
}

// engineUID is the uid of a rootless Podman engine's user, "" for a
// rootful engine.
func engineUID(e model.ContainerEngine) string {
	if !strings.HasPrefix(e.Name, "podman:") {
		return ""
	}
	if uid, ok := strings.CutPrefix(e.Socket, "/run/user/"); ok {
		if uid, _, ok = strings.Cut(uid, "/"); ok && uid != "0" {
			return uid
		}
	}
	return ""
}

// firstFile is the first of these files in dir, as a host path, or "".
func firstFile(e *Env, dir string, names []string) string {
	for _, n := range names {
		p := filepath.Join(dir, n)
		if fi, err := os.Stat(e.path(p)); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// composeServices are the keys of a Compose file's top-level services
// mapping, read line by line: enough to list them, without a YAML parser.
func composeServices(content string) []string {
	var out []string
	in, indent := false, -1
	for _, line := range strings.Split(content, "\n") {
		body := strings.TrimRight(line, " \t\r")
		trimmed := strings.TrimSpace(body)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		ind := composeIndent(body)
		if ind == 0 {
			in = strings.HasPrefix(body, "services:") && strings.TrimSpace(stripYAMLComment(strings.TrimPrefix(body, "services:"))) == ""
			indent = -1
			continue
		}
		if !in {
			continue
		}
		if indent < 0 {
			indent = ind
		}
		if ind != indent {
			continue
		}
		key, rest, ok := strings.Cut(trimmed, ":")
		if !ok || (rest != "" && rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		if key = strings.Trim(key, `"'`); key != "" {
			out = append(out, key)
		}
	}
	return out
}
