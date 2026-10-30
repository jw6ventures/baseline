package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/jw6ventures/baseline/internal/model"
)

// composeMaxContent caps a Compose file's content in the section; the hash
// still covers the whole file.
const composeMaxContent = 64 << 10

// composeStacks groups containers into Compose projects by their labels,
// which podman-compose sets the same way as Docker Compose (docs/agent.md
// §3.2), and reads each project's config files.
func (e *Env) composeStacks(ctrs []model.Container, engines []model.ContainerEngine) []model.ComposeStack {
	kinds, uids := map[string]string{}, map[string]string{}
	for _, eng := range engines {
		kinds[eng.Name], uids[eng.Name] = eng.Kind, engineUID(eng)
	}
	type key struct{ engine, project string }
	byKey := map[key]*model.ComposeStack{}
	files := map[key]string{}
	services := map[key]map[string]bool{}
	var keys []key
	for _, c := range ctrs {
		if c.ComposeProject == "" {
			continue
		}
		k := key{c.Engine, c.ComposeProject}
		st := byKey[k]
		if st == nil {
			st = &model.ComposeStack{Engine: c.Engine, Project: c.ComposeProject}
			byKey[k], services[k] = st, map[string]bool{}
			keys = append(keys, k)
		}
		// Containers come sorted, so the first one's labels win the same
		// way every time.
		if st.WorkingDir == "" {
			st.WorkingDir = c.Labels["com.docker.compose.project.working_dir"]
		}
		if files[k] == "" {
			files[k] = c.Labels["com.docker.compose.project.config_files"]
		}
		if c.ComposeService != "" {
			services[k][c.ComposeService] = true
		}
	}

	clis := map[string]string{}
	out := []model.ComposeStack{}
	for _, k := range keys {
		st := byKey[k]
		st.Services = []string{}
		for s := range services[k] {
			st.Services = append(st.Services, s)
		}
		sort.Strings(st.Services)
		kind := kinds[k.engine]
		if _, ok := clis[kind]; !ok {
			clis[kind] = e.composeCLI(kind)
		}
		st.CLI = clis[kind]
		for _, p := range strings.Split(files[k], ",") {
			if p = strings.TrimSpace(p); p != "" {
				st.ConfigFiles = append(st.ConfigFiles, e.composeFile(p, st.WorkingDir, uids[k.engine]))
			}
		}
		st.Orphaned = len(st.ConfigFiles) == 0
		for _, f := range st.ConfigFiles {
			if f.Error != "" {
				st.Orphaned = true
			}
		}
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Engine != out[j].Engine {
			return out[i].Engine < out[j].Engine
		}
		return out[i].Project < out[j].Project
	})
	return out
}

// composeCLI is how stacks on an engine of this kind can be driven. It only
// looks for files, so it is cheap enough to run with every collection.
func (e *Env) composeCLI(kind string) string {
	switch kind {
	case "docker":
		for _, dir := range []string{"/usr/libexec/docker/cli-plugins", "/usr/lib/docker/cli-plugins",
			"/usr/local/lib/docker/cli-plugins", "/usr/local/libexec/docker/cli-plugins"} {
			if e.Exists(dir + "/docker-compose") {
				return "docker compose"
			}
		}
		if e.Has("docker-compose") {
			return "docker-compose"
		}
	case "podman":
		// "podman compose" wraps whichever of the two providers is installed.
		if e.Has("podman") && (e.Has("docker-compose") || e.Has("podman-compose")) {
			return "podman compose"
		}
		if e.Has("podman-compose") {
			return "podman-compose"
		}
	}
	return ""
}

// composeFile reads one config file: its hash and size, and its content
// capped and with secret values masked. A rootless Podman stack's user
// (uid) names its files in the labels they set, so only files that user
// owns, or anyone may read, are read: the agent reads as root.
func (e *Env) composeFile(p, workingDir, uid string) model.ComposeFile {
	if !filepath.IsAbs(p) {
		if workingDir == "" {
			return model.ComposeFile{Path: p, Error: "relative path without a working directory"}
		}
		p = filepath.Join(workingDir, p)
	}
	cf := model.ComposeFile{Path: p}
	// Non-blocking, so that a FIFO in its place doesn't hang the collection.
	f, err := os.OpenFile(e.path(p), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err == nil {
		defer f.Close()
		var fi os.FileInfo
		switch fi, err = f.Stat(); {
		case err != nil:
		case fi.IsDir():
			err = errors.New("is a directory")
		case !fi.Mode().IsRegular():
			err = errors.New("isn't a plain file")
		case uid != "" && !ownedOrPublic(fi, uid):
			err = errors.New("isn't the engine user's file")
		}
	}
	if err != nil {
		cf.Error = composeFileError(err)
		return cf
	}
	h := sha256.New()
	head := &composeHead{max: composeMaxContent + 1}
	n, err := io.Copy(io.MultiWriter(h, head), f)
	if err != nil {
		cf.Error = composeFileError(err)
		return cf
	}
	cf.Size, cf.SHA256 = n, hex.EncodeToString(h.Sum(nil))
	content := head.buf
	if len(content) > composeMaxContent {
		// Cut at a line end so no line is masked half-read.
		content = content[:composeMaxContent]
		if i := strings.LastIndexByte(string(content), '\n'); i >= 0 {
			content = content[:i+1]
		}
		cf.Truncated = true
	}
	cf.Content = maskComposeSecrets(strings.ToValidUTF8(string(content), "�"))
	return cf
}

// ownedOrPublic reports whether uid owns the file or anyone may read it.
func ownedOrPublic(fi os.FileInfo, uid string) bool {
	if fi.Mode().Perm()&0o004 != 0 {
		return true
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && strconv.FormatUint(uint64(st.Uid), 10) == uid
}

// composeFileError keeps the reason, not the full path (which tests and fixtures
// prefix with their root).
func composeFileError(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "not found"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}

// composeHead keeps the first max bytes written to it.
type composeHead struct {
	buf []byte
	max int
}

func (w *composeHead) Write(p []byte) (int, error) {
	if room := w.max - len(w.buf); room > 0 {
		w.buf = append(w.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

var (
	// composeSecretKey matches keys whose values look like secrets.
	composeSecretKey = regexp.MustCompile(`(?i)pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|auth`)
	// "KEY: value", "- KEY: value", also commented out.
	composeYAMLPair = regexp.MustCompile(`^(\s*(?:#\s*)?(?:-\s+)?)(["']?)([\w.-]+)(["']?\s*:)(\s*)(.*)$`)
	// "KEY=value", "- KEY=value", `- "KEY=value"`.
	composeEnvPair = regexp.MustCompile(`^(\s*(?:#\s*)?(?:-\s*)?)(["']?)([\w.-]+)=(.*)$`)
	// A value that only refers to a variable: $VAR, ${VAR}, ${VAR:?error}.
	// A default (${VAR:-x}) is a literal value and is masked.
	composeVarRef = regexp.MustCompile(`^\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*(?::?\?[^}]*)?\})$`)
	// A YAML block scalar indicator: the value is on the lines below.
	composeBlock = regexp.MustCompile(`^[|>][+-]?[0-9]?\s*(#.*)?$`)
	// The password in a URL's userinfo (DATABASE_URL=postgres://u:pw@db).
	composeURLPassword = regexp.MustCompile(`(\w://[^\s:/@'"]*:)([^\s@/'"]+)@`)
)

const composeMask = "********"

// maskComposeSecrets replaces the values of secret-looking keys, in YAML
// mappings and in KEY=value environment entries, and passwords in URLs.
// Empty values and values that only reference a variable are left alone:
// they hold nothing.
func maskComposeSecrets(content string) string {
	lines := strings.SplitAfter(content, "\n")
	blockIndent := -1 // masking a block scalar's lines indented past this
	for i, line := range lines {
		body := strings.TrimRight(line, "\r\n")
		eol := line[len(body):]
		if blockIndent >= 0 {
			if strings.TrimSpace(body) == "" {
				continue
			}
			if composeIndent(body) > blockIndent {
				lines[i] = strings.Repeat(" ", composeIndent(body)) + composeMask + eol
				continue
			}
			blockIndent = -1
		}
		if m := composeYAMLPair.FindStringSubmatch(body); m != nil && composeSecretName(m[3]) {
			value := m[6]
			if composeBlock.MatchString(value) {
				blockIndent = composeIndent(body)
				continue
			}
			if !keepComposeValue(stripYAMLComment(value)) {
				lines[i] = m[1] + m[2] + m[3] + m[4] + m[5] + composeMask + eol
			}
			continue
		}
		if m := composeEnvPair.FindStringSubmatch(body); m != nil && composeSecretName(m[3]) {
			value, quote := m[4], m[2]
			if quote != "" {
				value = strings.TrimSuffix(strings.TrimSpace(value), quote)
			}
			if !keepComposeValue(value) {
				lines[i] = m[1] + quote + m[3] + "=" + composeMask + quote + eol
				continue
			}
		}
		lines[i] = composeURLPassword.ReplaceAllStringFunc(lines[i], func(u string) string {
			m := composeURLPassword.FindStringSubmatch(u)
			if composeVarRef.MatchString(m[2]) {
				return u
			}
			return m[1] + composeMask + "@"
		})
	}
	return strings.Join(lines, "")
}

// composeSecretName reports whether a key names a secret. In a Traefik
// label (traefik.<proto>.<routers|services|middlewares>.<name>...) the
// router's, service's or middleware's name is left out: a router named
// "authentik" doesn't make its rule a secret.
func composeSecretName(key string) bool {
	if f := strings.Split(key, "."); len(f) > 4 && strings.EqualFold(f[0], "traefik") {
		key = strings.Join(append(f[:3:3], f[4:]...), ".")
	}
	return composeSecretKey.MatchString(key)
}

// keepComposeValue is true for values that hold no secret.
func keepComposeValue(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	return v == "" || composeVarRef.MatchString(v)
}

// stripYAMLComment drops a trailing " # comment" outside quotes.
func stripYAMLComment(v string) string {
	if v != "" && (v[0] == '"' || v[0] == '\'') {
		if j := strings.IndexByte(v[1:], v[0]); j >= 0 {
			return v[:j+2]
		}
		return v
	}
	if j := strings.Index(v, " #"); j >= 0 {
		return v[:j]
	}
	if strings.HasPrefix(v, "#") {
		return ""
	}
	return v
}

func composeIndent(s string) int { return len(s) - len(strings.TrimLeft(s, " \t")) }
