// Package k8smanifest reads the Kubernetes manifests that k8s.deploy and
// k8s.edit apply (docs/agent.md §6.1). The server checks a manifest when a
// change is made and the cluster agent again before it applies one, with
// the same rules.
//
// Neither side carries a YAML library (docs/architecture.md §9). A manifest
// is split into its documents, and only each document's apiVersion, kind
// and metadata name and namespace are read, which must be plain block
// mappings at the top of the document. The document itself goes to the API
// server untouched, as a server-side apply patch, and the API server parses
// it in full.
package k8smanifest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	// MaxSize caps a manifest.
	MaxSize = 1 << 20
	// MaxObjects caps the objects in one manifest.
	MaxObjects = 100
)

// Resource is a kind a manifest may hold, and where the API serves it.
type Resource struct {
	APIVersion string // apps/v1
	Kind       string // Deployment
	Plural     string // deployments
	// Workload kinds roll out: the agent waits for them.
	Workload bool
}

// Resources are the kinds a manifest may hold: namespaced workloads and
// what goes with them. Secrets are never among them (Baseline doesn't read
// or write Secrets), nor are cluster-scoped kinds or RBAC.
var Resources = []Resource{
	{"apps/v1", "Deployment", "deployments", true},
	{"apps/v1", "StatefulSet", "statefulsets", true},
	{"apps/v1", "DaemonSet", "daemonsets", true},
	{"batch/v1", "CronJob", "cronjobs", false},
	{"batch/v1", "Job", "jobs", false},
	{"v1", "Service", "services", false},
	{"v1", "ConfigMap", "configmaps", false},
	{"v1", "PersistentVolumeClaim", "persistentvolumeclaims", false},
	{"v1", "ServiceAccount", "serviceaccounts", false},
	{"networking.k8s.io/v1", "Ingress", "ingresses", false},
	{"networking.k8s.io/v1", "NetworkPolicy", "networkpolicies", false},
	{"autoscaling/v2", "HorizontalPodAutoscaler", "horizontalpodautoscalers", false},
	{"policy/v1", "PodDisruptionBudget", "poddisruptionbudgets", false},
}

// Kinds lists the kinds a manifest may hold, for messages.
func Kinds() string {
	var ks []string
	for _, r := range Resources {
		ks = append(ks, r.Kind)
	}
	return strings.Join(ks, ", ")
}

func lookup(apiVersion, kind string) (Resource, bool) {
	for _, r := range Resources {
		if r.APIVersion == apiVersion && r.Kind == kind {
			return r, true
		}
	}
	return Resource{}, false
}

// Object is one document of a manifest.
type Object struct {
	Resource
	Namespace string
	Name      string
	// Doc is the document as written, without the separators around it.
	Doc []byte
}

// Key names the object in messages and results: "Deployment shop/web".
func (o Object) Key() string { return o.Kind + " " + o.Namespace + "/" + o.Name }

// Path is the object's API path.
func (o Object) Path() string {
	return CollectionPath(o.APIVersion, o.Namespace, o.Plural) + "/" + o.Name
}

// CollectionPath is where the API serves a namespaced resource.
func CollectionPath(apiVersion, namespace, plural string) string {
	prefix := "/apis/" + apiVersion
	if apiVersion == "v1" {
		prefix = "/api/v1"
	}
	return prefix + "/namespaces/" + namespace + "/" + plural
}

var (
	reLabel     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	reSubdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	// A top-level key, "kind: Deployment" or "metadata:".
	reKey = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_-]*)[ \t]*:(?:[ \t]+(.*))?$`)
)

// Parse reads a manifest. Objects that name no namespace go in
// namespace. Every object must be of one of the Resources, named, and
// appear once.
func Parse(manifest []byte, namespace string) ([]Object, error) {
	if len(manifest) > MaxSize {
		return nil, fmt.Errorf("the manifest is larger than %d KB", MaxSize>>10)
	}
	if !reLabel.MatchString(namespace) {
		return nil, fmt.Errorf("%q isn't a namespace", namespace)
	}
	docs, err := split(manifest)
	if err != nil {
		return nil, err
	}
	var out []Object
	seen := map[string]bool{}
	for i, doc := range docs {
		o, err := parseDoc(doc, namespace)
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", i+1, err)
		}
		if seen[o.Key()] {
			return nil, fmt.Errorf("document %d: %s appears twice", i+1, o.Key())
		}
		seen[o.Key()] = true
		out = append(out, o)
	}
	if len(out) == 0 {
		return nil, errors.New("the manifest holds no objects")
	}
	if len(out) > MaxObjects {
		return nil, fmt.Errorf("the manifest holds more than %d objects", MaxObjects)
	}
	return out, nil
}

// split cuts a manifest into its documents at "---" lines, leaving out the
// ones that hold only comments and blank lines.
func split(manifest []byte) ([][]byte, error) {
	var docs [][]byte
	var cur bytes.Buffer
	flush := func() {
		if !blank(cur.Bytes()) {
			docs = append(docs, bytes.Clone(cur.Bytes()))
		}
		cur.Reset()
	}
	sc := bufio.NewScanner(bytes.NewReader(manifest))
	sc.Buffer(make([]byte, 64<<10), MaxSize+1)
	for sc.Scan() {
		line := sc.Text()
		if strings.ContainsRune(line, 0) {
			return nil, errors.New("the manifest isn't text")
		}
		if isSeparator(line) {
			flush()
			continue
		}
		if strings.HasPrefix(line, "%") && cur.Len() == 0 {
			return nil, errors.New("YAML directives (%YAML, %TAG) aren't supported")
		}
		cur.WriteString(line)
		cur.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return docs, nil
}

func isSeparator(line string) bool {
	for _, sep := range []string{"---", "..."} {
		if rest, ok := strings.CutPrefix(line, sep); ok {
			rest = strings.TrimSpace(rest)
			if rest == "" || strings.HasPrefix(rest, "#") {
				return true
			}
		}
	}
	return false
}

func blank(doc []byte) bool {
	for _, line := range strings.Split(string(doc), "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "#") {
			return false
		}
	}
	return true
}

func parseDoc(doc []byte, namespace string) (Object, error) {
	var apiVersion, kind, name, ns string
	var err error
	if t := bytes.TrimSpace(doc); len(t) > 0 && t[0] == '{' {
		apiVersion, kind, name, ns, err = jsonHeader(t)
	} else {
		apiVersion, kind, name, ns, err = yamlHeader(string(doc))
	}
	if err != nil {
		return Object{}, err
	}
	if apiVersion == "" || kind == "" {
		return Object{}, errors.New("an object needs apiVersion and kind")
	}
	if kind == "List" || strings.HasSuffix(kind, "List") {
		return Object{}, errors.New("write each object as its own document rather than a List")
	}
	if kind == "Secret" {
		return Object{}, errors.New("Baseline doesn't apply Secrets; create them in the cluster and refer to them")
	}
	res, ok := lookup(apiVersion, kind)
	if !ok {
		for _, r := range Resources {
			if r.Kind == kind {
				return Object{}, fmt.Errorf("%s is %s here, not %s", kind, r.APIVersion, apiVersion)
			}
		}
		return Object{}, fmt.Errorf("Baseline doesn't apply %s %s; a manifest may hold %s", apiVersion, kind, Kinds())
	}
	if name == "" {
		return Object{}, fmt.Errorf("the %s has no metadata.name (generateName isn't supported)", kind)
	}
	if !reSubdomain.MatchString(name) {
		return Object{}, fmt.Errorf("%q isn't a %s name", name, kind)
	}
	if ns == "" {
		ns = namespace
	}
	if !reLabel.MatchString(ns) {
		return Object{}, fmt.Errorf("%q isn't a namespace", ns)
	}
	return Object{Resource: res, Namespace: ns, Name: name, Doc: doc}, nil
}

func jsonHeader(doc []byte) (apiVersion, kind, name, ns string, err error) {
	var h struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	if err := dec.Decode(&h); err != nil {
		return "", "", "", "", fmt.Errorf("JSON: %w", err)
	}
	if dec.More() {
		return "", "", "", "", errors.New("JSON: one object per document")
	}
	return h.APIVersion, h.Kind, h.Metadata.Name, h.Metadata.Namespace, nil
}

// yamlHeader reads apiVersion, kind and metadata's name and namespace from
// a block mapping. It refuses what it can't read for certain, rather than
// guess: those keys in flow style, with anchors, aliases or tags, or
// written twice.
func yamlHeader(doc string) (apiVersion, kind, name, ns string, err error) {
	lines := strings.Split(doc, "\n")
	seen := map[string]bool{}
	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], " \t\r")
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		if line[0] == '{' || line[0] == '-' || line[0] == '[' {
			return "", "", "", "", errors.New("the document isn't a YAML mapping of apiVersion, kind, metadata...")
		}
		m := reKey.FindStringSubmatch(line)
		if m == nil {
			continue // a quoted key, or a continuation the API server reads
		}
		key, val := m[1], m[2]
		switch key {
		case "apiVersion", "kind":
			if seen[key] {
				return "", "", "", "", fmt.Errorf("%s appears twice", key)
			}
			seen[key] = true
			v, err := scalar(val)
			if err != nil {
				return "", "", "", "", fmt.Errorf("%s: %w", key, err)
			}
			if key == "kind" {
				kind = v
			} else {
				apiVersion = v
			}
		case "metadata":
			if seen[key] {
				return "", "", "", "", errors.New("metadata appears twice")
			}
			seen[key] = true
			if v := stripComment(val); v != "" {
				return "", "", "", "", errors.New("write metadata as a block (name: on its own line), not in flow style")
			}
			var n int
			name, ns, n, err = metadata(lines[i+1:])
			if err != nil {
				return "", "", "", "", err
			}
			i += n
		}
	}
	return apiVersion, kind, name, ns, nil
}

// metadata reads name and namespace from the lines of metadata's block,
// and returns how many lines the block took.
func metadata(lines []string) (name, ns string, n int, err error) {
	indent := -1
	seen := map[string]bool{}
	for n = 0; n < len(lines); n++ {
		line := strings.TrimRight(lines[n], " \t\r")
		t := strings.TrimLeft(line, " ")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "\t") || strings.HasPrefix(line, "\t") {
			return "", "", 0, errors.New("metadata is indented with tabs")
		}
		in := len(line) - len(t)
		if in == 0 {
			break // the next top-level key
		}
		if indent < 0 {
			indent = in
		}
		if in < indent {
			return "", "", 0, errors.New("metadata's indentation is uneven")
		}
		if in > indent {
			continue // inside labels, annotations...
		}
		m := reKey.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		key := m[1]
		if key != "name" && key != "namespace" {
			continue
		}
		if seen[key] {
			return "", "", 0, fmt.Errorf("metadata.%s appears twice", key)
		}
		seen[key] = true
		v, err := scalar(m[2])
		if err != nil {
			return "", "", 0, fmt.Errorf("metadata.%s: %w", key, err)
		}
		if key == "name" {
			name = v
		} else {
			ns = v
		}
	}
	return name, ns, n, nil
}

// scalar reads a plain or quoted one-line scalar.
func scalar(v string) (string, error) {
	v = stripComment(v)
	switch {
	case v == "":
		return "", nil
	case strings.HasPrefix(v, `"`):
		var s string
		if err := json.Unmarshal([]byte(v), &s); err != nil {
			return "", fmt.Errorf("can't read %s", v)
		}
		return s, nil
	case strings.HasPrefix(v, "'"):
		if len(v) < 2 || !strings.HasSuffix(v, "'") {
			return "", fmt.Errorf("can't read %s", v)
		}
		return strings.ReplaceAll(v[1:len(v)-1], "''", "'"), nil
	case strings.ContainsAny(v[:1], "&*!|>{[@`%"):
		return "", fmt.Errorf("write it as a plain value, not %s", v)
	}
	return v, nil
}

// stripComment drops a trailing comment from an unquoted value.
func stripComment(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, `"`) || strings.HasPrefix(v, "'") {
		// A comment after a quoted value: cut after the closing quote.
		q := v[0]
		for i := 1; i < len(v); i++ {
			if v[i] == '\\' && q == '"' {
				i++
				continue
			}
			if v[i] == q {
				if q == '\'' && i+1 < len(v) && v[i+1] == '\'' {
					i++
					continue
				}
				return v[:i+1]
			}
		}
		return v
	}
	if strings.HasPrefix(v, "#") {
		return ""
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	}
	if i := strings.Index(v, "\t#"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
