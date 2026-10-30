// Package registry is a small OCI distribution (Docker Registry v2) client
// and the semver advisory logic built on it (docs/agent.md §3.3). The server
// uses it to spot digest drift, where a tag now points at a newer image than
// the one a container runs, and newer tags allowed by a container's rule.
// It is in-house because it only needs manifest HEAD/GET and tag listing
// (docs/architecture.md §9).
package registry

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Ref is a parsed image reference.
type Ref struct {
	Registry   string // "docker.io", "ghcr.io", "registry.example:5000"
	Repository string // "library/nginx", "linuxserver/plex"
	Tag        string // "" when Digest is set and no tag was given
	Digest     string // "sha256:..." when the ref pins one
}

// The grammar is Docker's distribution/reference, so a ref Docker accepts
// parses here the same way.
var (
	componentRe = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	domainRe    = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*|\[[a-fA-F0-9:]+\])(?::[0-9]+)?$`)
	tagRe       = regexp.MustCompile(`^\w[\w.-]{0,127}$`)
	digestRe    = regexp.MustCompile(`^[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[a-zA-Z0-9=_-]{32,}$`)
	hexRe       = regexp.MustCompile(`^[a-f0-9]+$`)
)

// maxNameLen is Docker's limit on registry plus repository.
const maxNameLen = 255

// ParseRef parses an image reference with Docker's normalization: no
// registry means docker.io, single-component Docker Hub names get
// "library/", and a missing tag means "latest" unless a digest is given.
func ParseRef(s string) (Ref, error) {
	bad := func(why string) (Ref, error) {
		return Ref{}, fmt.Errorf("invalid image reference %q: %s", s, why)
	}
	if s == "" {
		return Ref{}, errors.New("empty image reference")
	}
	// An image ID is what `docker ps` shows for a container whose image was
	// untagged; it names no repository to ask.
	if len(s) == 64 && hexRe.MatchString(s) || strings.HasPrefix(s, "sha256:") && !strings.Contains(s, "/") {
		return bad("an image ID, not a repository")
	}
	var r Ref
	name := s
	if n, d, ok := strings.Cut(s, "@"); ok {
		if !validDigest(d) {
			return bad("malformed digest")
		}
		name, r.Digest = n, d
	}
	if i := strings.LastIndexByte(name, ':'); i >= 0 && !strings.Contains(name[i+1:], "/") {
		name, r.Tag = name[:i], name[i+1:]
		if !tagRe.MatchString(r.Tag) {
			return bad("malformed tag")
		}
	}
	if name == "" {
		return bad("no repository")
	}
	if len(name) > maxNameLen {
		return bad("name too long")
	}

	repo := name
	if i := strings.IndexByte(name, '/'); i >= 0 {
		if first := name[:i]; strings.ContainsAny(first, ".:") || first == "localhost" {
			if !domainRe.MatchString(first) {
				return bad("malformed registry host")
			}
			r.Registry, repo = strings.ToLower(first), name[i+1:]
		}
	}
	switch r.Registry {
	case "", "index.docker.io", "registry-1.docker.io":
		r.Registry = "docker.io"
	}
	if r.Registry == "docker.io" && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	if repo != strings.ToLower(repo) {
		return bad("repository must be lowercase")
	}
	for _, c := range strings.Split(repo, "/") {
		if !componentRe.MatchString(c) {
			return bad("malformed repository")
		}
	}
	r.Repository = repo
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	return r, nil
}

// validDigest accepts algorithm:encoded, holding the registered algorithms
// to their exact lengths so a truncated digest is caught here rather than
// showing up as drift.
func validDigest(d string) bool {
	if !digestRe.MatchString(d) {
		return false
	}
	alg, enc, _ := strings.Cut(d, ":")
	switch alg {
	case "sha256":
		return len(enc) == 64 && hexRe.MatchString(enc)
	case "sha512":
		return len(enc) == 128 && hexRe.MatchString(enc)
	}
	return true
}

// String returns the canonical form, e.g. "docker.io/library/nginx:1.27",
// "quay.io/x/y@sha256:..." or "ghcr.io/a/b:tag@sha256:...".
func (r Ref) String() string {
	s := r.Repo()
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

// Repo returns the registry and repository, e.g. "docker.io/library/nginx".
func (r Ref) Repo() string { return r.Registry + "/" + r.Repository }
