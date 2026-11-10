// Package composefile edits Compose files in place, line by line, so that
// everything else in them (comments, order, quoting, anchors) stays as it
// was. It only understands the block style Compose files are written in.
package composefile

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrNoImage is returned when the file doesn't set the service's image.
var ErrNoImage = errors.New("no image line for the service")

var (
	reServices = regexp.MustCompile(`^services:[ \t]*(#.*)?$`)
	reKey      = regexp.MustCompile(`^([ \t]*)(?:"([^"]+)"|'([^']+)'|([^\s"'#:][^:#]*?))[ \t]*:[ \t]*(#.*)?$`)
	reImage    = regexp.MustCompile(`^([ \t]*image[ \t]*:[ \t]*)("[^"]*"|'[^']*'|[^\s#]+)([ \t]*(?:#.*)?)$`)
)

// indent is a line's indentation, and whether it holds anything (not blank
// or a comment).
func indent(line string) (int, bool) {
	t := strings.TrimLeft(line, " \t")
	if t == "" || strings.HasPrefix(t, "#") {
		return 0, false
	}
	return len(line) - len(t), true
}

// SetTag moves a service's image to tag: in "image: repo:old" the tag is
// replaced (or added, for a reference without one). It returns the file
// with that one line changed and the reference as it was. A reference set
// through a variable, or pinned by digest, is refused; so is a service
// whose image isn't written in its own entry (ErrNoImage).
func SetTag(data []byte, service, tag string) ([]byte, string, error) {
	lines := strings.SplitAfter(string(data), "\n")
	strip := func(l string) string { return strings.TrimRight(l, "\r\n") }
	start := -1
	for i, l := range lines {
		if reServices.MatchString(strip(l)) {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, "", errors.New("no services section in block style")
	}
	// The services section: up to the next top-level key.
	end := len(lines)
	svcIndent := -1
	for i := start + 1; i < len(lines); i++ {
		n, ok := indent(strip(lines[i]))
		if !ok {
			continue
		}
		if n == 0 {
			end = i
			break
		}
		if svcIndent < 0 {
			svcIndent = n
		}
	}
	// The service's entry.
	from, to := -1, end
	for i := start + 1; i < end; i++ {
		l := strip(lines[i])
		n, ok := indent(l)
		if !ok {
			continue
		}
		if from >= 0 && n <= svcIndent {
			to = i
			break
		}
		if from < 0 && n == svcIndent {
			if m := reKey.FindStringSubmatch(l); m != nil && m[2]+m[3]+strings.TrimSpace(m[4]) == service {
				from = i
			}
		}
	}
	if from < 0 {
		return nil, "", fmt.Errorf("%w: no service %s", ErrNoImage, service)
	}
	propIndent := -1
	at := -1
	for i := from + 1; i < to; i++ {
		l := strip(lines[i])
		n, ok := indent(l)
		if !ok {
			continue
		}
		if propIndent < 0 {
			propIndent = n
		}
		if n != propIndent || !reImage.MatchString(l) {
			continue
		}
		if at >= 0 {
			return nil, "", fmt.Errorf("service %s sets its image twice", service)
		}
		at = i
	}
	if at < 0 {
		return nil, "", fmt.Errorf("%w %s", ErrNoImage, service)
	}
	l := strip(lines[at])
	m := reImage.FindStringSubmatch(l)
	value, quote := m[2], ""
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') {
		quote, value = value[:1], value[1:len(value)-1]
	}
	switch {
	case strings.Contains(value, "$"):
		return nil, value, fmt.Errorf("service %s sets its image through a variable (%s); change it where the variable is set", service, value)
	case strings.Contains(value, "@"):
		return nil, value, fmt.Errorf("service %s's image is pinned by digest (%s)", service, value)
	case value == "":
		return nil, value, fmt.Errorf("service %s's image is empty", service)
	}
	ref := WithTag(value, tag)
	lines[at] = m[1] + quote + ref + quote + m[3] + lines[at][len(l):]
	var b bytes.Buffer
	for _, x := range lines {
		b.WriteString(x)
	}
	return b.Bytes(), value, nil
}

// WithTag is an image reference with its tag replaced, or added when it
// has none.
func WithTag(ref, tag string) string {
	name := ref
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		if j := strings.LastIndex(ref[i:], ":"); j >= 0 {
			name = ref[:i+j]
		}
	} else if j := strings.LastIndex(ref, ":"); j >= 0 {
		name = ref[:j]
	}
	return name + ":" + tag
}
