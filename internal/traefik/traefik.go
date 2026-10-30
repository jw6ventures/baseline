// Package traefik reads the routers Traefik's Docker provider builds from a
// container's labels, for the hostnames they route to it
// (docs/data-model.md §1). It only reads labels: routers from Traefik's
// file provider or its static configuration aren't visible here.
package traefik

import (
	"slices"
	"strconv"
	"strings"
)

// Matcher kinds that name hosts.
const (
	Host          = "Host"
	HostRegexp    = "HostRegexp"
	HostSNI       = "HostSNI"
	HostSNIRegexp = "HostSNIRegexp"
)

// Match is one hostname, or hostname pattern, a router's rule matches.
type Match struct {
	Kind string // Host | HostRegexp | HostSNI | HostSNIRegexp
	// Value is the hostname, lowercase and without a trailing dot, or the
	// pattern as written.
	Value string
}

// Regexp reports whether Value is a pattern rather than a hostname.
func (m Match) Regexp() bool { return m.Kind == HostRegexp || m.Kind == HostSNIRegexp }

// Router is an HTTP or TCP router defined by labels.
type Router struct {
	Name        string
	Protocol    string // http | tcp
	Rule        string
	EntryPoints []string
	TLS         bool
	Service     string // as labelled; "" lets Traefik pick
	// Port is the port of the service it sends to when a label sets it, 0
	// when Traefik picks the container's exposed port.
	Port    int
	Matches []Match
}

// Routers lists the routers with a rule in a container's labels, by
// protocol and name. A container with traefik.enable=false has none.
func Routers(labels map[string]string) []Router {
	type key struct{ proto, name string }
	byKey := map[key]*Router{}
	ports := map[key]int{}     // services' ports, by protocol and service name
	services := map[key]bool{} // services defined, by protocol and name
	for k, v := range labels {
		lk := strings.ToLower(k)
		if lk == "traefik.enable" && strings.EqualFold(strings.TrimSpace(v), "false") {
			return nil
		}
		f := strings.SplitN(k, ".", 5)
		if len(f) < 5 || !strings.EqualFold(f[0], "traefik") {
			continue
		}
		proto := strings.ToLower(f[1])
		if proto != "http" && proto != "tcp" {
			continue
		}
		name, prop := f[3], strings.ToLower(f[4])
		switch strings.ToLower(f[2]) {
		case "services":
			services[key{proto, name}] = true
			if prop == "loadbalancer.server.port" {
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					ports[key{proto, name}] = n
				}
			}
			continue
		case "routers":
		default:
			continue
		}
		r := byKey[key{proto, name}]
		if r == nil {
			r = &Router{Name: name, Protocol: proto}
			byKey[key{proto, name}] = r
		}
		switch {
		case prop == "rule":
			r.Rule = v
		case prop == "entrypoints":
			for _, ep := range strings.Split(v, ",") {
				if ep = strings.TrimSpace(ep); ep != "" {
					r.EntryPoints = append(r.EntryPoints, ep)
				}
			}
			slices.Sort(r.EntryPoints)
		case prop == "service":
			r.Service = strings.TrimSpace(v)
		case prop == "tls":
			r.TLS = r.TLS || strings.EqualFold(strings.TrimSpace(v), "true")
		case strings.HasPrefix(prop, "tls."):
			// certresolver, options, domains, passthrough: TLS is on.
			r.TLS = true
		}
	}

	only := map[string][]string{} // service names by protocol
	for k := range services {
		only[k.proto] = append(only[k.proto], k.name)
	}
	var out []Router
	for _, r := range byKey {
		if strings.TrimSpace(r.Rule) == "" {
			continue
		}
		r.Matches = ParseRule(r.Rule)
		svc := r.Service
		if svc == "" && len(only[r.Protocol]) == 1 {
			// One service on the container: Traefik sends the router there.
			svc = only[r.Protocol][0]
		}
		r.Port = ports[key{r.Protocol, strings.TrimSuffix(svc, "@docker")}]
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b Router) int {
		if c := strings.Compare(a.Protocol, b.Protocol); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

// ParseRule finds the hosts a rule matches: the arguments of its Host,
// HostHeader, HostRegexp, HostSNI and HostSNIRegexp matchers, in v2
// (several arguments per matcher) and v3 syntax. Negated matchers, and
// HostSNI(`*`), match no host in particular and are left out.
func ParseRule(rule string) []Match {
	var out []Match
	seen := map[Match]bool{}
	add := func(m Match) {
		if m.Value != "" && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	groups := []bool{false} // whether each open group is negated
	not := false            // a "!" before the next matcher or group
	for i := 0; i < len(rule); {
		c := rule[i]
		switch {
		case c == '!':
			not = !not
			i++
		case c == '(':
			groups = append(groups, groups[len(groups)-1] != not)
			not = false
			i++
		case c == ')':
			if len(groups) > 1 {
				groups = groups[:len(groups)-1]
			}
			i++
		case c == '`' || c == '"':
			_, n, _ := readString(rule[i:])
			i += n
		case isIdent(c):
			j := i
			for j < len(rule) && (isIdent(rule[j]) || (rule[j] >= '0' && rule[j] <= '9')) {
				j++
			}
			name := rule[i:j]
			k := j
			for k < len(rule) && isSpace(rule[k]) {
				k++
			}
			if k >= len(rule) || rule[k] != '(' {
				i = j
				continue
			}
			args, n, ok := readArgs(rule[k:])
			if !ok {
				i = k // treat it as a group
				continue
			}
			negated := groups[len(groups)-1] != not
			not = false
			i = k + n
			kind := matcherKind(name)
			if kind == "" || negated {
				continue
			}
			for _, a := range args {
				switch kind {
				case Host, HostSNI:
					a = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".")
					if kind == HostSNI && a == "*" {
						continue
					}
				}
				add(Match{Kind: kind, Value: a})
			}
		default:
			i++
		}
	}
	return out
}

func matcherKind(name string) string {
	switch strings.ToLower(name) {
	case "host", "hostheader":
		return Host
	case "hostregexp":
		return HostRegexp
	case "hostsni":
		return HostSNI
	case "hostsniregexp":
		return HostSNIRegexp
	}
	return ""
}

// readArgs reads a matcher's arguments from s, which starts at its "(": a
// comma-separated list of quoted strings. n is how far it read, through the
// closing ")".
func readArgs(s string) (args []string, n int, ok bool) {
	i := 1
	for {
		for i < len(s) && isSpace(s[i]) {
			i++
		}
		if i >= len(s) {
			return nil, 0, false
		}
		if s[i] == ')' && len(args) == 0 {
			return args, i + 1, true
		}
		if s[i] != '`' && s[i] != '"' {
			return nil, 0, false
		}
		v, m, ok := readString(s[i:])
		if !ok {
			return nil, 0, false
		}
		args = append(args, v)
		i += m
		for i < len(s) && isSpace(s[i]) {
			i++
		}
		switch {
		case i >= len(s):
			return nil, 0, false
		case s[i] == ',':
			i++
		case s[i] == ')':
			return args, i + 1, true
		default:
			return nil, 0, false
		}
	}
}

// readString reads the Go string literal s starts with: raw in backticks,
// or interpreted in double quotes.
func readString(s string) (v string, n int, ok bool) {
	q := s[0]
	for i := 1; i < len(s); i++ {
		switch {
		case q == '"' && s[i] == '\\':
			i++
		case s[i] == q:
			if q == '`' {
				return s[1:i], i + 1, true
			}
			v, err := strconv.Unquote(s[:i+1])
			return v, i + 1, err == nil
		}
	}
	return "", len(s), false
}

func isIdent(c byte) bool { return c == '_' || (c|0x20 >= 'a' && c|0x20 <= 'z') }
func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
