// Package vercmp compares package versions the way each distro's package
// manager does (docs/agent.md §2), for update checks on the agent and CVE
// matching on the server (internal/vuln).
package vercmp

import "strings"

// RPM compares two [epoch:]version[-release] strings like rpm's rpmvercmp
// applied to each part in turn. It returns -1, 0 or 1.
func RPM(a, b string) int {
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)
	if c := rpmvercmp(ea, eb); c != 0 {
		return c
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	return rpmvercmp(ra, rb)
}

func splitEVR(s string) (epoch, version, release string) {
	epoch = "0"
	if e, rest, ok := strings.Cut(s, ":"); ok && e != "" && strings.Trim(e, "0123456789") == "" {
		epoch, s = e, rest
	}
	version, release = s, ""
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		version, release = s[:i], s[i+1:]
	}
	return epoch, version, release
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// rpmvercmp is rpm's segment comparison: runs of digits compare
// numerically and beat runs of letters, '~' sorts before anything (even the
// end of the string) and '^' after the end but before anything else.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	for len(a) > 0 || len(b) > 0 {
		for len(a) > 0 && !isAlnum(a[0]) && a[0] != '~' && a[0] != '^' {
			a = a[1:]
		}
		for len(b) > 0 && !isAlnum(b[0]) && b[0] != '~' && b[0] != '^' {
			b = b[1:]
		}
		// Tilde: pre-release, older than anything.
		if len(a) > 0 && a[0] == '~' || len(b) > 0 && b[0] == '~' {
			if len(a) == 0 || a[0] != '~' {
				return 1
			}
			if len(b) == 0 || b[0] != '~' {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		// Caret: post-release snapshot, newer than the end of the string.
		if len(a) > 0 && a[0] == '^' || len(b) > 0 && b[0] == '^' {
			if len(a) == 0 {
				return -1
			}
			if len(b) == 0 {
				return 1
			}
			if a[0] != '^' {
				return 1
			}
			if b[0] != '^' {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if len(a) == 0 || len(b) == 0 {
			break
		}
		numeric := isDigit(a[0])
		seg := func(s string) (string, string) {
			i := 0
			for i < len(s) && (numeric && isDigit(s[i]) || !numeric && isAlpha(s[i])) {
				i++
			}
			return s[:i], s[i:]
		}
		var sa, sb string
		sa, a = seg(a)
		sb, b = seg(b)
		if sb == "" {
			// Segments of different types: numbers are newer.
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			sa = strings.TrimLeft(sa, "0")
			sb = strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				if len(sa) > len(sb) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
	}
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return -1
	}
	return 1
}
