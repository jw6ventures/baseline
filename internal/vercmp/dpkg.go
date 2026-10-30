package vercmp

import "strings"

// Dpkg compares two [epoch:]upstream[-revision] strings like
// dpkg --compare-versions. It returns -1, 0 or 1.
func Dpkg(a, b string) int {
	ea, ua, ra := splitDpkg(a)
	eb, ub, rb := splitDpkg(b)
	if c := cmpNumber(ea, eb); c != 0 {
		return c
	}
	if c := dpkgVerrevcmp(ua, ub); c != 0 {
		return c
	}
	return dpkgVerrevcmp(ra, rb)
}

// splitDpkg splits off the epoch (before the first colon) and the Debian
// revision (after the last hyphen).
func splitDpkg(s string) (epoch, upstream, revision string) {
	epoch = "0"
	if e, rest, ok := strings.Cut(s, ":"); ok && e != "" && strings.Trim(e, "0123456789") == "" {
		epoch, s = e, rest
	}
	upstream = s
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		upstream, revision = s[:i], s[i+1:]
	}
	return epoch, upstream, revision
}

// cmpNumber compares two runs of digits numerically, whatever their length.
func cmpNumber(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// dpkgOrder is a character's weight in a non-digit run: '~' sorts before
// everything, even the end of the part, then the end, then letters, then
// everything else.
func dpkgOrder(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	case c != 0:
		return int(c) + 256
	}
	return 0
}

// dpkgVerrevcmp is dpkg's verrevcmp: alternating non-digit runs, compared
// by dpkgOrder, and digit runs, compared numerically.
func dpkgVerrevcmp(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		for len(a) > 0 && !isDigit(a[0]) || len(b) > 0 && !isDigit(b[0]) {
			var ca, cb byte
			if len(a) > 0 && !isDigit(a[0]) {
				ca = a[0]
			}
			if len(b) > 0 && !isDigit(b[0]) {
				cb = b[0]
			}
			if oa, ob := dpkgOrder(ca), dpkgOrder(cb); oa != ob {
				if oa < ob {
					return -1
				}
				return 1
			}
			if ca != 0 {
				a = a[1:]
			}
			if cb != 0 {
				b = b[1:]
			}
		}
		i, j := 0, 0
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if c := cmpNumber(a[:i], b[:j]); c != 0 {
			return c
		}
		a, b = a[i:], b[j:]
	}
	return 0
}
