package registry

import "strings"

// challenge is one WWW-Authenticate challenge: a lowercased scheme and its
// auth-params with lowercased names.
type challenge struct {
	scheme string
	params map[string]string
}

// parseChallenges parses WWW-Authenticate values (RFC 7235). Values can
// hold several challenges, and quoted values can hold commas, as in
// scope="repository:a/b:pull,push", so splitting on commas won't do.
func parseChallenges(values []string) []challenge {
	var out []challenge
	for _, v := range values {
		p := authParser{s: v}
		for {
			p.skip(" \t,")
			if p.i >= len(p.s) {
				break
			}
			scheme := p.token()
			if scheme == "" {
				p.i++ // junk; resync on the next token
				continue
			}
			ch := challenge{scheme: strings.ToLower(scheme), params: map[string]string{}}
			for {
				p.skip(" \t,")
				save := p.i
				name := p.token()
				p.skip(" \t")
				if name == "" || !p.eat('=') {
					// Not name=value: the start of the next challenge.
					p.i = save
					break
				}
				p.skip(" \t")
				var val string
				if p.peek() == '"' {
					val = p.quoted()
				} else {
					// Lenient: servers send unquoted URLs, which aren't tokens.
					start := p.i
					for p.i < len(p.s) && strings.IndexByte(", \t", p.s[p.i]) < 0 {
						p.i++
					}
					val = p.s[start:p.i]
				}
				ch.params[strings.ToLower(name)] = val
			}
			out = append(out, ch)
		}
	}
	return out
}

type authParser struct {
	s string
	i int
}

func (p *authParser) peek() byte {
	if p.i < len(p.s) {
		return p.s[p.i]
	}
	return 0
}

func (p *authParser) eat(c byte) bool {
	if p.i < len(p.s) && p.s[p.i] == c {
		p.i++
		return true
	}
	return false
}

func (p *authParser) skip(set string) {
	for p.i < len(p.s) && strings.IndexByte(set, p.s[p.i]) >= 0 {
		p.i++
	}
}

func isTokenChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func (p *authParser) token() string {
	start := p.i
	for p.i < len(p.s) && isTokenChar(p.s[p.i]) {
		p.i++
	}
	return p.s[start:p.i]
}

// quoted reads a quoted-string, unescaping backslash pairs. An unterminated
// string runs to the end of the header.
func (p *authParser) quoted() string {
	p.i++ // opening quote
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		p.i++
		switch {
		case c == '"':
			return b.String()
		case c == '\\' && p.i < len(p.s):
			b.WriteByte(p.s[p.i])
			p.i++
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
