// Package stackenv handles a Compose stack's .env, the file that holds its
// secrets (docs/change-management.md §5.1). The server keeps every version
// encrypted with BASELINE_SECRET_KEY, so it can be edited from the UI, and a
// keyed hash of it; the agent writes it beside the stack's Compose file.
package stackenv

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/jw6ventures/jw6-go-utils/oidc"
)

// MaxSize caps a .env file.
const MaxSize = 64 << 10

// sealed is a .env as it is encrypted for the database: bound to its
// revision, so one row's file can't be moved to another.
type sealed struct {
	Revision string `json:"revision"`
	Env      string `json:"env"`
}

// Seal encrypts a .env for the database.
func Seal(c *oidc.CookieCodec, revision string, text []byte) (string, error) {
	return c.Seal(sealed{Revision: revision, Env: string(text)}, 0)
}

// Open decrypts a .env Seal made for this revision.
func Open(c *oidc.CookieCodec, revision, blob string) ([]byte, error) {
	var v sealed
	if err := c.Open(blob, &v); err != nil {
		return nil, errors.New("the .env doesn't open (did BASELINE_SECRET_KEY change?)")
	}
	if v.Revision != revision {
		return nil, errors.New("the .env belongs to another revision")
	}
	return []byte(v.Env), nil
}

// HashKey is the key .env hashes are made with, derived from the server's
// secret key.
func HashKey(secret []byte) []byte {
	// The label predates the rename to Baseline; changing it would change
	// every stored hash.
	k, err := hkdf.Key(sha256.New, secret, nil, "jcmdb stack env hash", 32)
	if err != nil {
		panic(err)
	}
	return k
}

// Hash is the server's fingerprint of a .env: HMAC-SHA256 under HashKey,
// so it can be shown and compared without helping anyone guess short
// secrets from it. Equal files hash the same.
func Hash(key, text []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(text)
	return "hmac-sha256:" + hex.EncodeToString(m.Sum(nil))
}

// SHA256 is a file's plain SHA-256, hex, as inventory reports Compose files.
func SHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

var reKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// ValidKey reports whether s can name a variable.
func ValidKey(s string) bool { return len(s) <= 128 && reKey.MatchString(s) }

// line is one line of a .env: a variable (key set) or anything else kept
// as it is (comments, blank lines).
type line struct {
	key  string
	text string
}

// parse reads a .env as Compose does: KEY=VALUE lines, optionally after
// "export ", with blank lines and # comments.
func parse(text []byte) ([]line, error) {
	if len(text) > MaxSize {
		return nil, fmt.Errorf("the .env is larger than %d KiB", MaxSize>>10)
	}
	if !utf8.Valid(text) || bytes.IndexByte(text, 0) >= 0 {
		return nil, errors.New("the .env isn't text")
	}
	s := strings.ReplaceAll(string(text), "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil, nil
	}
	var out []line
	for n, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			out = append(out, line{text: l})
			continue
		}
		k, _, ok := strings.Cut(strings.TrimPrefix(t, "export "), "=")
		k = strings.TrimSpace(k)
		if !ok || !ValidKey(k) {
			// Never quote the line: it may hold a secret.
			return nil, fmt.Errorf("line %d isn't KEY=VALUE", n+1)
		}
		out = append(out, line{key: k, text: l})
	}
	return out, nil
}

func format(lines []line) []byte {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.text)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// Check validates a .env and returns its variable names, sorted. A name
// set twice is refused: which one wins would be a surprise.
func Check(text []byte) ([]string, error) {
	lines, err := parse(text)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, l := range lines {
		if l.key == "" {
			continue
		}
		if slices.Contains(keys, l.key) {
			return nil, fmt.Errorf("%s is set twice", l.key)
		}
		keys = append(keys, l.key)
	}
	slices.Sort(keys)
	return keys, nil
}
