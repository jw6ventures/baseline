package stackenv

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/jw6ventures/jw6-go-utils/oidc"
)

func TestSealOpen(t *testing.T) {
	c, err := oidc.NewCookieCodec(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Seal(c, "rev", []byte("A=1\n"))
	if err != nil || strings.Contains(blob, "A=1") {
		t.Fatalf("seal = %q, %v", blob, err)
	}
	if pt, err := Open(c, "rev", blob); err != nil || string(pt) != "A=1\n" {
		t.Fatalf("open = %q, %v", pt, err)
	}
	if _, err := Open(c, "rev2", blob); err == nil {
		t.Error("opened as another revision's")
	}
	other, _ := oidc.NewCookieCodec(bytes.Repeat([]byte{8}, 32))
	if _, err := Open(other, "rev", blob); err == nil {
		t.Error("opened with another key")
	}
}

func TestCheck(t *testing.T) {
	keys, err := Check([]byte("# c\n\nexport B=2\nA=\"x y\"\r\nC.D=1\n"))
	if err != nil || !slices.Equal(keys, []string{"A", "B", "C.D"}) {
		t.Fatalf("keys = %q, %v", keys, err)
	}
	for in, want := range map[string]string{
		"A=1\nA=2\n":                   "A is set twice",
		"A=1\nhunter2\n":               "line 2 isn't KEY=VALUE",
		"1A=x\n":                       "line 1",
		"A=1\x00\n":                    "isn't text",
		strings.Repeat("A", MaxSize+1): "larger than",
	} {
		_, err := Check([]byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Check(%.20q) = %v, want %q", in, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Error("an error quotes a secret")
		}
	}
}

func TestHash(t *testing.T) {
	a, b := Hash([]byte("k1"), []byte("A=1")), Hash([]byte("k2"), []byte("A=1"))
	if a == b || !strings.HasPrefix(a, "hmac-sha256:") || a != Hash([]byte("k1"), []byte("A=1")) {
		t.Errorf("hashes %s %s", a, b)
	}
}
