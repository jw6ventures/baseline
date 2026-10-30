package pki

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func pubPEM(t *testing.T, k ed25519.PrivateKey) string {
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func privPEM(t *testing.T, k ed25519.PrivateKey) string {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func newKey(t *testing.T) ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The committed key file must parse, or every agent build loses self-update.
func TestBuiltInReleaseKeys(t *testing.T) {
	if _, err := ReleaseKeys(); err != nil {
		t.Fatal(err)
	}
}

func TestParseReleaseKeys(t *testing.T) {
	a, b, c := newKey(t), newKey(t), newKey(t)
	keys, err := ParseReleaseKeys([]byte("comment\n" + pubPEM(t, a) + "\nmore text\n" + pubPEM(t, b)))
	if err != nil || len(keys) != 2 || !keys[0].Equal(a.Public()) || !keys[1].Equal(b.Public()) {
		t.Fatalf("%v %v", keys, err)
	}
	if keys, err := ParseReleaseKeys([]byte("no keys yet\n")); err != nil || len(keys) != 0 {
		t.Fatalf("%v %v", keys, err)
	}
	if _, err := ParseReleaseKeys([]byte(pubPEM(t, a) + pubPEM(t, b) + pubPEM(t, c))); err == nil {
		t.Fatal("three keys accepted")
	}
	if _, err := ParseReleaseKeys([]byte(privPEM(t, a))); err == nil {
		t.Fatal("private key accepted as a public key")
	}
}

func TestReleaseSignatures(t *testing.T) {
	a, b, other := newKey(t), newKey(t), newKey(t)
	signers, err := ParseReleaseSigningKeys([]byte(privPEM(t, a) + privPEM(t, b)))
	if err != nil || len(signers) != 2 {
		t.Fatalf("%v %v", signers, err)
	}
	stmt := ReleaseStatement("1.0", "amd64", "ab")
	sigs, err := ParseReleaseSignatures(FormatReleaseSignatures([][]byte{ed25519.Sign(signers[0], stmt), ed25519.Sign(signers[1], stmt)}))
	if err != nil || len(sigs) != 2 {
		t.Fatalf("%v %v", sigs, err)
	}
	trustB := []ed25519.PublicKey{b.Public().(ed25519.PublicKey)}
	if !VerifyRelease(trustB, "1.0", "amd64", "ab", sigs) {
		t.Fatal("signature by a trusted key refused")
	}
	if VerifyRelease([]ed25519.PublicKey{other.Public().(ed25519.PublicKey)}, "1.0", "amd64", "ab", sigs) {
		t.Fatal("untrusted key accepted")
	}
	if VerifyRelease(trustB, "1.1", "amd64", "ab", sigs) || VerifyRelease(trustB, "1.0", "arm64", "ab", sigs) {
		t.Fatal("signature passed off as another version or arch")
	}
	if VerifyRelease(nil, "1.0", "amd64", "ab", sigs) {
		t.Fatal("verified without keys")
	}
	if _, err := ParseReleaseSignatures([]byte(strings.Repeat(string(FormatReleaseSignatures(sigs[:1])), 5))); err == nil {
		t.Fatal("five signatures accepted")
	}
	if _, err := ParseReleaseSignatures([]byte("bm90IGEgc2lnbmF0dXJl\n")); err == nil {
		t.Fatal("short signature accepted")
	}
}
