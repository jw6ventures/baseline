package pki

import (
	"crypto/ed25519"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Agent releases are signed in CI (.github/workflows/release.yml) with keys
// the server never holds (docs/agent.md §5.2). Their public halves are
// built into every agent from release-keys.pem, so a server can hand out
// binaries but can't make a new one an agent will accept.

const (
	// MaxReleaseKeys is how many release keys an agent trusts at once: the
	// current one and, during a rotation, the next.
	MaxReleaseKeys = 2
	// maxReleaseSignatures bounds the work a server can make an agent do.
	maxReleaseSignatures = 4
)

//go:embed release-keys.pem
var releaseKeysPEM []byte

// ReleaseKeys returns the release public keys built into this binary. An
// empty list (a build without keys) means nothing can be verified.
func ReleaseKeys() ([]ed25519.PublicKey, error) {
	return ParseReleaseKeys(releaseKeysPEM)
}

// ParseReleaseKeys reads ed25519 public keys from PEM ("PUBLIC KEY", as
// `openssl pkey -pubout` writes them). Text outside the blocks is ignored.
func ParseReleaseKeys(b []byte) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			break
		}
		if blk.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("release keys: unexpected %s block", blk.Type)
		}
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("release keys: %w", err)
		}
		ed, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("release keys: not an ed25519 key")
		}
		keys = append(keys, ed)
	}
	if len(keys) > MaxReleaseKeys {
		return nil, fmt.Errorf("release keys: %d keys, at most %d are trusted at once", len(keys), MaxReleaseKeys)
	}
	return keys, nil
}

// ParseReleaseSigningKeys reads ed25519 private keys from PEM ("PRIVATE
// KEY", PKCS #8, as `openssl genpkey -algorithm ed25519` writes them).
func ParseReleaseSigningKeys(b []byte) ([]ed25519.PrivateKey, error) {
	var keys []ed25519.PrivateKey
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			break
		}
		if blk.Type != "PRIVATE KEY" {
			return nil, fmt.Errorf("signing key: unexpected %s block", blk.Type)
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("signing key: %w", err)
		}
		ed, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("signing key: not an ed25519 key")
		}
		keys = append(keys, ed)
	}
	if len(keys) == 0 {
		return nil, errors.New("signing key: no PEM block")
	}
	return keys, nil
}

// VerifyRelease reports whether any signature over the release statement
// verifies against any of keys.
func VerifyRelease(keys []ed25519.PublicKey, version, arch, sha256hex string, sigs [][]byte) bool {
	stmt := ReleaseStatement(version, arch, sha256hex)
	for i, sig := range sigs {
		if i == maxReleaseSignatures {
			break
		}
		for _, k := range keys {
			if len(sig) == ed25519.SignatureSize && ed25519.Verify(k, stmt, sig) {
				return true
			}
		}
	}
	return false
}

// FormatReleaseSignatures writes the .sig file shipped next to an agent
// binary: one base64 signature per line.
func FormatReleaseSignatures(sigs [][]byte) []byte {
	var sb strings.Builder
	for _, s := range sigs {
		sb.WriteString(base64.StdEncoding.EncodeToString(s) + "\n")
	}
	return []byte(sb.String())
}

// ParseReleaseSignatures reads a .sig file.
func ParseReleaseSignatures(b []byte) ([][]byte, error) {
	var sigs [][]byte
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		s, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(s) != ed25519.SignatureSize {
			return nil, errors.New("release signatures: not a base64 ed25519 signature")
		}
		sigs = append(sigs, s)
	}
	if len(sigs) > maxReleaseSignatures {
		return nil, fmt.Errorf("release signatures: %d, at most %d", len(sigs), maxReleaseSignatures)
	}
	return sigs, nil
}
