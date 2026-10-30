package pki

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// An enrollment token is "baseline1.<secret>.<CA fingerprint>", both parts
// base64url. The fingerprint lets a new agent pin the CA without being handed
// a file; only the secret's hash is stored.
const tokenPrefix = "baseline1"

// legacyTokenPrefix is the prefix of tokens made before the rename to
// Baseline, which still enroll.
const legacyTokenPrefix = "jcmdb1"

var ErrBadToken = errors.New("malformed enrollment token")

// NewTokenSecret returns a random 192-bit secret.
func NewTokenSecret() []byte {
	b := make([]byte, 24)
	rand.Read(b)
	return b
}

func FormatToken(secret, caFingerprint []byte) string {
	enc := base64.RawURLEncoding
	return tokenPrefix + "." + enc.EncodeToString(secret) + "." + enc.EncodeToString(caFingerprint)
}

func ParseToken(token string) (secret, caFingerprint []byte, err error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 || (parts[0] != tokenPrefix && parts[0] != legacyTokenPrefix) {
		return nil, nil, ErrBadToken
	}
	enc := base64.RawURLEncoding
	if secret, err = enc.DecodeString(parts[1]); err != nil || len(secret) < 16 {
		return nil, nil, ErrBadToken
	}
	if caFingerprint, err = enc.DecodeString(parts[2]); err != nil || len(caFingerprint) != sha256.Size {
		return nil, nil, ErrBadToken
	}
	return secret, caFingerprint, nil
}

// HashTokenSecret is what the database stores.
func HashTokenSecret(secret []byte) []byte {
	h := sha256.Sum256(secret)
	return h[:]
}
