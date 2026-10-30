package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CookieCodec seals arbitrary values into authenticated, encrypted cookie
// strings using AES-GCM. The same codec (constructed from the same key) is used
// to seal the in-flight login state and the post-login session. Because GCM is
// an AEAD, sealed values are both confidential and tamper-evident; an embedded
// expiry timestamp additionally bounds a cookie's lifetime independent of the
// browser.
type CookieCodec struct {
	aead cipher.AEAD
}

// CookieOptions controls the non-value attributes of cookies written by
// SetCookie and ClearCookie. The zero value is not recommended; start from
// DefaultCookieOptions.
type CookieOptions struct {
	Path     string
	Domain   string
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

// DefaultCookieOptions returns hardened defaults suitable for first-party
// session and login-state cookies served over HTTPS.
func DefaultCookieOptions() CookieOptions {
	return CookieOptions{
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

type sealedEnvelope struct {
	Exp  int64           `json:"exp"`
	Data json.RawMessage `json:"data"`
}

// NewCookieCodec creates a codec from a symmetric key. The key must be 16, 24
// or 32 bytes long (selecting AES-128, AES-192 or AES-256). Generate it once
// with crypto/rand and keep it secret and stable across application instances.
func NewCookieCodec(key []byte) (*CookieCodec, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("oidc: cookie key must be 16, 24 or 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to create GCM: %w", err)
	}
	return &CookieCodec{aead: aead}, nil
}

// Seal JSON-encodes v, stamps it with an expiry of now+ttl (ttl <= 0 means no
// expiry), encrypts it and returns a URL-safe string suitable for a cookie
// value.
func (c *CookieCodec) Seal(v any, ttl time.Duration) (string, error) {
	return c.seal(v, ttl, nil)
}

func (c *CookieCodec) seal(v any, ttl time.Duration, aad []byte) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("oidc: failed to encode cookie value: %w", err)
	}

	var exp int64
	if ttl > 0 {
		exp = time.Now().Add(ttl).UnixNano()
	}
	envelope, err := json.Marshal(sealedEnvelope{Exp: exp, Data: data})
	if err != nil {
		return "", fmt.Errorf("oidc: failed to encode cookie envelope: %w", err)
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("oidc: failed to generate nonce: %w", err)
	}

	sealed := c.aead.Seal(nonce, nonce, envelope, aad)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal: it decrypts and authenticates the value, enforces the
// embedded expiry and decodes the payload into dest. It returns an error if the
// value was tampered with, sealed by a different key, or has expired.
func (c *CookieCodec) Open(value string, dest any) error {
	return c.open(value, dest, nil)
}

func (c *CookieCodec) open(value string, dest any, aad []byte) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("oidc: failed to decode cookie value: %w", err)
	}

	nonceSize := c.aead.NonceSize()
	if len(raw) < nonceSize {
		return fmt.Errorf("oidc: cookie value is too short")
	}

	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return fmt.Errorf("oidc: cookie authentication failed: %w", err)
	}

	var envelope sealedEnvelope
	if err := json.Unmarshal(plaintext, &envelope); err != nil {
		return fmt.Errorf("oidc: failed to decode cookie envelope: %w", err)
	}
	if envelope.Exp != 0 && time.Now().UnixNano() > envelope.Exp {
		return fmt.Errorf("oidc: cookie has expired")
	}

	if err := json.Unmarshal(envelope.Data, dest); err != nil {
		return fmt.Errorf("oidc: failed to decode cookie value: %w", err)
	}
	return nil
}

// SetCookie seals v and writes it as a cookie named name. The cookie's Max-Age
// is derived from ttl (ttl <= 0 writes a session cookie that the browser drops
// on close, while still embedding no server-side expiry).
func (c *CookieCodec) SetCookie(w http.ResponseWriter, name string, v any, ttl time.Duration, opts CookieOptions) error {
	sealed, err := c.seal(v, ttl, cookieAAD(name))
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     name,
		Value:    sealed,
		Path:     opts.Path,
		Domain:   opts.Domain,
		Secure:   opts.Secure,
		HttpOnly: opts.HttpOnly,
		SameSite: opts.SameSite,
	}
	if ttl > 0 {
		cookie.MaxAge = int(ttl.Seconds())
		cookie.Expires = time.Now().Add(ttl)
	}
	http.SetCookie(w, cookie)
	return nil
}

// ReadCookie reads the cookie named name from r and opens it into dest. It
// returns http.ErrNoCookie if the cookie is absent.
func (c *CookieCodec) ReadCookie(r *http.Request, name string, dest any) error {
	cookie, err := r.Cookie(name)
	if err != nil {
		return err
	}
	return c.open(cookie.Value, dest, cookieAAD(name))
}

// ClearCookie writes an expired, empty cookie named name to delete it from the
// browser. Path and Domain must match those used when the cookie was set.
func ClearCookie(w http.ResponseWriter, name string, opts CookieOptions) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     opts.Path,
		Domain:   opts.Domain,
		Secure:   opts.Secure,
		HttpOnly: opts.HttpOnly,
		SameSite: opts.SameSite,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func cookieAAD(name string) []byte {
	return []byte("jw6-go-utils/oidc/cookie:" + name)
}
