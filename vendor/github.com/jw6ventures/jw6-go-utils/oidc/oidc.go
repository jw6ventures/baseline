// Package oidc provides a small, framework-agnostic OpenID Connect relying
// party (login) helper for JW6 applications.
//
// It wraps the standard Go OIDC stack (github.com/coreos/go-oidc and
// golang.org/x/oauth2): it performs provider discovery, builds the
// authorization-code redirect URL (with state, nonce and PKCE), exchanges the
// returned code for tokens, and verifies the ID token. It deliberately does not
// register HTTP routes or middleware; the calling application wires its own
// /login and /callback handlers and uses the secure cookie codec in this
// package (see cookie.go) to persist the in-flight state and the resulting
// session.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	jw6_utils "github.com/jw6ventures/jw6-go-utils"
	"golang.org/x/oauth2"
)

// DefaultScopes are requested when Config.Scopes is empty. "openid" is required
// for OIDC; profile and email are requested so the common identity claims are
// available on the returned Session.
var DefaultScopes = []string{coreoidc.ScopeOpenID, "profile", "email"}

// Logger matches the logging contract used elsewhere in jw6-go-utils so an
// application's *jw6_utils.Utils can be passed directly.
type Logger interface {
	Log(class string, method string, level jw6_utils.LogLevel, message string)
}

// Config describes a single OIDC provider/client relationship.
type Config struct {
	// Issuer is the provider's issuer URL, e.g. "https://accounts.google.com".
	// Discovery is performed against Issuer + "/.well-known/openid-configuration".
	Issuer string
	// ClientID and ClientSecret identify the registered application. For public
	// clients (no secret) leave ClientSecret empty; PKCE still protects the flow.
	ClientID     string
	ClientSecret string
	// RedirectURL is the application's callback URL registered with the provider.
	RedirectURL string
	// Scopes overrides DefaultScopes when set. "openid" is added automatically
	// if missing.
	Scopes []string
	// Logger is optional; when nil no logging is performed.
	Logger Logger
}

// Authenticator is a ready-to-use, concurrency-safe OIDC client for one
// provider. Create it with NewAuthenticator.
type Authenticator struct {
	provider     *coreoidc.Provider
	verifier     *coreoidc.IDTokenVerifier
	oauth2Config oauth2.Config
	logger       Logger
}

// AuthRequest is the result of starting a login. The application redirects the
// user to URL and must persist State, Nonce and PKCEVerifier (e.g. in a sealed
// cookie via CookieCodec) so they can be supplied to Exchange on callback.
type AuthRequest struct {
	URL          string
	State        string
	Nonce        string
	PKCEVerifier string
}

// Session is the verified result of a completed login.
type Session struct {
	Subject       string         // "sub" claim — stable user identifier
	Email         string         // "email" claim, if present
	EmailVerified bool           // "email_verified" claim, if present
	Name          string         // "name" claim, if present
	Claims        map[string]any // all ID token claims
	IDToken       string         // raw (verified) ID token
	AccessToken   string
	RefreshToken  string    // present only if the provider returned one
	Expiry        time.Time // access token expiry; zero if unknown
}

// NewAuthenticator performs OIDC discovery against config.Issuer and returns an
// Authenticator. The ctx is used only for discovery; it may be a request or
// startup context and need not outlive the returned Authenticator.
func NewAuthenticator(ctx context.Context, config Config) (*Authenticator, error) {
	if strings.TrimSpace(config.Issuer) == "" {
		return nil, fmt.Errorf("oidc: issuer is required")
	}
	if strings.TrimSpace(config.ClientID) == "" {
		return nil, fmt.Errorf("oidc: client id is required")
	}
	if strings.TrimSpace(config.RedirectURL) == "" {
		return nil, fmt.Errorf("oidc: redirect url is required")
	}

	provider, err := coreoidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery failed for issuer %q: %w", config.Issuer, err)
	}

	a := &Authenticator{
		provider: provider,
		verifier: provider.Verifier(&coreoidc.Config{ClientID: config.ClientID}),
		oauth2Config: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       resolveScopes(config.Scopes),
		},
		logger: config.Logger,
	}

	a.log("NewAuthenticator", jw6_utils.Info, fmt.Sprintf("OIDC provider configured for issuer %s", config.Issuer))
	return a, nil
}

// AuthRequest begins a login by generating fresh state, nonce and PKCE values
// and building the authorization URL. The returned State, Nonce and
// PKCEVerifier must be stored and passed back to Exchange.
func (a *Authenticator) AuthRequest(opts ...oauth2.AuthCodeOption) (AuthRequest, error) {
	state, err := randomToken()
	if err != nil {
		return AuthRequest{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return AuthRequest{}, err
	}

	verifier := oauth2.GenerateVerifier()

	params := append([]oauth2.AuthCodeOption{
		coreoidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	}, opts...)

	return AuthRequest{
		URL:          a.oauth2Config.AuthCodeURL(state, params...),
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: verifier,
	}, nil
}

// Exchange completes a login: it swaps the authorization code for tokens
// (proving possession of pkceVerifier), then verifies the ID token's signature,
// issuer, audience, expiry and nonce. The caller is responsible for verifying
// the OAuth state parameter before calling Exchange (compare the state returned
// on the callback against the stored AuthRequest.State).
func (a *Authenticator) Exchange(ctx context.Context, code, nonce, pkceVerifier string) (*Session, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("oidc: authorization code is required")
	}
	if strings.TrimSpace(nonce) == "" {
		return nil, fmt.Errorf("oidc: nonce is required")
	}
	if strings.TrimSpace(pkceVerifier) == "" {
		return nil, fmt.Errorf("oidc: PKCE verifier is required")
	}

	token, err := a.oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return nil, fmt.Errorf("oidc: token exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("oidc: token response did not include an id_token")
	}

	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: id token verification failed: %w", err)
	}

	if idToken.Nonce == "" || idToken.Nonce != nonce {
		return nil, fmt.Errorf("oidc: id token nonce mismatch")
	}

	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: failed to parse id token claims: %w", err)
	}

	session := &Session{
		Subject:       idToken.Subject,
		Email:         stringClaim(claims, "email"),
		EmailVerified: boolClaim(claims, "email_verified"),
		Name:          stringClaim(claims, "name"),
		Claims:        claims,
		IDToken:       rawIDToken,
		AccessToken:   token.AccessToken,
		RefreshToken:  token.RefreshToken,
		Expiry:        token.Expiry,
	}

	a.log("Exchange", jw6_utils.Info, fmt.Sprintf("Authenticated subject %s", session.Subject))
	return session, nil
}

// UserInfo fetches the provider's userinfo endpoint using the session's access
// token and merges any additional claims into the provided destination. It is
// optional; the ID token already carries the standard identity claims for most
// providers.
func (a *Authenticator) UserInfo(ctx context.Context, session *Session, dest any) error {
	if session == nil || session.AccessToken == "" {
		return fmt.Errorf("oidc: a session with an access token is required")
	}
	info, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: session.AccessToken}))
	if err != nil {
		return fmt.Errorf("oidc: userinfo request failed: %w", err)
	}
	if err := info.Claims(dest); err != nil {
		return fmt.Errorf("oidc: failed to parse userinfo claims: %w", err)
	}
	return nil
}

func resolveScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return append([]string(nil), DefaultScopes...)
	}
	for _, s := range scopes {
		if s == coreoidc.ScopeOpenID {
			return append([]string(nil), scopes...)
		}
	}
	return append([]string{coreoidc.ScopeOpenID}, scopes...)
}

// randomToken returns a URL-safe, 256-bit random string for use as an OAuth
// state or OIDC nonce value.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidc: failed to generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func stringClaim(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func boolClaim(claims map[string]any, key string) bool {
	if v, ok := claims[key].(bool); ok {
		return v
	}
	return false
}

func (a *Authenticator) log(method string, level jw6_utils.LogLevel, message string) {
	if a.logger == nil {
		return
	}
	a.logger.Log("OIDC", method, level, message)
}
