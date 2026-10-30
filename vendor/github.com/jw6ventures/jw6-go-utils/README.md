## JW6 Go Utils

A collection of helpful utilities
 - Logging utilities
 - PostgreSQL Database manager with a version based migration system
 - OpenID Connect (OIDC) login helper with a secure cookie codec


## Database Manager Usage (PostgreSQL only)

```go
package main

import (
	"log"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"
	"github.com/jw6ventures/jw6-go-utils/database"
)

func main() {
	utils := &jw6_utils.Utils{LogLevel: jw6_utils.Info}

	manager := database.NewManager(database.Config{
		Driver:           "postgres",
		ConnString:       "postgres://user:pass@localhost:5432/app?sslmode=disable",
		MigrationsPath:   "migrations",
		AppVersion:       "1.2.3",
		SchemaPath:       "db.sql",
		SchemaCheckTable: "users",
		Logger:           utils,
	})

	if err := manager.Initialize(); err != nil {
		log.Fatal(err)
	}
	defer manager.Close()

	// Use manager.DB for queries, or manager.MigrationManager for migration helpers.
}
```

Notes:
- The database manager currently supports PostgreSQL only.
- The migration manager uses an `application` table with `key`/`value` columns and it generated immediately after opening the DB connection the first time. It stores the current schema version under `key = 'version'`.
- Ensure your baseline schema (e.g., `db.sql`) inserts the starting version row into the `application` table.
  ```
	INSERT INTO application (key,value) VALUES ('version', 'v0.0.1')
  ```
- Migrations live in the directory you pass via `MigrationsPath`, with files named `vX.Y.Z.sql` (e.g., `v1.2.3.sql`). Pre-release tags are supported (e.g., `v0.1.0-rc1.sql` or `v0.1.0-RC2.sql`).
- The manager runs migrations in semantic version order from the stored DB version up to `AppVersion`.
- If a migration file includes explicit transaction statements (BEGIN/COMMIT/etc.), it is executed as-is; otherwise it runs inside a managed transaction.

## OIDC Login (OpenID Connect relying party)

The `oidc` package adds a standard login mechanism to your apps. It works with any
OpenID Connect provider (Google, Auth0, Okta, Keycloak, Entra, etc.) via discovery,
and is framework-agnostic: it does **not** register routes. You wire your own
`/login` and `/callback` handlers and use the included AES-GCM cookie codec to carry
the in-flight login state and the resulting session.

The flow:
1. `AuthRequest()` returns a redirect URL plus the `state`, `nonce` and PKCE
   verifier. Seal those into a short-lived cookie and redirect the user.
2. On callback, read the cookie back, confirm the returned `state` matches, then
   call `Exchange()` to swap the code for verified tokens (it checks the ID token
   signature, issuer, audience, expiry and nonce).
3. Seal the returned `Session` into your session cookie.

Generate the cookie key once, store it in your secret manager, and provide the
same value to every app instance:

```sh
openssl rand -base64 32
export OIDC_COOKIE_KEY="paste-the-generated-value-here"
```

```go
package main

import (
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"
	"github.com/jw6ventures/jw6-go-utils/oidc"
)

const stateCookie = "jw6_login"
const sessionCookie = "jw6_session"

func main() {
	utils := &jw6_utils.Utils{LogLevel: jw6_utils.Info}

	auth, err := oidc.NewAuthenticator(context.Background(), oidc.Config{
		Issuer:       "https://accounts.google.com",
		ClientID:     "your-client-id",
		ClientSecret: "your-client-secret", // omit for public clients; PKCE still applies
		RedirectURL:  "https://app.example.com/callback",
		// Scopes defaults to openid/profile/email when omitted.
		Logger: utils,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Generate this once with crypto/rand, store it as base64, and reuse it.
	key, err := base64.StdEncoding.DecodeString(os.Getenv("OIDC_COOKIE_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	codec, err := oidc.NewCookieCodec(key)
	if err != nil {
		log.Fatal(err)
	}
	opts := oidc.DefaultCookieOptions()

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		req, err := auth.AuthRequest()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Persist state/nonce/verifier for the callback (5 minute lifetime).
		if err := codec.SetCookie(w, stateCookie, req, 5*time.Minute, opts); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, req.URL, http.StatusFound)
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		var pending oidc.AuthRequest
		if err := codec.ReadCookie(r, stateCookie, &pending); err != nil {
			http.Error(w, "login expired", http.StatusBadRequest)
			return
		}
		oidc.ClearCookie(w, stateCookie, opts)

		if r.URL.Query().Get("state") != pending.State {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}

		session, err := auth.Exchange(r.Context(),
			r.URL.Query().Get("code"), pending.Nonce, pending.PKCEVerifier)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Store the verified session (e.g. for 24h).
		_ = codec.SetCookie(w, sessionCookie, session, 24*time.Hour, opts)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

Notes:
- `Authenticator` is concurrency-safe; create one per provider at startup.
- The flow always uses PKCE (S256) and a verified `nonce`; the app is responsible
  for comparing the OAuth `state` parameter (shown above).
- `Session` exposes `Subject` (the stable `sub`), `Email`, `EmailVerified`, `Name`,
  the raw `Claims` map, and the ID/access/refresh tokens. Call `auth.UserInfo(...)`
  if you need additional claims from the provider's userinfo endpoint.
- `CookieCodec` uses AES-GCM, so sealed cookies are encrypted and tamper-evident,
  with an embedded expiry independent of the browser. The key must be 16, 24 or 32
  bytes (AES-128/192/256). Generate it once (for example, 32 random bytes), store
  it in your secret manager as base64, and keep the same value across restarts and
  app instances.
- `DefaultCookieOptions()` sets `Secure`, `HttpOnly` and `SameSite=Lax`; serve over
  HTTPS in production.

## Logging Setup Example

```go
package main

import (
	jw6_utils "github.com/jw6ventures/jw6-go-utils"
)

func main() {
	// Only logs Info/Warn/Error/Fatal from helpers that accept a Logger.
	utils := &jw6_utils.Utils{LogLevel: jw6_utils.Info}

	utils.Log("Bootstrap", "main", jw6_utils.Info, "Logging ready")
}
```

Notes:
- `Utils.LogLevel` is the minimum threshold; lower levels are skipped.
- `Fatal` prints a banner but does not exit the process.
- Logs print to stdout and include ANSI color codes.
