// Package storetest opens throwaway databases for tests.
package storetest

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jw6ventures/baseline/internal/store"
)

// New opens a fresh database created on the server at BASELINE_TEST_DB_URL
// (see `make test-db`) and dropped when the test ends. It returns the store
// and its connection URL. Without BASELINE_TEST_DB_URL the test is skipped.
func New(t testing.TB) (*store.Store, string) {
	t.Helper()
	adminURL := os.Getenv("BASELINE_TEST_DB_URL")
	if adminURL == "" {
		t.Skip("BASELINE_TEST_DB_URL not set; run `make test-db` for database tests")
	}
	admin, err := sql.Open("postgres", adminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })

	name := fmt.Sprintf("baseline_test_%d", rand.Uint64())
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec("DROP DATABASE " + name + " WITH (FORCE)") })

	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	s := Open(t, u.String())
	t.Cleanup(s.Close)
	return s, u.String()
}

// Open opens the database at dbURL with the repo's schema and migrations.
// The caller closes it.
func Open(t testing.TB, dbURL string) *store.Store {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "..")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := store.Open(ctx, store.Options{
		URL:            dbURL,
		SchemaPath:     filepath.Join(root, "db", "db.sql"),
		MigrationsPath: filepath.Join(root, "db", "migrations"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
