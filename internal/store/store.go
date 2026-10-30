// Package store is Baseline's PostgreSQL access layer: hand-written SQL over
// database/sql, no ORM (docs/data-model.md).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"
	"github.com/jw6ventures/jw6-go-utils/database"
	"github.com/lib/pq"
)

// migrationName is a migration file's name, vX.Y.Z.sql.
var migrationName = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)\.sql$`)

// SchemaVersion is the database schema in dir, the version of its newest
// migration (X.Y.Z): the migrations are the one place it is written down.
func SchemaVersion(dir string) (string, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("migrations: %w", err)
	}
	var best [3]int
	found := false
	for _, f := range files {
		m := migrationName.FindStringSubmatch(f.Name())
		if m == nil || f.IsDir() {
			continue
		}
		var v [3]int
		for i := range v {
			v[i], _ = strconv.Atoi(m[i+1])
		}
		if !found || slices.Compare(v[:], best[:]) > 0 {
			best, found = v, true
		}
	}
	if !found {
		return "", fmt.Errorf("migrations: no vX.Y.Z.sql files in %s", dir)
	}
	return fmt.Sprintf("%d.%d.%d", best[0], best[1], best[2]), nil
}

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
	// ErrInUse refuses to delete something others depend on.
	ErrInUse = errors.New("in use")
)

// Options locates the database and its schema files.
type Options struct {
	URL            string
	SchemaPath     string // base schema, run once on an empty database
	MigrationsPath string
	Logger         database.Logger
}

type Store struct {
	db  *sql.DB
	mgr *database.Manager

	seriesMu sync.Mutex
	series   map[string]int64 // metric series IDs by host, kind, name, instance
}

// Open connects, creating or migrating the schema, and retries with backoff
// until it succeeds or ctx is cancelled: under Compose the database container
// may still be starting when the server boots.
func Open(ctx context.Context, opts Options) (*Store, error) {
	version, err := SchemaVersion(opts.MigrationsPath)
	if err != nil {
		return nil, err
	}
	backoff := time.Second
	for {
		mgr := database.NewManager(database.Config{
			Driver:           "postgres",
			ConnString:       opts.URL,
			SchemaPath:       opts.SchemaPath,
			SchemaCheckTable: "audit_log",
			MigrationsPath:   opts.MigrationsPath,
			AppVersion:       version,
			Logger:           opts.Logger,
		})
		err := mgr.Initialize()
		if err == nil {
			mgr.DB.SetMaxOpenConns(20)
			return &Store{db: mgr.DB, mgr: mgr}, nil
		}
		if opts.Logger != nil {
			opts.Logger.Log("Store", "Open", jw6_utils.Warn,
				fmt.Sprintf("database unavailable, retrying in %v: %v", backoff, err))
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w (last error: %v)", ctx.Err(), err)
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (s *Store) Close() { s.mgr.Close() }

// DB exposes the pool, for tests and health checks.
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// tx runs fn in a transaction, committing if it returns nil.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// mapErr turns driver errors callers care about into package errors.
func mapErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "23505": // unique_violation
			return ErrConflict
		case "23503", "22P02": // foreign_key_violation, malformed UUID
			return ErrNotFound
		}
	}
	return err
}
