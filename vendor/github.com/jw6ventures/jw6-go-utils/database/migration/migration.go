package migration

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"

	"github.com/Masterminds/semver/v3"
)

type Logger interface {
	Log(class string, method string, level jw6_utils.LogLevel, message string)
}

type Option func(*Manager)

type Manager struct {
	DB             *sql.DB
	MigrationsPath string
	AppVersion     string
	Logger         Logger
}

type MigrationFile struct {
	Version *semver.Version
	Path    string
}

func NewManager(db *sql.DB, migrationsPath, appVersion string, opts ...Option) *Manager {
	manager := &Manager{
		DB:             db,
		MigrationsPath: migrationsPath,
		AppVersion:     appVersion,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(manager)
		}
	}
	return manager
}

func WithLogger(logger Logger) Option {
	return func(manager *Manager) {
		manager.Logger = logger
	}
}

func EnsureApplicationTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS application (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to create application table: %w", err)
	}
	return nil
}

func (m *Manager) Initialize() error {
	if _, err := semver.NewVersion(m.AppVersion); err != nil {
		return fmt.Errorf("invalid application version %s: %w", m.AppVersion, err)
	}

	if err := EnsureApplicationTable(m.DB); err != nil {
		return err
	}

	var count int
	err := m.DB.QueryRow("SELECT COUNT(*) FROM application WHERE key = 'version'").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check version: %w", err)
	}

	if count == 0 {
		return fmt.Errorf("database version not initialized; set baseline version in schema (application table key 'version')")
	}

	return nil
}

func (m *Manager) GetDBVersion() (string, error) {
	var version string
	err := m.DB.QueryRow("SELECT value FROM application WHERE key = 'version'").Scan(&version)
	if err != nil {
		return "", fmt.Errorf("failed to get database version: %w", err)
	}
	return version, nil
}

func (m *Manager) UpdateDBVersion(version string) error {
	_, err := m.DB.Exec("UPDATE application SET value = $1 WHERE key = 'version'", version)
	if err != nil {
		return fmt.Errorf("failed to update database version: %w", err)
	}
	return nil
}

func (m *Manager) MigrateDatabase() error {
	dbVersion, err := m.GetDBVersion()
	if err != nil {
		return err
	}

	parsedDBVersion, err := semver.NewVersion(dbVersion)
	if err != nil {
		return fmt.Errorf("invalid database version %s: %w", dbVersion, err)
	}

	parsedAppVersion, err := semver.NewVersion(m.AppVersion)
	if err != nil {
		return fmt.Errorf("invalid application version %s: %w", m.AppVersion, err)
	}

	if parsedAppVersion.Compare(parsedDBVersion) <= 0 {
		m.log("MigrateDatabase", jw6_utils.Info, fmt.Sprintf("Database is up to date (version %s)", dbVersion))
		return nil
	}

	migrations, err := m.findMigrations(parsedDBVersion, parsedAppVersion)
	if err != nil {
		return err
	}

	if len(migrations) == 0 {
		m.log("MigrateDatabase", jw6_utils.Info, fmt.Sprintf("No migrations found between %s and %s", dbVersion, m.AppVersion))
		return m.UpdateDBVersion(m.AppVersion)
	}

	m.log("MigrateDatabase", jw6_utils.Info, fmt.Sprintf("Applying %d migrations from %s to %s", len(migrations), dbVersion, m.AppVersion))

	for _, migration := range migrations {
		m.log("MigrateDatabase", jw6_utils.Info, fmt.Sprintf("Applying migration to version %s", migration.Version.String()))

		migrationFileContent, err := os.ReadFile(migration.Path)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", migration.Path, err)
		}

		if hasExplicitTransactionStatements(string(migrationFileContent)) {
			if _, err := m.DB.Exec(string(migrationFileContent)); err != nil {
				return fmt.Errorf("failed to apply migration %s: %w", migration.Version.String(), err)
			}

			if err := m.UpdateDBVersion(migration.Version.String()); err != nil {
				return fmt.Errorf("failed to update version to %s: %w", migration.Version.String(), err)
			}
		} else {
			tx, err := m.DB.Begin()
			if err != nil {
				return fmt.Errorf("failed to start transaction: %w", err)
			}

			_, err = tx.Exec(string(migrationFileContent))
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to apply migration %s: %w", migration.Version.String(), err)
			}

			_, err = tx.Exec("UPDATE application SET value = $1 WHERE key = 'version'", migration.Version.String())
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to update version to %s: %w", migration.Version.String(), err)
			}

			if err := tx.Commit(); err != nil {
				return fmt.Errorf("failed to commit transaction: %w", err)
			}
		}

		m.log("MigrateDatabase", jw6_utils.Info, fmt.Sprintf("Successfully applied migration to version %s", migration.Version.String()))
	}

	lastMigrationVersion := migrations[len(migrations)-1].Version
	if !lastMigrationVersion.Equal(parsedAppVersion) {
		if err := m.UpdateDBVersion(m.AppVersion); err != nil {
			return err
		}
		m.log("MigrateDatabase", jw6_utils.Info, fmt.Sprintf("Updated database version to application version %s", m.AppVersion))
	}

	return nil
}

func (m *Manager) findMigrations(fromVersion, toVersion *semver.Version) ([]MigrationFile, error) {
	files, err := os.ReadDir(m.MigrationsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	versionRegex := regexp.MustCompile(`^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)\.sql$`)

	var migrations []MigrationFile
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		matches := versionRegex.FindStringSubmatch(file.Name())
		if len(matches) != 2 {
			m.log("findMigrations", jw6_utils.Info, fmt.Sprintf("Ignoring file with invalid naming format: %s", file.Name()))
			continue
		}

		version, err := semver.NewVersion(matches[1])
		if err != nil {
			m.log("findMigrations", jw6_utils.Info, fmt.Sprintf("Ignoring file with invalid version: %s", file.Name()))
			continue
		}

		if version.GreaterThan(fromVersion) && migrationWithinTarget(version, toVersion) {
			migrations = append(migrations, MigrationFile{
				Version: version,
				Path:    filepath.Join(m.MigrationsPath, file.Name()),
			})
		}
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version.LessThan(migrations[j].Version)
	})

	return migrations, nil
}

func migrationWithinTarget(version, target *semver.Version) bool {
	if version.Compare(target) <= 0 {
		return true
	}

	// Allow a final release migration such as 1.0.12 to run for prerelease
	// app targets on the same core version such as 1.0.12-rc1.
	if target.Prerelease() == "" || version.Prerelease() != "" {
		return false
	}

	return version.Major() == target.Major() &&
		version.Minor() == target.Minor() &&
		version.Patch() == target.Patch()
}

func (m *Manager) log(method string, level jw6_utils.LogLevel, message string) {
	if m.Logger == nil {
		return
	}
	m.Logger.Log("Database", method, level, message)
}

var transactionStatementRegex = regexp.MustCompile(`(?im)\b(BEGIN|COMMIT|ROLLBACK|START\s+TRANSACTION|BEGIN\s+TRANSACTION)\b`)

func hasExplicitTransactionStatements(sqlText string) bool {
	cleaned := stripSQLLiteralsAndComments(sqlText)
	return transactionStatementRegex.MatchString(cleaned)
}

func stripSQLLiteralsAndComments(sqlText string) string {
	var out strings.Builder
	out.Grow(len(sqlText))

	inLineComment := false
	inBlockComment := false
	inSingleQuote := false
	inDoubleQuote := false
	dollarTag := ""

	for i := 0; i < len(sqlText); i++ {
		ch := sqlText[i]
		next := byte(0)
		if i+1 < len(sqlText) {
			next = sqlText[i+1]
		}

		if inLineComment {
			if ch == '\n' {
				inLineComment = false
				out.WriteByte('\n')
			}
			continue
		}

		if inBlockComment {
			if ch == '*' && next == '/' {
				inBlockComment = false
				i++
				out.WriteByte(' ')
			}
			continue
		}

		if dollarTag != "" {
			if strings.HasPrefix(sqlText[i:], dollarTag) {
				i += len(dollarTag) - 1
				dollarTag = ""
				out.WriteByte(' ')
			}
			continue
		}

		if inSingleQuote {
			if ch == '\'' {
				if next == '\'' {
					i++
					continue
				}
				inSingleQuote = false
				out.WriteByte(' ')
			}
			continue
		}

		if inDoubleQuote {
			if ch == '"' {
				inDoubleQuote = false
				out.WriteByte(' ')
			}
			continue
		}

		if ch == '-' && next == '-' {
			inLineComment = true
			i++
			continue
		}

		if ch == '/' && next == '*' {
			inBlockComment = true
			i++
			continue
		}

		if ch == '\'' {
			inSingleQuote = true
			continue
		}

		if ch == '"' {
			inDoubleQuote = true
			continue
		}

		if ch == '$' {
			if tag, ok := readDollarTag(sqlText[i:]); ok {
				dollarTag = tag
				i += len(tag) - 1
				continue
			}
		}

		out.WriteByte(ch)
	}

	return out.String()
}

func readDollarTag(sqlText string) (string, bool) {
	if len(sqlText) < 2 || sqlText[0] != '$' {
		return "", false
	}
	if sqlText[1] == '$' {
		return "$$", true
	}
	for i := 1; i < len(sqlText); i++ {
		ch := sqlText[i]
		if ch == '$' {
			return sqlText[:i+1], true
		}
		if !isDollarTagChar(ch) {
			return "", false
		}
	}
	return "", false
}

func isDollarTagChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '_'
}
