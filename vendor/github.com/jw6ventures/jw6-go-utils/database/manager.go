package database

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	jw6_utils "github.com/jw6ventures/jw6-go-utils"
	"github.com/jw6ventures/jw6-go-utils/database/migration"

	_ "github.com/lib/pq" // PostgreSQL driver
)

type Logger interface {
	Log(class string, method string, level jw6_utils.LogLevel, message string)
}

type Config struct {
	Driver            string
	ConnString        string
	MigrationsPath    string
	AppVersion        string
	SchemaPath        string
	SchemaCheckTable  string
	SchemaCheckQuery  string
	SchemaCheckArgs   []any
	Logger            Logger
}

type Manager struct {
	DB               *sql.DB
	MigrationManager *migration.Manager
	config           Config
	Logger           Logger
}

func NewManager(config Config) *Manager {
	return &Manager{
		config: config,
		Logger: config.Logger,
	}
}

func (m *Manager) Initialize() error {
	if strings.TrimSpace(m.config.Driver) == "" {
		return fmt.Errorf("database driver is required")
	}
	if strings.TrimSpace(m.config.ConnString) == "" {
		return fmt.Errorf("connection string is required")
	}

	db, err := sql.Open(m.config.Driver, m.config.ConnString)
	if err != nil {
		return err
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return err
	}

	m.DB = db

	if err := migration.EnsureApplicationTable(m.DB); err != nil {
		m.Close()
		return err
	}

	if err := m.ensureSchema(); err != nil {
		m.Close()
		return err
	}

	if strings.TrimSpace(m.config.MigrationsPath) != "" || strings.TrimSpace(m.config.AppVersion) != "" {
		if strings.TrimSpace(m.config.MigrationsPath) == "" || strings.TrimSpace(m.config.AppVersion) == "" {
			m.Close()
			return fmt.Errorf("both migrations path and app version are required to run migrations")
		}

		m.MigrationManager = migration.NewManager(m.DB, m.config.MigrationsPath, m.config.AppVersion, migration.WithLogger(m.Logger))
		if err := m.MigrationManager.Initialize(); err != nil {
			m.Close()
			return err
		}

		if err := m.MigrationManager.MigrateDatabase(); err != nil {
			m.Close()
			return err
		}
	}

	m.log("Initialize", jw6_utils.Info, "Database connection established")
	return nil
}

func (m *Manager) Close() {
	if m.DB != nil {
		m.DB.Close()
		m.log("Close", jw6_utils.Info, "Database connection closed")
	}
}

func (m *Manager) ensureSchema() error {
	if strings.TrimSpace(m.config.SchemaPath) == "" {
		return nil
	}

	if strings.TrimSpace(m.config.SchemaCheckQuery) == "" && strings.TrimSpace(m.config.SchemaCheckTable) == "" {
		return fmt.Errorf("schema check query or table name is required when schema path is set")
	}

	exists, err := m.schemaExists()
	if err != nil {
		return err
	}

	if exists {
		return nil
	}

	m.log("Initialize", jw6_utils.Info, "Database schema does not exist, creating it")
	schema, err := os.ReadFile(m.config.SchemaPath)
	if err != nil {
		return err
	}

	if _, err := m.DB.Exec(string(schema)); err != nil {
		return err
	}
	m.log("Initialize", jw6_utils.Info, "Database schema created")
	return nil
}

func (m *Manager) schemaExists() (bool, error) {
	var exists bool

	if strings.TrimSpace(m.config.SchemaCheckQuery) != "" {
		args := m.config.SchemaCheckArgs
		if err := m.DB.QueryRow(m.config.SchemaCheckQuery, args...).Scan(&exists); err != nil {
			return false, err
		}
		return exists, nil
	}

	err := m.DB.QueryRow(`SELECT EXISTS (
		SELECT FROM information_schema.tables 
		WHERE table_schema = 'public' 
		AND table_name = $1
	)`, m.config.SchemaCheckTable).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (m *Manager) log(method string, level jw6_utils.LogLevel, message string) {
	if m.Logger == nil {
		return
	}
	m.Logger.Log("Database", method, level, message)
}
