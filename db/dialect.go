// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import "fmt"

// Dialect abstracts SQL differences between SQLite, PostgreSQL, and MySQL.
type Dialect interface {
	// DriverName returns the database/sql driver name.
	DriverName() string

	// DSN builds the connection string from PG config.
	DSN() string

	// OpenSuffix returns extra connection params (empty for SQLite).
	OpenSuffix() string

	// AutoIncrement returns the column type for auto-increment PK.
	AutoIncrement() string

	// BlobType returns the binary data type name.
	BlobType() string

	// NowExpr returns the default expression for current timestamp.
	NowExpr() string

	// Placeholder returns the parameter placeholder for index i (0-based).
	Placeholder(i int) string

	// InsertOrReplace returns INSERT ... ON CONFLICT ... for upsert.
	InsertOrReplace(table, columns, values string) string

	// InsertOrIgnore returns INSERT ... ON CONFLICT DO NOTHING.
	InsertOrIgnore(table, columns, values string) string

	// VacuumInto returns the backup SQL, or empty if unsupported.
	VacuumInto(path string) string

	// BoolInt converts a bool to the dialect's integer representation.
	BoolInt(v bool) int

	// EnableFKs returns SQL to enable foreign keys (empty for PG).
	EnableFKs() string

	// SupportsColumnDrop returns true if ALTER TABLE DROP COLUMN is supported.
	SupportsColumnDrop() bool
}

// SQLiteDialect implements Dialect for modernc.org/sqlite.
type SQLiteDialect struct{}

func (SQLiteDialect) DriverName() string { return "sqlite" }
func (SQLiteDialect) DSN() string        { return "" }

// OpenSuffix returns SQLite connection parameters. WAL + synchronous=NORMAL is the
// officially recommended high-concurrency combination for SQLite: under NORMAL,
// COMMIT no longer fsyncs every time (only at checkpoint), while consistency is
// still fully guaranteed by the WAL. The previous default FULL caused one fsync
// per independent transaction (~10µs serial), throttling single-issue API
// concurrent writes to ~700/s by the SQLite single-writer lock. cache_size is
// increased to 64MB (negative value = KiB) to improve page cache hit rate for
// INSERT index updates on large databases (the default 2MB page cache causes
// frequent disk misses during B-tree index traversal on a 700MB database,
// causing throughput to drop sharply as the database grows). SQLite PRAGMA
// parameters are embedded as multiple ?_pragma= groups connected by &.
func (SQLiteDialect) OpenSuffix() string {
	return "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=cache_size(-65536)"
}
func (SQLiteDialect) AutoIncrement() string    { return "INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT" }
func (SQLiteDialect) BlobType() string         { return "BLOB" }
func (SQLiteDialect) NowExpr() string          { return "(datetime('now'))" }
func (SQLiteDialect) Placeholder(i int) string { return "?" }
func (SQLiteDialect) EnableFKs() string        { return "PRAGMA foreign_keys = ON;" }
func (SQLiteDialect) SupportsColumnDrop() bool { return true }

func (SQLiteDialect) InsertOrReplace(table, columns, values string) string {
	return fmt.Sprintf("INSERT OR REPLACE INTO %s (%s) VALUES (%s)", table, columns, values)
}

func (SQLiteDialect) InsertOrIgnore(table, columns, values string) string {
	return fmt.Sprintf("INSERT OR IGNORE INTO %s (%s) VALUES (%s)", table, columns, values)
}

func (SQLiteDialect) VacuumInto(path string) string {
	return fmt.Sprintf("VACUUM INTO '%s'", path)
}

func (SQLiteDialect) BoolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// pgDialect implements Dialect for PostgreSQL (via pgx).
type pgDialect struct{}

func (pgDialect) DriverName() string { return "pgx" }

func (pgDialect) DSN() string { return "" }

func (pgDialect) DSNOld(cfg *PGConfig) string {
	if cfg.DSN != "" {
		return cfg.DSN
	}
	dsn := fmt.Sprintf("host=%s port=%d user=%s dbname=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.DBName)
	if cfg.Password != "" {
		dsn += fmt.Sprintf(" password=%s", cfg.Password)
	}
	if cfg.SSLMode != "" {
		dsn += fmt.Sprintf(" sslmode=%s", cfg.SSLMode)
	} else {
		dsn += " sslmode=disable"
	}
	return dsn
}

func (pgDialect) OpenSuffix() string { return "?sslmode=disable" } // used as query params

func (pgDialect) AutoIncrement() string { return "SERIAL PRIMARY KEY" }
func (pgDialect) BlobType() string      { return "BYTEA" }
func (pgDialect) NowExpr() string       { return "NOW()" }
func (pgDialect) EnableFKs() string     { return "" } // PG has FKs by default

func (pgDialect) Placeholder(i int) string {
	return fmt.Sprintf("$%d", i+1)
}

func (pgDialect) SupportsColumnDrop() bool { return false } // PG requires complex rewrite

func (pgDialect) InsertOrReplace(table, columns, values string) string {
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT ON CONSTRAINT %s_pkey DO UPDATE SET %s",
		table, columns, values, table, conflictSet(columns))
}

func (pgDialect) InsertOrIgnore(table, columns, values string) string {
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT DO NOTHING", table, columns, values)
}

func (pgDialect) VacuumInto(_ string) string { return "" } // not supported

func (pgDialect) BoolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// mysqlDialect implements Dialect for MySQL/MariaDB (via go-sql-driver/mysql).
type mysqlDialect struct{}

func (mysqlDialect) DriverName() string       { return "mysql" }
func (mysqlDialect) DSN() string              { return "" }
func (mysqlDialect) OpenSuffix() string       { return "?charset=utf8mb4&parseTime=true" }
func (mysqlDialect) AutoIncrement() string    { return "INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT" }
func (mysqlDialect) BlobType() string         { return "BLOB" }
func (mysqlDialect) NowExpr() string          { return "NOW()" }
func (mysqlDialect) Placeholder(i int) string { return "?" }
func (mysqlDialect) EnableFKs() string        { return "" } // MySQL parses but ignores FK by default
func (mysqlDialect) SupportsColumnDrop() bool { return true }

func (mysqlDialect) InsertOrReplace(table, columns, values string) string {
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON DUPLICATE KEY UPDATE %s",
		table, columns, values, mysqlConflictSet(columns))
}

func (mysqlDialect) InsertOrIgnore(table, columns, values string) string {
	return fmt.Sprintf("INSERT IGNORE INTO %s (%s) VALUES (%s)", table, columns, values)
}

func (mysqlDialect) VacuumInto(_ string) string { return "" } // not supported

func (mysqlDialect) BoolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// mysqlConflictSet builds "col1=VALUES(col1), col2=VALUES(col2)" for MySQL ON DUPLICATE KEY UPDATE.
func mysqlConflictSet(columns string) string {
	cols := splitCSV(columns)
	set := make([]string, len(cols))
	for i, c := range cols {
		set[i] = fmt.Sprintf("%s=VALUES(%s)", c, c)
	}
	return joinCSV(set)
}

// conflictSet builds "col1=EXCLUDED.col1, col2=EXCLUDED.col2" from columns.
// Used by INSERT ... ON CONFLICT DO UPDATE SET ... "col1=EXCLUDED.col1, col2=EXCLUDED.col2" from columns.
// Used by INSERT ... ON CONFLICT DO UPDATE SET ...
func conflictSet(columns string) string {
	cols := splitCSV(columns)
	set := make([]string, len(cols))
	for i, c := range cols {
		set[i] = fmt.Sprintf("%s=EXCLUDED.%s", c, c)
	}
	return joinCSV(set)
}

// splitCSV splits a comma-separated column list, trimming whitespace.
func splitCSV(s string) []string {
	var result []string
	current := make([]byte, 0)
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			if len(current) > 0 {
				result = append(result, string(current))
				current = current[:0]
			}
		} else if s[i] != ' ' {
			current = append(current, s[i])
		}
	}
	if len(current) > 0 {
		result = append(result, string(current))
	}
	return result
}

// joinCSV joins strings with comma+space.
func joinCSV(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ", "
		}
		result += p
	}
	return result
}

// PGConfig holds PostgreSQL connection parameters.
type PGConfig struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	DBName   string `json:"dbname,omitempty"`
	SSLMode  string `json:"sslmode,omitempty"`
	DSN      string `json:"dsn,omitempty"` // raw DSN overrides above
}

// NewPGDialect creates a new PostgreSQL dialect with the given config.
func NewPGDialect(cfg PGConfig) Dialect {
	return &pgDialectWithConfig{cfg: cfg}
}

type pgDialectWithConfig struct {
	pgDialect
	cfg PGConfig
}

func (p *pgDialectWithConfig) DSN() string {
	if p.cfg.DSN != "" {
		return p.cfg.DSN
	}
	dsn := fmt.Sprintf("host=%s port=%d user=%s dbname=%s",
		p.cfg.Host, p.cfg.Port, p.cfg.User, p.cfg.DBName)
	if p.cfg.Password != "" {
		dsn += fmt.Sprintf(" password=%s", p.cfg.Password)
	}
	if p.cfg.SSLMode != "" {
		dsn += fmt.Sprintf(" sslmode=%s", p.cfg.SSLMode)
	} else {
		dsn += " sslmode=disable"
	}
	return dsn
}

func (p *pgDialectWithConfig) OpenSuffix() string {
	return ""
}

// NewMySQLDialect creates a MySQL dialect. dsn is the full connection string,
// e.g. "user:password@tcp(host:3306)/dbname?charset=utf8mb4&parseTime=true".
func NewMySQLDialect(dsn string) Dialect {
	return &mysqlDialectWithConfig{dsn: dsn}
}

type mysqlDialectWithConfig struct {
	mysqlDialect
	dsn string
}

func (m *mysqlDialectWithConfig) DSN() string { return m.dsn }
