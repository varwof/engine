// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// createDatabaseResult describes the execution result of CreateDatabaseIfNotExists.
type createDatabaseResult struct {
	// Created indicates the database was newly created (false = already exists or no creation needed).
	Created bool
	// Database is the target database name (empty for SQLite).
	Database string
	// Driver is the driver name (sqlite / pgx / mysql).
	Driver string
}

// CreateDatabaseIfNotExists ensures the target database exists and is reachable:
//   - sqlite://   → creates the parent directory (file is auto-created by Open), idempotent
//   - postgres:// → connects to the postgres maintenance database with the same credentials, CREATE DATABASE (if not exists)
//   - mysql://    → connects to the server with no database name, CREATE DATABASE IF NOT EXISTS
//
// Note: PG/MySQL require the connecting user to have database creation privileges.
// This method only handles database creation; schema migration is performed
// by Open/OpenWithDialect.
func CreateDatabaseIfNotExists(dsn string) (createDatabaseResult, error) {
	res := createDatabaseResult{Driver: "sqlite"}

	// DATABASE_URL environment variable takes precedence (consistent with Open).
	if env := os.Getenv("DATABASE_URL"); env != "" {
		dsn = env
	}

	switch {
	case strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://"):
		return createPGDatabase(dsn, res)
	case strings.HasPrefix(dsn, "mysql://") || strings.HasPrefix(dsn, "mariadb://"):
		return createMySQLDatabase(dsn, res)
	case isRawMySQLDSN(dsn):
		// Raw driver DSN (e.g. user:pass@tcp(host:3306)/db) without URL prefix.
		return createMySQLDatabase(dsn, res)
	default:
		// SQLite: ensure the parent directory exists (the file itself is created by Open).
		filePath := strings.TrimPrefix(dsn, "sqlite://")
		if filePath != "" && filePath != ":memory:" {
			dir := filepath.Dir(filePath)
			if dir != "" && dir != "." {
				if err := os.MkdirAll(dir, 0755); err != nil {
					return res, fmt.Errorf("create sqlite dir %q: %w", dir, err)
				}
			}
		}
		res.Driver = "sqlite"
		return res, nil
	}
}

// isRawMySQLDSN checks whether the DSN is a bare MySQL driver DSN without a URL prefix.
// Characteristic: contains @tcp(...) or @unix(...) network addresses (SQLite paths cannot contain these).
func isRawMySQLDSN(dsn string) bool {
	return strings.Contains(dsn, "@tcp(") || strings.Contains(dsn, "@unix(")
}

// createPGDatabase connects to the postgres maintenance database and ensures the target database exists.
func createPGDatabase(dsn string, res createDatabaseResult) (createDatabaseResult, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return res, fmt.Errorf("parse postgres dsn: %w", err)
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" {
		return res, fmt.Errorf("postgres dsn missing database name: %s", dsn)
	}
	if !validIdentifier(dbName) {
		return res, fmt.Errorf("invalid postgres database name %q", dbName)
	}

	// Connect to postgres maintenance database (same credentials, same host).
	admin := *u
	admin.Path = "/postgres"
	db, err := sql.Open("pgx", admin.String())
	if err != nil {
		return res, fmt.Errorf("connect postgres admin: %w", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return res, fmt.Errorf("ping postgres admin: %w", err)
	}

	var exists bool
	if err := db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", dbName,
	).Scan(&exists); err != nil {
		return res, fmt.Errorf("check postgres database: %w", err)
	}
	if exists {
		res.Database = dbName
		res.Driver = "pgx"
		return res, nil
	}

	// CREATE DATABASE does not support parameter placeholders; the identifier has been validated via validIdentifier.
	if _, err := db.Exec("CREATE DATABASE " + dbName); err != nil {
		return res, fmt.Errorf("create postgres database %q: %w", dbName, err)
	}
	res.Created = true
	res.Database = dbName
	res.Driver = "pgx"
	return res, nil
}

// createMySQLDatabase connects to the MySQL server (without a database name) and ensures the target database exists.
func createMySQLDatabase(dsn string, res createDatabaseResult) (createDatabaseResult, error) {
	raw := dsn
	// Support both URL form and raw driver DSN.
	if strings.HasPrefix(dsn, "mysql://") || strings.HasPrefix(dsn, "mariadb://") {
		raw = MySQLURLToDSN(dsn)
	}
	// Extract the database name and admin DSN without database.
	dbName, adminDSN, err := splitMySQLDSN(raw)
	if err != nil {
		return res, err
	}

	db, err := sql.Open("mysql", adminDSN)
	if err != nil {
		return res, fmt.Errorf("connect mysql admin: %w", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return res, fmt.Errorf("ping mysql admin: %w", err)
	}

	var exists int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?", dbName,
	).Scan(&exists); err != nil {
		return res, fmt.Errorf("check mysql database: %w", err)
	}
	if exists > 0 {
		res.Database = dbName
		res.Driver = "mysql"
		return res, nil
	}

	if _, err := db.Exec("CREATE DATABASE IF NOT EXISTS `" + dbName + "`"); err != nil {
		return res, fmt.Errorf("create mysql database %q: %w", dbName, err)
	}
	res.Created = true
	res.Database = dbName
	res.Driver = "mysql"
	return res, nil
}

// splitMySQLDSN separates the database name from the admin DSN (without database) in a raw DSN.
// Input example: user:pass@tcp(host:3306)/pki?charset=utf8mb4&parseTime=true
//
//	u@unix(/tmp/mysql.sock)/mydb?parseTime=true
//
// Output: ("pki", "user:pass@tcp(host:3306)/?charset=utf8mb4&parseTime=true")
func splitMySQLDSN(dsn string) (string, string, error) {
	// Match the /dbname after the address portion (which may contain a socket path with / inside tcp/unix parentheses).
	m := mysqlAddrRe.FindStringSubmatch(dsn)
	if m == nil {
		return "", "", fmt.Errorf("mysql dsn missing database name: %s", dsn)
	}
	dbPart := m[2]
	if dbPart == "" {
		return "", "", fmt.Errorf("mysql dsn missing database name: %s", dsn)
	}
	dbName := dbPart
	params := ""
	if idx := strings.Index(dbPart, "?"); idx >= 0 {
		dbName = dbPart[:idx]
		params = dbPart[idx:]
	}
	if !validIdentifier(dbName) {
		return "", "", fmt.Errorf("invalid mysql database name %q", dbName)
	}
	adminDSN := m[1] + "/" + params
	return dbName, adminDSN, nil
}

// mysqlAddrRe matches the MySQL DSN address prefix + dbname:
//
//	group1 = user:pass@tcp(host:port)  or  user@unix(/path/to.sock)
//	group2 = dbname?params
var mysqlAddrRe = regexp.MustCompile(`^(.+@(?:tcp|unix)\([^)]*\))/([^/]*)$`)

var identRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// validIdentifier validates that a database name contains only alphanumeric characters and underscores (prevents SQL injection).
func validIdentifier(s string) bool {
	return s != "" && identRe.MatchString(s)
}
