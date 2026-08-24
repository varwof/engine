// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// DB wraps sql.DB with dialect-aware operations.
type DB struct {
	*sql.DB
	dialect Dialect
	// path is the original DSN/file path, used to derive an on-disk lock
	// directory for non-PostgreSQL dialects (see NewDistLock). Empty for
	// network databases where it is not applicable.
	path string
}

func (d *DB) Dialect() Dialect { return d.dialect }
func (d *DB) RawDB() *sql.DB   { return d.DB }

// Path returns the original DSN/file path this handle was opened with.
// It is used to detect whether a config reload points at the same underlying
// store (in which case a running engine can be kept without a full rebuild).
func (d *DB) Path() string { return d.path }

// BackupTo creates a consistent online snapshot via SQLite VACUUM INTO.
// For PostgreSQL, this returns an error (use pg_dump instead).
func (d *DB) BackupTo(path string) error {
	sql := d.dialect.VacuumInto(path)
	if sql == "" {
		return fmt.Errorf("backup not supported for this database driver")
	}
	// Use raw DB to bypass the auto-rebind override (VACUUM doesn't use ? params)
	if _, err := d.DB.Exec(sql); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	return nil
}

// CheckpointWAL forces a WAL checkpoint (SQLite only). High-throughput
// issuance can outrun SQLite's auto-checkpoint (which is suppressed by
// concurrent readers), letting pki.db-wal grow unboundedly and slowing every
// subsequent write. Calling this periodically keeps the WAL bounded.
// Non-SQLite drivers are a no-op.
func (d *DB) CheckpointWAL() {
	if d.dialect.DriverName() != "sqlite" {
		return
	}
	if _, err := d.Exec("PRAGMA wal_checkpoint(PASSIVE)"); err != nil {
		slog.Debug("db: wal checkpoint", "error", err)
	}
}

// DialectForDSN returns the appropriate Dialect for a given DSN string.
// Supported: postgres://, mysql://, mariadb://, or anything else → SQLite.
func DialectForDSN(dsn string) Dialect {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return NewPGDialect(PGConfig{DSN: dsn})
	}
	if strings.HasPrefix(dsn, "mysql://") || strings.HasPrefix(dsn, "mariadb://") {
		mysqlDSN := MySQLURLToDSN(dsn)
		return NewMySQLDialect(mysqlDSN)
	}
	return SQLiteDialect{}
}

// Open opens a SQLite database and runs migrations.
// Auto-detects database type from connection string prefix:
//
//	sqlite://                → SQLite (default)
//	postgres:// or postgresql:// → PostgreSQL (pgx)
//	mysql:// or mariadb://      → MySQL/MariaDB
//
// If DATABASE_URL environment variable is set, it takes precedence over path.
func Open(path string) (*DB, error) {
	// Allow DATABASE_URL env var to override config path.
	if env := os.Getenv("DATABASE_URL"); env != "" {
		path = env
	}
	if strings.HasPrefix(path, "postgres://") || strings.HasPrefix(path, "postgresql://") {
		return OpenWithDialect(path, NewPGDialect(PGConfig{DSN: path}))
	}
	if strings.HasPrefix(path, "mysql://") || strings.HasPrefix(path, "mariadb://") {
		dsn := MySQLURLToDSN(path)
		return OpenWithDialect(dsn, NewMySQLDialect(dsn))
	}

	// Strip optional sqlite:// prefix for consistency with other schemes.
	filePath := strings.TrimPrefix(path, "sqlite://")
	return OpenWithDialect(filePath, SQLiteDialect{})
	// OpenWithDialect opens a database with the given dialect and runs migrations.
}

// mysqlURLToDSN converts mysql://user:pass@host:port/dbname?params
// to the go-sql-driver/mysql DSN format: user:pass@tcp(host:port)/dbname?params.
// Also passes through raw driver DSNs (user:pass@tcp(host)/db, user:pass@unix(...)/db).
func MySQLURLToDSN(url string) string {
	rest := url
	for _, prefix := range []string{"mysql://", "mariadb://"} {
		if strings.HasPrefix(rest, prefix) {
			rest = rest[len(prefix):]
			break
		}
	}
	// Check if already in raw driver format (contains @tcp( or @unix()
	if strings.Contains(rest, "@tcp(") || strings.Contains(rest, "@unix(") {
		return rest
	}
	// URL format: user:pass@host:port/dbname or host:port/dbname
	if strings.Contains(rest, "@") {
		// Split userinfo and the rest
		parts := strings.SplitN(rest, "@", 2)
		userinfo := parts[0]
		addrAndDB := parts[1] // "host:port/dbname?params"
		// Split first / to separate address from dbname/params
		if idx := strings.Index(addrAndDB, "/"); idx >= 0 {
			addr := addrAndDB[:idx]
			dbpart := addrAndDB[idx:] // "/dbname?params"
			return userinfo + "@tcp(" + addr + ")" + dbpart
		}
		return userinfo + "@tcp(" + addrAndDB + ")"
	}
	// No @: plain TCP address like "host:port/dbname"
	if idx := strings.Index(rest, "/"); idx >= 0 {
		addr := rest[:idx]
		dbpart := rest[idx:]
		return "tcp(" + addr + ")" + dbpart
	}
	return "tcp(" + rest + ")"
}
func OpenWithDialect(dsn string, d Dialect) (*DB, error) {
	driverName := d.DriverName()
	if driverName == "pgx" || driverName == "mysql" {
		// pgx/stdlib and go-sql-driver/mysql require explicit registration; import ensures it's available
	}

	var db *sql.DB
	var err error
	if driverName == "sqlite" {
		db, err = sql.Open(driverName, dsn+d.OpenSuffix())
	} else {
		db, err = sql.Open(driverName, d.DSN())
	}
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	// Connection pool configuration: prevent connection churn. The SQLite driver (modernc)
	// re-parses and executes ?_pragma= parameters (journal_mode/busy_timeout/synchronous)
	// for every new connection. With the default MaxIdleConns=2, connections are opened/closed
	// frequently under high concurrency, making PRAGMA re-parsing a hot spot
	// (measured CPU profile: 90% of SQL parse time spent in _sqlite3Pragma).
	db.SetMaxOpenConns(200)
	db.SetMaxIdleConns(50)
	db.SetConnMaxIdleTime(10 * time.Minute)

	// Enable foreign keys for SQLite
	if fkSQL := d.EnableFKs(); fkSQL != "" {
		if _, err := db.Exec(fkSQL); err != nil {
			db.Close()
			return nil, fmt.Errorf("enable fk: %w", err)
		}
	}

	result := &DB{db, d, dsn}
	if err := result.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := result.backfillV12(); err != nil {
		slog.Warn("db: v12 backfill incomplete", "error", err)
	}
	return result, nil
}

// backfillV12 parses existing certificates and trust_anchors DER and populates
// the new v12 fields (subject_o, key_algo, ski, etc.).
func (d *DB) backfillV12() error {
	if err := d.backfillCertsV12(); err != nil {
		return err
	}
	return d.backfillTrustAnchorsV12()
}

func (d *DB) backfillCertsV12() error {
	// Only backfill rows missing subject_o
	rows, err := d.Query(`
		SELECT serial_number, ca_name, cert_der
		FROM certificates WHERE subject_o IS NULL`)
	if err != nil {
		return fmt.Errorf("backfill certs query: %w", err)
	}
	defer rows.Close()

	type certKey struct {
		serial string
		ca     string
	}
	var pending []certKey
	var certs []*x509.Certificate
	for rows.Next() {
		var k certKey
		var der []byte
		if err := rows.Scan(&k.serial, &k.ca, &der); err != nil {
			return fmt.Errorf("backfill scan: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		pending = append(pending, k)
		certs = append(certs, cert)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for i, cert := range certs {
		algo, size := pubKeyInfoV12(cert.PublicKey)
		sigAlgo := cert.SignatureAlgorithm.String()
		ski := bytesHexV12(cert.SubjectKeyId)
		aki := bytesHexV12(cert.AuthorityKeyId)
		san := formatSANsV12(cert)
		subjO := subjectFirstV12(cert.Subject.Organization)
		subjC := subjectFirstV12(cert.Subject.Country)
		issuerDN := cert.Issuer.String()

		_, err := d.Exec(`
			UPDATE certificates SET
				subject_o = ?, subject_c = ?, issuer_dn = ?,
				key_algo = ?, key_size = ?, sig_algo = ?,
				ski = ?, aki = ?, san = ?
			WHERE serial_number = ? AND ca_name = ?`,
			subjO, subjC, issuerDN,
			algo, size, sigAlgo,
			ski, aki, san,
			pending[i].serial, pending[i].ca)
		if err != nil {
			return fmt.Errorf("backfill update cert %s/%s: %w",
				pending[i].ca, pending[i].serial, err)
		}
	}
	if len(pending) > 0 {
		slog.Info("db: backfilled certificate fields", "count", len(pending))
	}
	return nil
}

func (d *DB) backfillTrustAnchorsV12() error {
	rows, err := d.Query(`
		SELECT id, cert_der FROM trust_anchors WHERE subject_o IS NULL`)
	if err != nil {
		return fmt.Errorf("backfill trust query: %w", err)
	}
	defer rows.Close()

	type taKey struct{ id int }
	var pending []taKey
	var certs []*x509.Certificate
	for rows.Next() {
		var k taKey
		var der []byte
		if err := rows.Scan(&k.id, &der); err != nil {
			return fmt.Errorf("backfill trust scan: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		pending = append(pending, k)
		certs = append(certs, cert)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for i, cert := range certs {
		algo, size := pubKeyInfoV12(cert.PublicKey)
		h := sha1.Sum(cert.Raw)
		sha1fp := fmt.Sprintf("%x", h)
		subjO := subjectFirstV12(cert.Subject.Organization)
		subjC := subjectFirstV12(cert.Subject.Country)
		pathLen := -1
		if cert.MaxPathLen != 0 || cert.MaxPathLenZero {
			pathLen = cert.MaxPathLen
		}

		_, err := d.Exec(`
			UPDATE trust_anchors SET
				subject_o = ?, subject_c = ?,
				key_algo = ?, key_size = ?,
				sha1_fingerprint = ?, path_len = ?
			WHERE id = ?`,
			subjO, subjC, algo, size, sha1fp, pathLen, pending[i].id)
		if err != nil {
			return fmt.Errorf("backfill update trust %d: %w", pending[i].id, err)
		}
	}
	if len(pending) > 0 {
		slog.Info("db: backfilled trust_anchor fields", "count", len(pending))
	}
	return nil
}

func pubKeyInfoV12(pub any) (algo string, size int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "Unknown", 0
	}
}

func bytesHexV12(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", b)
}

func subjectFirstV12(vals []string) string {
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func formatSANsV12(cert *x509.Certificate) string {
	var parts []string
	for _, dns := range cert.DNSNames {
		parts = append(parts, "DNS:"+dns)
	}
	for _, ip := range cert.IPAddresses {
		parts = append(parts, "IP:"+ip.String())
	}
	for _, email := range cert.EmailAddresses {
		parts = append(parts, "email:"+email)
	}
	return strings.Join(parts, ", ")
}

// Exec overrides sql.DB.Exec with auto-rebind and INSERT OR REPLACE/IGNORE conversion.
func (d *DB) Exec(query string, args ...interface{}) (sql.Result, error) {
	if d.dialect.DriverName() == "pgx" || d.dialect.DriverName() == "mysql" {
		query = adaptInsertSQL(query, d.dialect)
	}
	return d.DB.Exec(d.Rebind(query), args...)
}

// Query overrides sql.DB.Query with auto-rebind.
func (d *DB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return d.DB.Query(d.Rebind(query), args...)
}

// QueryRow overrides sql.DB.QueryRow with auto-rebind.
func (d *DB) QueryRow(query string, args ...interface{}) *sql.Row {
	return d.DB.QueryRow(d.Rebind(query), args...)
}

// RebindDialect transforms ?-style placeholders to match the given dialect.
func RebindDialect(d Dialect, sql string) string {
	if d.DriverName() == "sqlite" || d.DriverName() == "mysql" {
		return sql
	}
	idx := 0
	result := make([]byte, 0, len(sql)*2)
	for i := 0; i < len(sql); i++ {
		if sql[i] == '?' {
			idx++
			ph := fmt.Sprintf("$%d", idx)
			result = append(result, []byte(ph)...)
		} else {
			result = append(result, sql[i])
		}
	}
	return string(result)
}

// adaptInsertSQL converts INSERT OR REPLACE/IGNORE to PG/MySQL syntax.
func adaptInsertSQL(sql string, d Dialect) string {
	sql = strings.TrimSpace(sql)
	switch d.DriverName() {
	case "mysql":
		if strings.HasPrefix(sql, "INSERT OR REPLACE") {
			rest := strings.TrimSpace(sql[len("INSERT OR REPLACE"):])
			if strings.HasPrefix(rest, "INTO ") {
				rest = strings.TrimSpace(rest[len("INTO "):])
			}
			return "REPLACE INTO " + rest
		}
		if strings.HasPrefix(sql, "INSERT OR IGNORE") {
			rest := strings.TrimSpace(sql[len("INSERT OR IGNORE"):])
			if strings.HasPrefix(rest, "INTO ") {
				rest = strings.TrimSpace(rest[len("INTO "):])
			}
			return "INSERT IGNORE INTO " + rest
		}
	case "pgx":
		if strings.HasPrefix(sql, "INSERT OR REPLACE") {
			rest := strings.TrimSpace(sql[len("INSERT OR REPLACE"):])
			if strings.HasPrefix(rest, "INTO ") {
				rest = strings.TrimSpace(rest[len("INTO "):])
			}
			return "INSERT INTO " + rest + " ON CONFLICT DO NOTHING"
		}
		if strings.HasPrefix(sql, "INSERT OR IGNORE") {
			rest := strings.TrimSpace(sql[len("INSERT OR IGNORE"):])
			if strings.HasPrefix(rest, "INTO ") {
				rest = strings.TrimSpace(rest[len("INTO "):])
			}
			return "INSERT INTO " + rest + " ON CONFLICT DO NOTHING"
		}
	}
	return sql
}

// Rebind transforms ?-style placeholders to this DB's dialect format.
func (d *DB) Rebind(sql string) string {
	return RebindDialect(d.dialect, sql)
}

// TxExec adapts INSERT OR REPLACE/IGNORE SQL and executes it within a transaction.
// sql.Tx.Exec() bypasses DB.Exec() conversion, so we need explicit adapt here.
func (d *DB) TxExec(tx *sql.Tx, query string, args ...interface{}) (sql.Result, error) {
	if d.dialect.DriverName() == "pgx" || d.dialect.DriverName() == "mysql" {
		query = adaptInsertSQL(query, d.dialect)
	}
	return tx.Exec(d.Rebind(query), args...)
}

// TxQuery adapts SQL for PG placeholder conversion and executes a query within a transaction.
func (d *DB) TxQuery(tx *sql.Tx, query string, args ...interface{}) (*sql.Rows, error) {
	return tx.Query(d.Rebind(query), args...)
}

// TxQueryRow adapts SQL for PG placeholder conversion and queries a row within a transaction.
func (d *DB) TxQueryRow(tx *sql.Tx, query string, args ...interface{}) *sql.Row {
	return tx.QueryRow(d.Rebind(query), args...)
}

// InsertReturning inserts a row and returns the auto-generated ID.
// Uses LastInsertId for SQLite/MySQL, RETURNING id for PostgreSQL.
func (d *DB) InsertReturning(query string, args ...interface{}) (int64, error) {
	if d.dialect.DriverName() == "pgx" {
		query = d.Rebind(query) + " RETURNING id"
		var id int64
		err := d.QueryRow(query, args...).Scan(&id)
		return id, err
	}
	res, err := d.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// LikeExpr returns a LIKE expression with substring match on both sides.
// Uses || concatenation for SQLite/PG and CONCAT for MySQL.
func (d *DB) LikeExpr(col string) string {
	if d.dialect.DriverName() == "mysql" {
		return col + " LIKE CONCAT('%', ?, '%')"
	}
	return col + " LIKE '%' || ? || '%'"
}
