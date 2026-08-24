// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"fmt"
	"strings"
)

type migration struct {
	version int
	up      string
	down    string
}

var migrations = []migration{
	{
		version: 1,
		up: `
	CREATE TABLE IF NOT EXISTS ca_meta (
	    name            VARCHAR(255) NOT NULL PRIMARY KEY,
	    cert_der        __BLOB__ NOT NULL,
	    subject         TEXT NOT NULL,
	    not_before      TEXT NOT NULL,
	    not_after       TEXT NOT NULL,
	    key_algorithm   TEXT NOT NULL,
	    fingerprint     TEXT NOT NULL,
	    key_encrypted   __BLOB__
	);

	CREATE TABLE IF NOT EXISTS certificates (
	    serial_number   VARCHAR(255) NOT NULL,
	    ca_name         VARCHAR(255) NOT NULL,
	    status          TEXT NOT NULL DEFAULT 'V',
	    subject         TEXT NOT NULL,
	    common_name     TEXT,
	    not_before      TEXT NOT NULL,
	    not_after       TEXT NOT NULL,
	    revoked_at      TEXT,
	    revoke_reason   INTEGER,
	    cert_der        __BLOB__ NOT NULL,
	    fingerprint     TEXT NOT NULL,
	    invalidity_date TEXT,
	    subject_o       TEXT,
	    subject_c       TEXT,
	    issuer_dn       TEXT,
	    key_algo        VARCHAR(32),
	    key_size        INTEGER,
	    sig_algo        VARCHAR(64),
	    ski             VARCHAR(64),
	    aki             VARCHAR(64),
	    san             TEXT,
	    profile_used    VARCHAR(64),
	    spki_hash       TEXT NOT NULL DEFAULT '',
	    principal_uid   TEXT NOT NULL DEFAULT '',
	    agent_id        TEXT NOT NULL DEFAULT '',
	    PRIMARY KEY (ca_name, serial_number)
	);

	CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
	CREATE INDEX IF NOT EXISTS idx_certificates_subject_o ON certificates(subject_o);
	CREATE INDEX IF NOT EXISTS idx_certificates_ski ON certificates(ski);
	CREATE INDEX IF NOT EXISTS idx_certificates_key_algo ON certificates(key_algo);
	CREATE INDEX IF NOT EXISTS idx_certificates_san ON certificates(san);
	CREATE INDEX IF NOT EXISTS idx_certificates_ca_status ON certificates(ca_name, status __TEXTIDX__);
	CREATE INDEX IF NOT EXISTS idx_certificates_spki_hash ON certificates(spki_hash);
	CREATE INDEX IF NOT EXISTS idx_certificates_principal_uid ON certificates(principal_uid);
	CREATE INDEX IF NOT EXISTS idx_certificates_ca_notbefore ON certificates(ca_name, not_before __TEXTIDX__);
	CREATE INDEX IF NOT EXISTS idx_certificates_ca_cn_status ON certificates(ca_name, common_name __TEXTIDX__, status __TEXTIDX__);

	CREATE TABLE IF NOT EXISTS _migrations (
	    version         INTEGER NOT NULL PRIMARY KEY,
	    applied_at      TEXT NOT NULL DEFAULT __NOW__
	);

	CREATE TABLE IF NOT EXISTS key_escrow (
	    ca_name         VARCHAR(255) NOT NULL,
	    serial_number   VARCHAR(255) NOT NULL,
	    encrypted_key   __BLOB__ NOT NULL,
	    PRIMARY KEY (ca_name, serial_number)
	);

	CREATE TABLE IF NOT EXISTS ct_logs (
	    ca_name         VARCHAR(255) NOT NULL,
	    serial_number   VARCHAR(255) NOT NULL,
	    sct_version     INTEGER NOT NULL,
	    log_id          TEXT NOT NULL,
	    timestamp       INTEGER NOT NULL,
	    signature       __BLOB__ NOT NULL,
	    PRIMARY KEY (ca_name, serial_number)
	);

	CREATE TABLE IF NOT EXISTS acme_accounts (
	    id              __AUTO__,
	    jwk_thumbprint  VARCHAR(255) NOT NULL UNIQUE,
	    jwk_json        TEXT NOT NULL DEFAULT '',
	    contact         TEXT NOT NULL DEFAULT '',
	    status          TEXT NOT NULL DEFAULT 'valid',
	    created_at      TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS acme_orders (
	    id              __AUTO__,
	    account_id      INTEGER NOT NULL,
	    status          TEXT NOT NULL DEFAULT 'pending',
	    identifiers     TEXT NOT NULL,
	    not_before      TEXT,
	    not_after       TEXT,
	    expires         TEXT NOT NULL,
	    created_at      TEXT NOT NULL,
	    FOREIGN KEY (account_id) REFERENCES acme_accounts(id)
	);

	CREATE TABLE IF NOT EXISTS acme_authorizations (
	    id              __AUTO__,
	    order_id        INTEGER NOT NULL,
	    identifier_type TEXT NOT NULL,
	    identifier_value TEXT NOT NULL,
	    status          TEXT NOT NULL DEFAULT 'pending',
	    token           TEXT NOT NULL,
	    expires         TEXT NOT NULL,
	    created_at      TEXT NOT NULL,
	    FOREIGN KEY (order_id) REFERENCES acme_orders(id)
	);

	CREATE TABLE IF NOT EXISTS acme_challenges (
	    id              __AUTO__,
	    authz_id        INTEGER NOT NULL,
	    type            TEXT NOT NULL DEFAULT 'http-01',
	    token           TEXT NOT NULL,
	    status          TEXT NOT NULL DEFAULT 'pending',
	    validated_at    TEXT,
	    FOREIGN KEY (authz_id) REFERENCES acme_authorizations(id)
	);

	CREATE TABLE IF NOT EXISTS acme_cert_orders (
	    id              __AUTO__,
	    order_id        INTEGER NOT NULL UNIQUE,
	    cert_der        __BLOB__,
	    serial_number   TEXT,
	    ca_name         TEXT,
	    created_at      TEXT NOT NULL,
	    cert_sha256     TEXT NOT NULL DEFAULT '',
	    FOREIGN KEY (order_id) REFERENCES acme_orders(id)
	);

	CREATE TABLE IF NOT EXISTS rbac_users (
	    id __AUTO__,
	    username VARCHAR(255) NOT NULL UNIQUE,
	    password_hash TEXT NOT NULL,
	    salt TEXT NOT NULL DEFAULT '',
	    role TEXT NOT NULL DEFAULT 'operator',
	    created_at TEXT NOT NULL DEFAULT __NOW__,
	    enabled INTEGER NOT NULL DEFAULT 1,
	    ca_scopes TEXT DEFAULT '',
	    operator_cert_pem TEXT DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS rbac_api_tokens (
	    id __AUTO__,
	    user_id INTEGER NOT NULL REFERENCES rbac_users(id),
	    token VARCHAR(255) NOT NULL UNIQUE,
	    description TEXT,
	    created_at TEXT NOT NULL DEFAULT __NOW__,
	    expires_at TEXT
	);

	CREATE TABLE IF NOT EXISTS audit_log (
	    id __AUTO__,
	    timestamp TEXT NOT NULL DEFAULT __NOW__,
	    username TEXT,
	    remote_addr TEXT,
	    method TEXT,
	    path TEXT,
	    action TEXT,
	    detail TEXT,
	    entry_hash TEXT,
	    prev_hash TEXT
	);

	CREATE TABLE IF NOT EXISTS ra_requests (
	    id __AUTO__,
	    csr_der __BLOB__ NOT NULL,
	    common_name VARCHAR(255) NOT NULL,
	    san_list TEXT,
	    profile TEXT NOT NULL DEFAULT 'tls-server',
	    ca_name TEXT NOT NULL DEFAULT 'issuing',
	    status TEXT NOT NULL DEFAULT 'pending',
	    requester VARCHAR(255) NOT NULL,
	    requested_at TEXT NOT NULL DEFAULT __NOW__,
	    issued_serial TEXT,
	    issued_at TEXT,
	    reject_reason TEXT,
	    required_approvals INTEGER NOT NULL DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS ra_approvals (
	    id __AUTO__,
	    request_id INTEGER NOT NULL REFERENCES ra_requests(id),
	    approver VARCHAR(255) NOT NULL,
	    decision TEXT NOT NULL,
	    comment TEXT,
	    decided_at TEXT NOT NULL DEFAULT __NOW__,
	    UNIQUE(request_id, approver)
	);

	CREATE TABLE IF NOT EXISTS webhook_subscriptions (
	    id __AUTO__,
	    url VARCHAR(512) NOT NULL,
	    events TEXT NOT NULL DEFAULT 'issue,revoke,expiry',
	    enabled INTEGER NOT NULL DEFAULT 1,
	    created TEXT NOT NULL DEFAULT __NOW__
	);

	CREATE TABLE IF NOT EXISTS cross_certs (
	    issuer_ca     VARCHAR(255) NOT NULL,
	    subject_ca    VARCHAR(255) NOT NULL,
	    cert_der      __BLOB__ NOT NULL,
	    not_before    TEXT NOT NULL,
	    not_after     TEXT NOT NULL,
	    serial_number VARCHAR(255) NOT NULL,
	    fingerprint   VARCHAR(255) NOT NULL,
	    status        TEXT NOT NULL DEFAULT 'V',
	    revoked_at    TEXT,
	    revoke_reason INTEGER,
	    PRIMARY KEY (issuer_ca, serial_number)
	);

	CREATE TABLE IF NOT EXISTS trust_anchors (
	    id          __AUTO__,
	    name        VARCHAR(255) NOT NULL,
	    hash_id     VARCHAR(255) NOT NULL,
	    cert_der    __BLOB__ NOT NULL,
	    subject     TEXT NOT NULL,
	    not_before  TEXT NOT NULL,
	    not_after   TEXT NOT NULL,
	    issuer      TEXT NOT NULL,
	    trusted     INTEGER NOT NULL DEFAULT 1,
	    source      VARCHAR(64) DEFAULT 'curl',
	    imported_at TEXT NOT NULL DEFAULT __NOW__,
	    subject_o   TEXT,
	    subject_c   TEXT,
	    key_algo    VARCHAR(32),
	    key_size    INTEGER,
	    sha1_fingerprint VARCHAR(64),
	    path_len    INTEGER DEFAULT -1,
	    UNIQUE(hash_id)
	);

	CREATE INDEX IF NOT EXISTS idx_trust_anchors_trusted_source ON trust_anchors(trusted, source);
	CREATE INDEX IF NOT EXISTS idx_trust_anchors_subject_o ON trust_anchors(subject_o);
	CREATE INDEX IF NOT EXISTS idx_trust_anchors_key_algo ON trust_anchors(key_algo);

	CREATE TABLE IF NOT EXISTS cert_archive (
	    serial_number   VARCHAR(255) NOT NULL,
	    ca_name         VARCHAR(255) NOT NULL,
	    status          TEXT NOT NULL DEFAULT 'V',
	    subject         TEXT NOT NULL,
	    common_name     TEXT,
	    not_before      TEXT NOT NULL,
	    not_after       TEXT NOT NULL,
	    revoked_at      TEXT,
	    revoke_reason   INTEGER,
	    invalidity_date TEXT,
	    cert_der        __BLOB__,
	    fingerprint     TEXT NOT NULL,
	    subject_o       TEXT,
	    subject_c       TEXT,
	    issuer_dn       TEXT,
	    key_algo        VARCHAR(32),
	    key_size        INTEGER,
	    sig_algo        VARCHAR(64),
	    ski             VARCHAR(64),
	    aki             VARCHAR(64),
	    san             TEXT,
	    profile_used    VARCHAR(64),
	    archived_at     TEXT NOT NULL DEFAULT __NOW__,
	    spki_hash       TEXT NOT NULL DEFAULT '',
	    principal_uid   TEXT NOT NULL DEFAULT '',
	    agent_id        TEXT NOT NULL DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_cert_archive_ca_name ON cert_archive(ca_name);
	CREATE INDEX IF NOT EXISTS idx_cert_archive_status ON cert_archive(status);
	CREATE INDEX IF NOT EXISTS idx_cert_archive_not_after ON cert_archive(not_after);
	CREATE INDEX IF NOT EXISTS idx_cert_archive_archived_at ON cert_archive(archived_at);

	CREATE TABLE IF NOT EXISTS scep_requests (
	    transaction_id  VARCHAR(255) NOT NULL PRIMARY KEY,
	    ca_name         VARCHAR(255) NOT NULL,
	    serial_number   VARCHAR(255) NOT NULL,
	    cert_der        __BLOB__ NOT NULL,
	    issuer_der      __BLOB__ NOT NULL,
	    created_at      TEXT NOT NULL DEFAULT __NOW__
	);
	CREATE INDEX IF NOT EXISTS idx_scep_requests_ca_serial ON scep_requests(ca_name, serial_number);

	CREATE TABLE IF NOT EXISTS renewal_tokens (
	    nonce    __NONCE__ NOT NULL PRIMARY KEY,
	    used     INTEGER NOT NULL DEFAULT 0,
	    created  TEXT NOT NULL DEFAULT __NOW__
	);
	CREATE INDEX IF NOT EXISTS idx_renewal_tokens_used ON renewal_tokens(used);

	CREATE TABLE IF NOT EXISTS gateway_registry (
	    id         __AUTO__,
	    address    VARCHAR(512) NOT NULL UNIQUE,
	    ca_name    VARCHAR(255) NOT NULL DEFAULT '',
	    status     VARCHAR(32) NOT NULL DEFAULT 'active',
	    last_seen  TEXT NOT NULL DEFAULT __NOW__,
	    registered TEXT NOT NULL DEFAULT __NOW__
	);
	CREATE INDEX IF NOT EXISTS idx_gateway_registry_status ON gateway_registry(status);

	CREATE TABLE IF NOT EXISTS sub_cas (
	    id              __AUTO__,
	    name            VARCHAR(255) NOT NULL UNIQUE,
	    parent_ca       VARCHAR(255) NOT NULL,
	    cert_der        __BLOB__ NOT NULL,
	    key_encrypted   __BLOB__,
	    subject         TEXT NOT NULL,
	    not_before      TEXT NOT NULL,
	    not_after       TEXT NOT NULL,
	    key_algorithm   TEXT NOT NULL,
	    fingerprint     TEXT NOT NULL,
	    status          TEXT NOT NULL DEFAULT 'active',
	    protocol        TEXT NOT NULL DEFAULT '',
	    key_usage       TEXT NOT NULL DEFAULT '',
	    max_path_len    INTEGER NOT NULL DEFAULT 0,
	    created_at      TEXT NOT NULL DEFAULT __NOW__,
	    revoked_at      TEXT,
	    revoke_reason   INTEGER
	);
	CREATE INDEX IF NOT EXISTS idx_sub_cas_parent ON sub_cas(parent_ca);
	CREATE INDEX IF NOT EXISTS idx_sub_cas_status ON sub_cas(status);
	CREATE INDEX IF NOT EXISTS idx_sub_cas_protocol ON sub_cas(protocol);

	CREATE TABLE IF NOT EXISTS audit_salts (
	    day      VARCHAR(16) NOT NULL PRIMARY KEY,
	    salt     VARCHAR(64) NOT NULL,
	    created  TEXT NOT NULL DEFAULT __NOW__
	);

	CREATE TABLE IF NOT EXISTS aic_extensions (
	    id                __AUTO__,
	    ca_name           TEXT NOT NULL,
	    serial_number     TEXT NOT NULL,
	    agent_id          TEXT NOT NULL,
	    principal_uid     TEXT NOT NULL,
	    capabilities_json TEXT NOT NULL DEFAULT '[]',
	    delegation_auth_json TEXT,
	    aic_json          TEXT NOT NULL DEFAULT '{}',
	    created_at        TEXT NOT NULL DEFAULT __NOW__
	);
	CREATE INDEX IF NOT EXISTS idx_aic_ext_ca_serial ON aic_extensions(ca_name __TEXTIDX__, serial_number __TEXTIDX__);
	CREATE INDEX IF NOT EXISTS idx_aic_ext_agent ON aic_extensions(agent_id __TEXTIDX__);
	CREATE INDEX IF NOT EXISTS idx_aic_ext_principal ON aic_extensions(principal_uid __TEXTIDX__);

	CREATE TABLE IF NOT EXISTS da_nonces (
	    nonce    __NONCE32__ NOT NULL PRIMARY KEY,
	    created  TEXT NOT NULL DEFAULT __NOW__
	);

	CREATE TABLE IF NOT EXISTS crl_number_state (
	    ca_name    VARCHAR(255) NOT NULL PRIMARY KEY,
	    last_number INTEGER NOT NULL DEFAULT 0,
	    updated_at  TEXT NOT NULL DEFAULT __NOW__
	);
	`,
		down: `
	DROP TABLE IF EXISTS crl_number_state;
	DROP TABLE IF EXISTS da_nonces;
	DROP INDEX IF EXISTS idx_aic_ext_principal;
	DROP INDEX IF EXISTS idx_aic_ext_agent;
	DROP INDEX IF EXISTS idx_aic_ext_ca_serial;
	DROP TABLE IF EXISTS aic_extensions;
	DROP TABLE IF EXISTS audit_salts;
	DROP INDEX IF EXISTS idx_sub_cas_protocol;
	DROP INDEX IF EXISTS idx_sub_cas_status;
	DROP INDEX IF EXISTS idx_sub_cas_parent;
	DROP TABLE IF EXISTS sub_cas;
	DROP INDEX IF EXISTS idx_gateway_registry_status;
	DROP TABLE IF EXISTS gateway_registry;
	DROP INDEX IF EXISTS idx_renewal_tokens_used;
	DROP TABLE IF EXISTS renewal_tokens;
	DROP INDEX IF EXISTS idx_scep_requests_ca_serial;
	DROP TABLE IF EXISTS scep_requests;
	DROP INDEX IF EXISTS idx_cert_archive_archived_at;
	DROP INDEX IF EXISTS idx_cert_archive_not_after;
	DROP INDEX IF EXISTS idx_cert_archive_status;
	DROP INDEX IF EXISTS idx_cert_archive_ca_name;
	DROP TABLE IF EXISTS cert_archive;
	DROP INDEX IF EXISTS idx_trust_anchors_key_algo;
	DROP INDEX IF EXISTS idx_trust_anchors_subject_o;
	DROP INDEX IF EXISTS idx_trust_anchors_trusted_source;
	DROP TABLE IF EXISTS trust_anchors;
	DROP TABLE IF EXISTS cross_certs;
	DROP TABLE IF EXISTS webhook_subscriptions;
	DROP TABLE IF EXISTS ra_approvals;
	DROP TABLE IF EXISTS ra_requests;
	DROP TABLE IF EXISTS audit_log;
	DROP TABLE IF EXISTS rbac_api_tokens;
	DROP TABLE IF EXISTS rbac_users;
	DROP TABLE IF EXISTS acme_cert_orders;
	DROP TABLE IF EXISTS acme_challenges;
	DROP TABLE IF EXISTS acme_authorizations;
	DROP TABLE IF EXISTS acme_orders;
	DROP TABLE IF EXISTS acme_accounts;
	DROP TABLE IF EXISTS ct_logs;
	DROP TABLE IF EXISTS key_escrow;
	DROP TABLE IF EXISTS _migrations;
	DROP INDEX IF EXISTS idx_certificates_ca_cn_status;
	DROP INDEX IF EXISTS idx_certificates_ca_notbefore;
	DROP INDEX IF EXISTS idx_certificates_principal_uid;
	DROP INDEX IF EXISTS idx_certificates_spki_hash;
	DROP INDEX IF EXISTS idx_certificates_ca_status;
	DROP INDEX IF EXISTS idx_certificates_san;
	DROP INDEX IF EXISTS idx_certificates_key_algo;
	DROP INDEX IF EXISTS idx_certificates_ski;
	DROP INDEX IF EXISTS idx_certificates_subject_o;
	DROP INDEX IF EXISTS idx_certificates_status;
	DROP TABLE IF EXISTS certificates;
	DROP TABLE IF EXISTS ca_meta;
	`,
	},
}

func SchemaVersion() int {
	if len(migrations) == 0 {
		return 0
	}
	return migrations[len(migrations)-1].version
}

func (d *DB) CurrentVersion() (int, error) {
	var currentVersion int
	err := d.QueryRow(d.Rebind("SELECT COALESCE(MAX(version), 0) FROM _migrations")).Scan(&currentVersion)
	if err != nil {
		return 0, fmt.Errorf("read migration version: %w", err)
	}
	return currentVersion, nil
}

// migrate runs all pending migrations, adapting SQL to the current dialect.
func (d *DB) migrate() error {
	// Ensure _migrations table exists first (v1 creates it, but for PG we need it upfront)
	if d.dialect.DriverName() == "pgx" {
		initSQL := `CREATE TABLE IF NOT EXISTS _migrations (
		    version INTEGER NOT NULL PRIMARY KEY,
		    applied_at TEXT NOT NULL DEFAULT NOW()
		)`
		if _, err := d.Exec(initSQL); err != nil {
			return fmt.Errorf("init migrations table: %w", err)
		}
	}

	// Create all tables at once for the maximum version (idempotent)
	current, err := d.CurrentVersion()
	if err != nil {
		current = 0 // no _migrations table yet → start from scratch
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		adapted := d.adaptSQL(m.up)
		if err := d.execMigrationSQL(adapted); err != nil {
			return fmt.Errorf("migration v%d: %w", m.version, err)
		}
		recordSQL := strings.ReplaceAll("INSERT INTO _migrations (version, applied_at) VALUES (?, __NOW__)", "__NOW__", d.dialect.NowExpr())
		if _, err := d.Exec(d.Rebind(recordSQL), m.version); err != nil {
			return fmt.Errorf("record migration v%d: %w", m.version, err)
		}
	}

	return nil
}

// execMigrationSQL executes migration SQL, splitting multi-statement strings for MySQL.
func (d *DB) execMigrationSQL(sql string) error {
	if d.dialect.DriverName() == "mysql" {
		// MySQL Exec() does not support multiple statements by default,
		// split on semicolons and execute each statement individually.
		statements := splitSQL(sql)
		for _, stmt := range statements {
			if trimmed := strings.TrimSpace(stmt); trimmed != "" {
				if _, err := d.Exec(trimmed); err != nil {
					return err
				}
			}
		}
		return nil
	}
	_, err := d.Exec(sql)
	return err
}

// splitSQL splits a multi-statement SQL string into individual statements.
func splitSQL(sql string) []string {
	var result []string
	current := make([]byte, 0, len(sql))
	for i := 0; i < len(sql); i++ {
		ch := sql[i]
		if ch == '\'' || ch == '"' || ch == '`' {
			current = append(current, ch)
			quote := ch
			for i++; i < len(sql); i++ {
				current = append(current, sql[i])
				if sql[i] == '\\' && i+1 < len(sql) {
					i++
					current = append(current, sql[i])
				} else if sql[i] == quote {
					break
				}
			}
		} else if ch == ';' {
			result = append(result, string(current))
			current = current[:0]
		} else {
			current = append(current, ch)
		}
	}
	if len(current) > 0 {
		result = append(result, string(current))
	}
	return result
}

// MigrateTo performs migration up/down to a specific version.
func (d *DB) MigrateTo(targetVersion int) error {
	currentVersion, err := d.CurrentVersion()
	if err != nil {
		return fmt.Errorf("current version: %w", err)
	}
	if targetVersion == currentVersion {
		return nil
	}
	if targetVersion > currentVersion {
		if targetVersion > SchemaVersion() {
			return fmt.Errorf("target version %d exceeds max schema version %d", targetVersion, SchemaVersion())
		}
		return d.migrateRange(currentVersion, targetVersion)
	}
	// Rollback
	for i := len(migrations) - 1; i >= 0; i-- {
		m := migrations[i]
		if m.version > currentVersion || m.version <= targetVersion {
			continue
		}
		// Delete migration record first (v1 down will drop _migrations table)
		if _, err := d.Exec(d.Rebind("DELETE FROM _migrations WHERE version = ?"), m.version); err != nil {
			return fmt.Errorf("record rollback v%d: %w", m.version, err)
		}
		down := d.adaptSQL(m.down)
		if _, err := d.Exec(down); err != nil {
			return fmt.Errorf("rollback migration v%d: %w", m.version, err)
		}
	}
	return nil
}

// migrateRange runs migrations from fromVersion+1 to targetVersion.
func (d *DB) migrateRange(fromVersion, targetVersion int) error {
	for _, m := range migrations {
		if m.version <= fromVersion {
			continue
		}
		if m.version > targetVersion {
			break
		}
		adapted := d.adaptSQL(m.up)
		if err := d.execMigrationSQL(adapted); err != nil {
			return fmt.Errorf("execute migration %d: %w", m.version, err)
		}
		recordSQL := strings.ReplaceAll("INSERT INTO _migrations (version, applied_at) VALUES (?, __NOW__)", "__NOW__", d.dialect.NowExpr())
		if _, err := d.Exec(d.Rebind(recordSQL), m.version); err != nil {
			return fmt.Errorf("record migration v%d: %w", m.version, err)
		}
	}
	return nil
}

// adaptSQL replaces dialect-specific placeholders in SQL.
func (d *DB) adaptSQL(sql string) string {
	// Handle ALTER TABLE DROP COLUMN for PostgreSQL (not directly supported)
	if d.dialect.DriverName() == "pgx" {
		lines := strings.Split(sql, "\n")
		var filtered []string
		for _, line := range lines {
			if strings.Contains(strings.ToUpper(line), "DROP COLUMN") {
				continue // skip DROP COLUMN for PG
			}
			filtered = append(filtered, line)
		}
		sql = strings.Join(filtered, "\n")
	}

	// Replace placeholders
	dialect := d.dialect
	sql = strings.ReplaceAll(sql, "__AUTO__", dialect.AutoIncrement())
	sql = strings.ReplaceAll(sql, "__BLOB__", dialect.BlobType())
	sql = strings.ReplaceAll(sql, "__NOW__", dialect.NowExpr())
	// __NONCE__ is a fixed 16-byte binary nonce used as a PRIMARY KEY.
	// MySQL/MariaDB cannot index BLOB columns (needs a prefix length), so it
	// uses VARBINARY(16); PostgreSQL uses BYTEA (no BLOB type); SQLite uses BLOB.
	if d.dialect.DriverName() == "mysql" {
		sql = strings.ReplaceAll(sql, "__NONCE__", "VARBINARY(16)")
	} else {
		sql = strings.ReplaceAll(sql, "__NONCE__", dialect.BlobType())
	}
	// __NONCE32__ is the DelegationAuthorization nonce (SIZE(32)) used as a
	// PRIMARY KEY. MySQL uses VARBINARY(32); PostgreSQL BYTEA; SQLite BLOB.
	if d.dialect.DriverName() == "mysql" {
		sql = strings.ReplaceAll(sql, "__NONCE32__", "VARBINARY(32)")
	} else {
		sql = strings.ReplaceAll(sql, "__NONCE32__", dialect.BlobType())
	}
	// __TEXTIDX__ marks a TEXT column inside a CREATE INDEX. MySQL/MariaDB
	// reject composite indexes over full-length TEXT columns (InnoDB 3072-byte
	// limit); a 10-byte prefix is sufficient for the equality lookups these
	// indexes serve. SQLite/PostgreSQL index TEXT columns directly.
	if d.dialect.DriverName() == "mysql" {
		sql = strings.ReplaceAll(sql, "__TEXTIDX__", "(10)")
	} else {
		sql = strings.ReplaceAll(sql, "__TEXTIDX__", "")
	}
	return sql
}
