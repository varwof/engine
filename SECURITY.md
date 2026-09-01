# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in `varwof/engine`, please do not
open a public issue. Report it privately to
[pki@varwof.com](mailto:pki@varwof.com).

Please include:

- The affected version(s)
- A description of the vulnerability and its impact
- A minimal reproducer if available

You should receive an acknowledgement within a few business days.
We ask that you give us reasonable time to address the issue before
public disclosure.

## Scope

This project is the persistence / state engine for the PKI/CA server
(MySQL / PostgreSQL / SQLite backends). Issues of interest include:

- Revocation, nonce and one-time-token durability (replay / un-revocation
  after crash or restart)
- Sensitive data at rest (private keys, tokens, nonces, audit) in
  plaintext columns
- SQL injection and identifier interpolation
- Audit log tamper-resistance
- Concurrency / write-pipeline data loss and race conditions
- Referential-integrity enforcement per backend

## Supported Versions

Security fixes are applied to the latest release. Older releases are
supported on a best-effort basis.

## Code Review Findings (2026-09-01)

Security / correctness review of the current `main`. All items below
are open and not yet fixed.

The dominant, systemic theme across this codebase: the engine is
"memory-is-authoritative" and persists to the backend through an
asynchronous, error-swallowing, drop-on-shutdown write path. Every
security-critical state transition (revocation, nonce consumption/
insertion) is therefore durable only if the async flush happens before
a crash or shutdown — otherwise the pre-transition state is recovered
on restart. Items 1-5 below are instances of that failure mode.

### Security (high)

1. **Revocation persistence is fire-and-forget; a failed/dropped DB
   write silently un-revokes a cert after restart**
   (`engine/engine.go:227-233` `enqueue`, `:269-273` `runOp`;
   `engine/writes.go:155-160,186-193,208-214`).
   Revocation UPDATEs are submitted to a channel with no error return;
   `runOp` only logs the failure and never retries, and `enqueue` drops
   the op when `ctx` is done. The memory set is rebuilt from the DB on
   startup (`engine/load.go`). Any failure (connection error, shutdown
   race, crash before the writer goroutine runs) leaves the DB row at
   `status='V'`; after restart the revoked cert is valid again and
   re-validates for mTLS/OCSP/CRL. This is the most serious issue.

2. **DA nonce / renewal-token replay after crash on WAL-disabled
   backends (PostgreSQL/MySQL)**
   (`engine/writes.go:283-298`, `:245`). With WAL disabled, `StoreDANonce`
   / `ConsumeNonce` buffer into the batch pipeline; DB convergence is
   deferred to the next flush. A crash before the flush drops the nonce,
   so on restart an empty/partial set is rebuilt and a replayed
   DelegationAuthorization signature is accepted (a second AIC minted) or
   a consumed renewal token reused. Explicitly documented as accepted in
   the code comment (`writes.go:263-271`), but it is the exact
   replay-protection mechanism failing open on crash-recovery.

3. **`rollbackLast` can roll back the wrong record on WAL fsync failure
   (WAL/memory desync)**
   (`recordbuffer/record_buffer.go:524-582`). `AddDANonceSync` appends to
   `rb.records` under `rb.mu` and then fsyncs the WAL under `walMu`,
   holding no lock across both steps. A concurrent `add()` of a cert can
   be appended after the nonce; on fsync failure `rollbackLast` (`:574-582`)
   pops the *last* element (the cert) while the DA nonce's WAL line
   survives without an in-memory record. The nonce this path exists to
   make durable is therefore lost on crash replay — weakening replay
   protection on the crash-safety path itself.

### Medium

4. **Failed revocation write swallowed; no retry / no surface**
   (`engine/engine.go:269-273`; `writes.go:84,189,210`). A
   `WHERE ... AND status='V'` matching zero rows, or a failed connection,
   is invisible to the caller, who already observed a successful revoke
   in memory. Only debug logs reveal it; the DB row stays active.
   Compounds #1; needs a durable/retried revocation path.

5. **All pending security ops dropped on shutdown without error**
   (`engine/engine.go:227-233`). When `ctx` is done, submitted
   revoke/nonce/token ops are not queued and return nothing; a revoke
   concurrent with shutdown is lost deterministically.

6. **DA / renewal nonces logged in plaintext hex**
   (`engine/writes.go:227` `StoreNonce`, `:279` `StoreDANonce`). The full
   one-time replay-protection token is written to logs on backpressure,
   leaking it to anyone with log access and enabling replay of the very
   signatures the nonce protects. Log a truncated hash instead.

7. **Out-of-band DB revocations are invisible to the in-memory read path**
   (`engine/reads.go:28-48,100-132`). `GetCertStatus`, `GetCertStatusByIssuer`
   and CRL generation read only memory; the DB is consulted solely at
   startup (`load.go`). A cert revoked directly in the DB (CLI-via-SQL,
   multi-node, cross-tool backfill) stays `valid` in memory until a full
   restart — authorizing it for mTLS/OCSP/CRL in the interim.

### Medium (data at rest / integrity)

8. **SQLite `PRAGMA foreign_keys = ON` runs on one pooled connection,
   not the pool** (`db/db.go:181,186-191`, `db/dialect.go:74`). The
   single `db.Exec` enables FKs only on that connection; SQLite
   `foreign_keys` is per-connection, and the pool is sized
   `SetMaxOpenConns(200)`/`SetMaxIdleConns(50)`, so most connections
   never get FKs turned on and the referential-integrity guarantees in
   `schema.go` are effectively unenforced for SQLite. (Fix: use
   `?_pragma=foreign_keys(1)` in the DSN / connection init, not one
   Exec.)

9. **Audit hash chain omits method/path/remote_addr**
   (`db/rbac.go:98-101`). `HashAuditEntry` digests only
   `prevHash|timestamp|username|action|detail`. An attacker with DB write
   access can alter `method`/`path`/`remote_addr` without breaking
   tamper detection, since those fields are not covered by the chain.

10. **Audit masking salt stored beside the masked data; plaintext
    fallback turns masking off** (`db/audit_salt.go:56`,
    `db/rbac.go:304-306`). The daily HMAC salt lives in `audit_salts`
    with the `audit_log` rows it masks, so a single dump contains both;
    masking is only time-based unlinkability, not confidentiality. And if
    `LoadOrCreateAuditSalt` fails, `LogAudit` silently stores the
    plaintext username/IP.

11. **ACME challenge / authorization tokens stored in plaintext**
    (`db/schema.go:121,131`, `db/acme.go:140,186`). `acme_challenges.token`
    and `acme_authorizations.token` (HTTP-01 proof-of-control secrets)
    are stored as plaintext TEXT; a DB leak exposes live challenge
    secrets usable to satisfy outstanding authorizations.

12. **File-lock symlink / TOCTOU with predictable paths**
    (`db/lock_file_unix.go:88,75-77,52-59`). `lockPath` derives a
    predictable `varwof-core.lock.<key>` file in the DB dir / `os.TempDir()`;
    `os.OpenFile(O_CREATE|O_RDWR, 0600)` follows symlinks. A local
    attacker writing to that dir can pre-place a symlink so the process
    `flock`s an arbitrary inode. No `O_NOFOLLOW` / `O_EXCL`, no
    ownership/inode re-validation.

13. **Silent `noopLock` downgrade defeats mutual exclusion**
    (`db/lock.go:31`, `db/lock_file_unix.go:44-47`). If `MkdirAll` on the
    lock dir fails, `newFileLock` returns `noopLock` and migration/CRL/
    serial allocation silently lose cross-process coordination, enabling
    duplicate serials / torn schema.

### Low / robustness

14. **`GenerateSalt` uses only 8 random bytes** (`db/rbac.go:76`). Below
    the 16-byte recommendation; in an offline Argon2id attack, per-user
    salt entropy / cross-account reuse is weakened.

15. **LIKE wildcard injection (not SQLi)** (`db/aic.go:127`,
    `db/certs.go:282`, `db/trust_anchor.go:92-93`). Filter strings are
    placed in `LIKE '%...%'` without escaping `%`/`_`; input like `%`
    matches everything, enabling broad result enumeration.

16. **`listGatewaysWhere` interpolates an identifier fragment**
    (`db/gateway_registry.go:85`). `WHERE ` + `where` is concatenated.
    Both current callers pass hardcoded constants, so not exploitable
    today, but it is one refactor away from interpolating untrusted input.

17. **Unbounded full-table reads** (`db/certs.go:191,241,500,599`,
    `db/renewal_tokens.go:89`, `db/da_nonces.go:137`, `db/rbac.go:285`).
    Several paths (`ListCerts`, `GetRevokedCertEntries`,
    `ListAllValidCertRefs`, `ListAllTokenHashes`) materialize every row;
    some feed CA/CRL/OCSP runtime paths and can exhaust memory on large
    stores.

18. **IssueCert can pin a cert to memory without persistence when the
    write buffer is full** (`engine/writes.go:44-49`). `insertIfAbsent`
    succeeds in memory, then `rb.Add` may fail with `ErrBackpressure`;
    the cert is never queued to the DB and the restart drops it.

19. **Token expiry compared lexicographically on RFC3339 strings**
    (`engine/user_token.go:238`). Correct only when every stored
    `expires_at` is UTC RFC3339 with identical formatting; a token created
    with a non-UTC offset compares wrong and can outlive its expiry.

20. **In-memory cache invalidation rests entirely on external wiring**
    (`cache/cache.go:113-176,273-287`). Status / auth-scope caches use
    plain TTL and have no internal coupling to a revocation event; any
    revocation path that misses `PurgeSerial`/`Delete` leaves a
    stale-authorization window until TTL.

21. **WAL truncation race can orphan a WAL line vs its in-memory record**
    (`recordbuffer/record_buffer.go:644-676`). `truncateWALIfIdle`
    truncates when `pending==0`, while `add()` writes WAL lines under
    `walMu` separately from appending under `rb.mu`; a line written just
    before truncation can be cut while its in-memory record survives
    (narrow crash-recovery window, on the crash-safety mechanism).

22. **MySQL FK enforcement disabled by default; multi-host serial race**
    (`db/dialect.go:161,110`). `mysqlDialect.EnableFKs()` returns `""`,
    and the file lock for network `d.path` falls back to a per-host
    `/tmp` dir that does not coordinate across hosts — permitting
    cross-node duplicate serial allocation in multi-instance setups.

### Non-issues (verified clean)

- No reachable classic SQL injection: `?`/`$N` placeholders used
  consistently; pagination uses integer operands.
- CA/sub-CA private keys stored only as `key_encrypted` (AES-256-CBC +
  PBKDF2) / `key_escrow`, not plaintext.
- API tokens are 32-byte `crypto/rand`, stored as (unsalted) SHA-256
  digest only, never logged, not timing-oracle-able.
- Nonce consume is an atomic CAS (`SET used=1 WHERE used=0`) — no
  in-process replay TOCTOU.
- CRL number uses a monotonic `CASE` guard.

### Environment (not a code bug)

23. `go.mod` declares `go 1.26.2` while the available toolchain is
    1.25.10; some analysis tooling fails in this environment.
