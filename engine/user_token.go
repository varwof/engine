// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"sync"
	"time"

	"github.com/varwof/engine/db"
)

// userIndex holds the full rbac_users rows resident in memory. Memory is the
// authoritative read source for authentication lookups (username → credential,
// role, CA scopes, enabled flag); the backend table is the persistence target
// and the startup load source. Mutations arrive through the server's write
// path (PutUser / DeleteUserByID) which keeps memory and backend in step.
type userIndex struct {
	mu     sync.RWMutex
	byName map[string]*db.RBACUser
	byID   map[int]*db.RBACUser
}

func newUserIndex() *userIndex {
	return &userIndex{
		byName: make(map[string]*db.RBACUser),
		byID:   make(map[int]*db.RBACUser),
	}
}

func (ix *userIndex) len() int {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return len(ix.byName)
}

func (ix *userIndex) load(users []*db.RBACUser) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	for _, u := range users {
		ix.byName[u.Username] = u
		ix.byID[u.ID] = u
	}
}

func (ix *userIndex) get(username string) *db.RBACUser {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.byName[username]
}

func (ix *userIndex) getByID(id int) *db.RBACUser {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.byID[id]
}

func (ix *userIndex) put(u *db.RBACUser) {
	if u == nil {
		return
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if prev, ok := ix.byID[u.ID]; ok {
		delete(ix.byName, prev.Username)
	}
	ix.byName[u.Username] = u
	ix.byID[u.ID] = u
}

func (ix *userIndex) delete(id int) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if prev, ok := ix.byID[id]; ok {
		delete(ix.byName, prev.Username)
		delete(ix.byID, id)
	}
}

// tokenEntry is the resident form of an rbac_api_tokens row. Only the SHA-256
// token hash is held (raw token material is never cached); ExpiresAt is nil for
// never-expiring tokens.
type tokenEntry struct {
	id        int
	userID    int
	expiresAt *string
}

// tokenIndex holds API tokens keyed by their SHA-256 hash, the same key the
// backend table column uses. Reads enforce expiry and the owning user's enabled
// flag, mirroring db.GetToken's JOIN semantics without any SQL. byID and byUser
// are auxiliary maps so admin deletes by id and password-rotation token
// eviction stay memory-consistent with the backend.
type tokenIndex struct {
	mu     sync.RWMutex
	byHash map[string]*tokenEntry
	byID   map[int]string
	byUser map[int]map[string]struct{}
}

func newTokenIndex() *tokenIndex {
	return &tokenIndex{
		byHash: make(map[string]*tokenEntry),
		byID:   make(map[int]string),
		byUser: make(map[int]map[string]struct{}),
	}
}

func (ix *tokenIndex) len() int {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return len(ix.byHash)
}

func (ix *tokenIndex) load(rows []db.TokenHashRow) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	for _, r := range rows {
		exp := r.ExpiresAt
		ix.byHash[r.TokenHash] = &tokenEntry{id: r.ID, userID: r.UserID, expiresAt: exp}
		ix.byID[r.ID] = r.TokenHash
		if ix.byUser[r.UserID] == nil {
			ix.byUser[r.UserID] = make(map[string]struct{})
		}
		ix.byUser[r.UserID][r.TokenHash] = struct{}{}
	}
}

func (ix *tokenIndex) put(r db.TokenHashRow) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	exp := r.ExpiresAt
	ix.insertLocked(&tokenEntry{id: r.ID, userID: r.UserID, expiresAt: exp}, r.TokenHash)
}

func (ix *tokenIndex) insertLocked(e *tokenEntry, hash string) {
	if prev, ok := ix.byID[e.id]; ok && prev != hash {
		ix.removeLocked(prev)
	}
	ix.byHash[hash] = e
	ix.byID[e.id] = hash
	if ix.byUser[e.userID] == nil {
		ix.byUser[e.userID] = make(map[string]struct{})
	}
	ix.byUser[e.userID][hash] = struct{}{}
}

func (ix *tokenIndex) get(hash string) *tokenEntry {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.byHash[hash]
}

func (ix *tokenIndex) getByID(id int) string {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.byID[id]
}

func (ix *tokenIndex) delete(hash string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.removeLocked(hash)
}

func (ix *tokenIndex) removeLocked(hash string) {
	e, ok := ix.byHash[hash]
	if !ok {
		return
	}
	delete(ix.byHash, hash)
	delete(ix.byID, e.id)
	if m := ix.byUser[e.userID]; m != nil {
		delete(m, hash)
		if len(m) == 0 {
			delete(ix.byUser, e.userID)
		}
	}
}

func (ix *tokenIndex) deleteByID(id int) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if hash := ix.byID[id]; hash != "" {
		ix.removeLocked(hash)
	}
}

func (ix *tokenIndex) deleteByUserID(userID int) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	for hash := range ix.byUser[userID] {
		if e, ok := ix.byHash[hash]; ok {
			delete(ix.byHash, hash)
			delete(ix.byID, e.id)
		}
	}
	delete(ix.byUser, userID)
}

// GetUserByUsername returns the resident user row, db.ErrNoRows-equivalent
// (ErrNotFound) on a miss. Mirrors db.GetUserByUsername semantics.
func (e *Engine) GetUserByUsername(username string) (*db.RBACUser, error) {
	e.tickRead(username != "")
	if u := e.users.get(username); u != nil {
		return u, nil
	}
	return nil, ErrNotFound
}

// GetUserByID returns the resident user row by account id, ErrNotFound on a
// miss. Used by the server's write path to refresh a resident row after an
// id-addressed update.
func (e *Engine) GetUserByID(id int) (*db.RBACUser, error) {
	if u := e.users.getByID(id); u != nil {
		return u, nil
	}
	return nil, ErrNotFound
}

// GetToken resolves an API token from the in-memory index. It enforces the
// token's expiry and the owning account's enabled flag (mirroring db.GetToken's
// JOIN + WHERE clause) and returns the owning user's identity.
func (e *Engine) GetToken(token string) (*db.TokenInfo, error) {
	hash := db.TokenHash(token)
	e.tickRead(true)
	te := e.tokens.get(hash)
	if te == nil {
		return nil, ErrNotFound
	}
	if info, ok := e.validToken(te); ok {
		return info, nil
	}
	return nil, ErrNotFound
}

func (e *Engine) validToken(te *tokenEntry) (*db.TokenInfo, bool) {
	// Compare expiry as time, not as a lexicographic string: RFC3339 values
	// with a non-UTC offset string-compare incorrectly and can outlive their
	// real expiry (finding 19). A value that cannot be parsed is treated as
	// expired (fail-safe).
	if te.expiresAt != nil {
		exp, err := time.Parse(time.RFC3339, *te.expiresAt)
		if err != nil || !exp.After(time.Now()) {
			return nil, false
		}
	}
	u := e.users.getByID(te.userID)
	if u == nil || !u.Enabled {
		return nil, false
	}
	return &db.TokenInfo{UserID: u.ID, Username: u.Username, Role: u.Role}, true
}

// PutUser upserts a user row into the in-memory index. The server calls this
// whenever it mutates a user so memory (authoritative) and the backend table
// stay in step.
func (e *Engine) PutUser(u *db.RBACUser) {
	e.users.put(u)
}

// DeleteUserByID removes a user (and by extension its tokens) from memory.
func (e *Engine) DeleteUserByID(id int) {
	e.users.delete(id)
}

// PutTokenHash upserts an API token into the in-memory index.
func (e *Engine) PutTokenHash(r db.TokenHashRow) {
	e.tokens.put(r)
}

// DeleteTokenByHash removes an API token from memory by its SHA-256 hash.
func (e *Engine) DeleteTokenByHash(hash string) {
	e.tokens.delete(hash)
}

// DeleteTokenByID removes an API token from memory by its primary key.
func (e *Engine) DeleteTokenByID(id int) {
	e.tokens.deleteByID(id)
}

// DeleteTokensByUserID removes every API token belonging to the account. The
// server calls it to mirror db.UpdateUserPassword / db.DeleteUser, which also
// clear the account's tokens in the backend.
func (e *Engine) DeleteTokensByUserID(userID int) {
	e.tokens.deleteByUserID(userID)
}
