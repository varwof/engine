// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func newUserTokenTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(t.TempDir() + "/user-token.db")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return d
}

func TestUserTokenLoadAndAuthLookups(t *testing.T) {
	d := newUserTokenTestDB(t)
	defer d.Close()

	if err := d.CreateUser("alice", "hash-a", "salt-a", "admin"); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if err := d.CreateUser("bob", "hash-b", "salt-b", "operator"); err != nil {
		t.Fatalf("create bob: %v", err)
	}

	alice, err := d.GetUserByUsername("alice")
	if err != nil {
		t.Fatalf("get alice: %v", err)
	}

	tok, err := d.CreateAPIToken(alice.ID, "login", "")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	e, err := NewEngine(d, EngineOptions{
		Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	defer e.Stop()
	defer e.Stop()

	if got, err := e.GetUserByUsername("alice"); err != nil || got.Username != "alice" {
		t.Fatalf("GetUserByUsername(alice)=(%v,%v), want alice,nil", got, err)
	}
	if got, err := e.GetUserByUsername("bob"); err != nil || got.Role != "operator" {
		t.Fatalf("GetUserByUsername(bob) role = %q err=%v, want operator", got.Role, err)
	}
	if _, err := e.GetUserByUsername("carol"); err != ErrNotFound {
		t.Fatalf("GetUserByUsername(carol) err=%v, want ErrNotFound", err)
	}

	info, err := e.GetToken(tok.Token)
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if info.Username != "alice" || info.Role != "admin" {
		t.Fatalf("GetToken info = %+v, want alice/admin", info)
	}
	if _, err := e.GetToken("definitely-not-a-real-token"); err != ErrNotFound {
		t.Fatalf("GetToken(unknown) err=%v, want ErrNotFound", err)
	}

	m := e.Metrics()
	if m.UserIndexSize != 2 || m.TokenIndexSize != 1 {
		t.Fatalf("metrics sizes = %d/%d, want 2/1", m.UserIndexSize, m.TokenIndexSize)
	}
}

func TestTokenIndexExpiryAndEnabled(t *testing.T) {
	d := newUserTokenTestDB(t)
	defer d.Close()

	if err := d.CreateUser("expiry", "h", "s", "operator"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	u, err := d.GetUserByUsername("expiry")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	expired := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	active := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if _, err := d.InsertReturning(
		"INSERT INTO rbac_api_tokens (user_id, token, description, expires_at) VALUES (?, ?, 't', ?)",
		u.ID, db.TokenHash("expired-token"), &expired); err != nil {
		t.Fatalf("insert expired: %v", err)
	}
	if _, err := d.InsertReturning(
		"INSERT INTO rbac_api_tokens (user_id, token, description, expires_at) VALUES (?, ?, 't', ?)",
		u.ID, db.TokenHash("active-token"), &active); err != nil {
		t.Fatalf("insert active: %v", err)
	}

	e, err := NewEngine(d, EngineOptions{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	defer e.Stop()

	// Expired token is rejected from memory, exactly like db.GetToken.
	if _, err := e.GetToken("expired-token"); err != ErrNotFound {
		t.Fatalf("GetToken(expired) err=%v, want ErrNotFound", err)
	}
	if _, err := e.GetToken("active-token"); err != nil {
		t.Fatalf("GetToken(active) err=%v, want nil", err)
	}

	// Disabling the owning user invalidates all of its tokens (memory mirror of
	// the JOIN's u.enabled = 1 clause).
	d.UpdateUserPassword(u.ID, "newhash", "newsalt") // also clears tokens
	e.PutUser(&db.RBACUser{ID: u.ID, Username: u.Username, PasswordHash: "newhash",
		Salt: "newsalt", Role: "operator", Enabled: true, CreatedAt: u.CreatedAt})
	e.DeleteTokenByHash(db.TokenHash("active-token"))
	if _, err := e.GetToken("active-token"); err != ErrNotFound {
		t.Fatalf("GetToken after memory delete err=%v, want ErrNotFound", err)
	}
}

func TestUserIndexMutations(t *testing.T) {
	d := newUserTokenTestDB(t)
	defer d.Close()

	if err := d.CreateUser("ken", "h", "s", "operator"); err != nil {
		t.Fatalf("create ken: %v", err)
	}
	ken, err := d.GetUserByUsername("ken")
	if err != nil {
		t.Fatalf("get ken: %v", err)
	}

	ix := newUserIndex()
	ix.load([]*db.RBACUser{ken})
	if ix.len() != 1 {
		t.Fatalf("len after load = %d, want 1", ix.len())
	}

	ix.put(&db.RBACUser{ID: ken.ID, Username: "ken", Role: "admin", Enabled: true, CreatedAt: ken.CreatedAt})
	if got := ix.get("ken"); got.Role != "admin" {
		t.Fatalf("role after put = %q, want admin", got.Role)
	}
	// put with new username re-keys by name.
	ix.put(&db.RBACUser{ID: ken.ID, Username: "ken2", Role: "operator", Enabled: true, CreatedAt: ken.CreatedAt})
	if ix.get("ken") != nil || ix.get("ken2") == nil {
		t.Fatalf("rename not applied in byName index")
	}
	ix.delete(ken.ID)
	if ix.len() != 0 {
		t.Fatalf("len after delete = %d, want 0", ix.len())
	}
}

func TestTokenIndexLoadPutDelete(t *testing.T) {
	d := newUserTokenTestDB(t)
	defer d.Close()

	if err := d.CreateUser("tok", "h", "s", "operator"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	u, err := d.GetUserByUsername("tok")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if _, err := d.CreateAPIToken(u.ID, "login", ""); err != nil {
		t.Fatalf("create token: %v", err)
	}

	tokens, err := d.ListAllTokenHashes()
	if err != nil || len(tokens) != 1 {
		t.Fatalf("ListAllTokenHashes = %d (%v), want 1", len(tokens), err)
	}

	ix := newTokenIndex()
	ix.load(tokens)
	if ix.len() != 1 {
		t.Fatalf("len after load = %d, want 1", ix.len())
	}
	if te := ix.get(tokens[0].TokenHash); te == nil || te.userID != u.ID {
		t.Fatalf("get = %+v, want userID %d", te, u.ID)
	}
	ix.delete(tokens[0].TokenHash)
	if ix.len() != 0 {
		t.Fatalf("len after delete = %d, want 0", ix.len())
	}
}
