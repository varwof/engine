// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

// loadPageSize is the batch size for paginated startup rebuilds (certs and AIC
// extensions). Paginating caps peak memory during load instead of materializing
// every row of the full table at once.
const loadPageSize = 1000

// load performs a full in-memory rebuild from the backend database. Memory is
// authoritative after this returns; any later drift converges through idempotent
// backend writes or a future restart.
func (e *Engine) load() error {
	offset := 0
	for {
		certs, err := e.DB().ListAllCertsPage(loadPageSize, offset)
		if err != nil {
			return err
		}
		for _, c := range certs {
			e.certIdx.put(c)
			if c.Status == "R" {
				e.revoked.put(c)
			}
		}
		if len(certs) < loadPageSize {
			break
		}
		offset += len(certs)
	}

	nonces, err := e.DB().ListNonces()
	if err != nil {
		return err
	}
	for _, n := range nonces {
		e.nonces.load(n.Nonce, n.Used, n.Created.Add(e.opts.NonceTTL))
	}

	daNonces, err := e.DB().ListDANonces()
	if err != nil {
		return err
	}
	for _, n := range daNonces {
		// DA nonces are "used" the moment they are stored (spent to mint an
		// AIC); presence in the set is the replay-protection signal.
		e.daNonces.load(n.Nonce, true, n.Created.Add(e.opts.NonceTTL))
	}

	subCas, err := e.DB().ListSubCAs("")
	if err != nil {
		return err
	}
	for _, s := range subCas {
		e.subCas.put(s)
	}

	anchors, err := e.DB().ListTrustAnchors(nil)
	if err != nil {
		return err
	}
	for _, a := range anchors {
		e.trust.put(a)
	}

	users, err := e.DB().ListRBACUsers()
	if err != nil {
		return err
	}
	for i := range users {
		e.users.put(&users[i])
	}

	// Paginate the token rebuild so a large API-token store cannot exhaust
	// memory during startup (finding 17).
	offset = 0
	for {
		tokens, err := e.DB().ListAllTokenHashesPage(loadPageSize, offset)
		if err != nil {
			return err
		}
		for i := range tokens {
			e.tokens.put(tokens[i])
		}
		if len(tokens) < loadPageSize {
			break
		}
		offset += len(tokens)
	}

	offset = 0
	for {
		aics, err := e.DB().ListAICExtensions("", loadPageSize, offset)
		if err != nil {
			return err
		}
		for _, a := range aics {
			e.aic.put(a)
		}
		if len(aics) < loadPageSize {
			break
		}
		offset += len(aics)
	}

	e.loaded.Store(true)
	return nil
}
