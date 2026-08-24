// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"sync"

	"github.com/varwof/engine/db"
)

// SubCAIndex is the in-memory sub-CA index, keyed by name with a parent-CA
// reverse index for CA relationship traversal.
type SubCAIndex struct {
	mu       sync.RWMutex
	byName   map[string]*db.SubCAMeta
	children map[string][]string // parent_ca -> sub-CA names
}

// NewSubCAIndex creates an empty sub-CA index.
func NewSubCAIndex() *SubCAIndex {
	return &SubCAIndex{
		byName:   make(map[string]*db.SubCAMeta),
		children: make(map[string][]string),
	}
}

func (i *SubCAIndex) Len() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.byName)
}

func (i *SubCAIndex) put(r *db.SubCAMeta) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.byName[r.Name] = r
	if r.ParentCA != "" {
		found := false
		for _, n := range i.children[r.ParentCA] {
			if n == r.Name {
				found = true
				break
			}
		}
		if !found {
			i.children[r.ParentCA] = append(i.children[r.ParentCA], r.Name)
		}
	}
}

func (i *SubCAIndex) get(name string) (*db.SubCAMeta, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	r, ok := i.byName[name]
	return r, ok
}

// TrustIndex is the in-memory trust-anchor index keyed by numeric id.
type TrustIndex struct {
	mu    sync.RWMutex
	byID  map[int]*db.TrustAnchor
	order []*db.TrustAnchor // stable name order for filtering
}

// NewTrustIndex creates an empty trust-anchor index.
func NewTrustIndex() *TrustIndex {
	return &TrustIndex{byID: make(map[int]*db.TrustAnchor)}
}

func (i *TrustIndex) Len() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.byID)
}

func (i *TrustIndex) put(r *db.TrustAnchor) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if _, ok := i.byID[r.ID]; !ok {
		i.order = append(i.order, r)
	}
	i.byID[r.ID] = r
}

func (i *TrustIndex) get(id int) (*db.TrustAnchor, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	r, ok := i.byID[id]
	return r, ok
}

// aicKey identifies an AIC extension by its certificate.
type aicKey struct {
	ca     string
	serial string
}

// AICIndex is the in-memory AIC extension index, with principal/agent
// secondary lookups.
type AICIndex struct {
	mu      sync.RWMutex
	byCert  map[aicKey]*db.AICExtension
	byAgent map[string][]*db.AICExtension
	byUid   map[string][]*db.AICExtension

	// residentBytes is an estimate of the resident memory of the AIC extension
	// JSON payloads (see estimateAICBytes). Maintained under mu; used for the
	// MaxResidentBytes byte budget and exposed via Metrics.
	residentBytes int64
}

// estimateAICBytes returns an estimate of the resident memory of an AIC
// extension: fixed base overhead plus the JSON payload lengths and index keys.
func estimateAICBytes(a *db.AICExtension) int64 {
	const baseOverhead = 256
	n := int64(baseOverhead) + int64(len(a.CapabilitiesJSON)+len(a.AICJSON))
	n += int64(len(a.CAName) + len(a.SerialNumber) + len(a.AgentID) + len(a.PrincipalUID))
	if a.DelegationAuthJSON != nil {
		n += int64(len(*a.DelegationAuthJSON))
	}
	return n
}

// ResidentBytes returns the estimated resident bytes of the AIC index.
func (i *AICIndex) ResidentBytes() int64 {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.residentBytes
}

// NewAICIndex creates an empty AIC extension index.
func NewAICIndex() *AICIndex {
	return &AICIndex{
		byCert:  make(map[aicKey]*db.AICExtension),
		byAgent: make(map[string][]*db.AICExtension),
		byUid:   make(map[string][]*db.AICExtension),
	}
}

func (i *AICIndex) Len() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.byCert)
}

func (i *AICIndex) put(a *db.AICExtension) {
	i.mu.Lock()
	defer i.mu.Unlock()
	k := aicKey{ca: a.CAName, serial: a.SerialNumber}
	i.byCert[k] = a
	i.residentBytes += estimateAICBytes(a)
	if a.AgentID != "" {
		i.byAgent[a.AgentID] = append(i.byAgent[a.AgentID], a)
	}
	if a.PrincipalUID != "" {
		i.byUid[a.PrincipalUID] = append(i.byUid[a.PrincipalUID], a)
	}
}

func (i *AICIndex) getByCert(ca, serial string) (*db.AICExtension, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	a, ok := i.byCert[aicKey{ca: ca, serial: serial}]
	return a, ok
}

func (i *AICIndex) getByAgent(agent string) []*db.AICExtension {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return append([]*db.AICExtension(nil), i.byAgent[agent]...)
}

func (i *AICIndex) getByUid(uid string) []*db.AICExtension {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return append([]*db.AICExtension(nil), i.byUid[uid]...)
}

// removeByCert drops the AIC extension bound to a certificate from every
// secondary map. Returns true if the extension was present.
func (i *AICIndex) removeByCert(ca, serial string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	k := aicKey{ca: ca, serial: serial}
	a, ok := i.byCert[k]
	if !ok {
		return false
	}
	delete(i.byCert, k)
	i.residentBytes -= estimateAICBytes(a)
	if a.AgentID != "" {
		i.byAgent[a.AgentID] = dropAIC(i.byAgent[a.AgentID], a)
		if len(i.byAgent[a.AgentID]) == 0 {
			delete(i.byAgent, a.AgentID)
		}
	}
	if a.PrincipalUID != "" {
		i.byUid[a.PrincipalUID] = dropAIC(i.byUid[a.PrincipalUID], a)
		if len(i.byUid[a.PrincipalUID]) == 0 {
			delete(i.byUid, a.PrincipalUID)
		}
	}
	return true
}

// dropAIC returns s without the given extension pointer. Order is preserved so
// agent/uid listing stays deterministic.
func dropAIC(s []*db.AICExtension, a *db.AICExtension) []*db.AICExtension {
	for idx, e := range s {
		if e == a {
			return append(s[:idx], s[idx+1:]...)
		}
	}
	return s
}
