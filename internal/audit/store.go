package audit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Store is a per-client, append-only, hash-chained audit log.
type Store interface {
	// Append seals e onto the end of e.Client's chain and persists it
	// durably before returning. On success e carries its N, PrevHash and
	// Hash. Callers must not return content to the AI until Append succeeds.
	Append(ctx context.Context, e *Entry) error
	// Range calls fn for each of client's entries with from <= Time < to,
	// in chain order. A zero from or to is an open bound.
	Range(ctx context.Context, client string, from, to time.Time, fn func(Entry) error) error
	// Verify walks client's whole chain and reports the first break.
	Verify(ctx context.Context, client string) (VerifyResult, error)
}

// VerifyResult is the outcome of walking one client's chain.
type VerifyResult struct {
	Client  string `json:"client"`
	Entries uint64 `json:"entries"`
	OK      bool   `json:"ok"`
	BadAt   uint64 `json:"bad_at,omitempty"` // N of the first entry that fails
	Reason  string `json:"reason,omitempty"`
	Head    string `json:"head,omitempty"` // Hash of the last good entry
}

// Verifier checks a chain one entry at a time, so a Store can verify a long
// chain without holding it in memory.
type Verifier struct {
	res  VerifyResult
	prev *Entry
}

func NewVerifier(client string) *Verifier {
	return &Verifier{res: VerifyResult{Client: client, OK: true}}
}

// Next checks e against the entries seen so far. It returns false once the
// chain is broken; later calls are ignored.
func (v *Verifier) Next(e Entry) bool {
	if !v.res.OK {
		return false
	}
	fail := func(format string, args ...any) bool {
		v.res.OK, v.res.BadAt, v.res.Reason = false, e.N, fmt.Sprintf(format, args...)
		return false
	}
	wantN, wantPrev := uint64(1), GenesisHash(v.res.Client)
	if v.prev != nil {
		wantN, wantPrev = v.prev.N+1, v.prev.Hash
	}
	switch {
	case e.Client != v.res.Client:
		return fail("entry for client %q in %q's chain", e.Client, v.res.Client)
	case e.N != wantN:
		return fail("sequence gap: want n=%d, got n=%d", wantN, e.N)
	case e.PrevHash != wantPrev:
		return fail("prev_hash does not match the previous entry")
	}
	h, err := e.ComputeHash()
	if err != nil {
		return fail("%v", err)
	}
	if h != e.Hash {
		return fail("hash mismatch: entry was altered")
	}
	cp := e
	v.prev = &cp
	v.res.Entries = e.N
	v.res.Head = e.Hash
	return true
}

// Result returns the verification outcome so far.
func (v *Verifier) Result() VerifyResult { return v.res }

// MemStore is an in-memory Store for tests.
type MemStore struct {
	mu     sync.Mutex
	chains map[string][]Entry
}

func NewMemStore() *MemStore { return &MemStore{chains: map[string][]Entry{}} }

func (m *MemStore) Append(_ context.Context, e *Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	chain := m.chains[e.Client]
	var prev *Entry
	if len(chain) > 0 {
		prev = &chain[len(chain)-1]
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if err := Seal(e, prev); err != nil {
		return err
	}
	m.chains[e.Client] = append(chain, *e)
	return nil
}

func (m *MemStore) Range(ctx context.Context, client string, from, to time.Time, fn func(Entry) error) error {
	m.mu.Lock()
	chain := append([]Entry(nil), m.chains[client]...)
	m.mu.Unlock()
	for _, e := range chain {
		if err := ctx.Err(); err != nil {
			return err
		}
		if (!from.IsZero() && e.Time.Before(from)) || (!to.IsZero() && !e.Time.Before(to)) {
			continue
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func (m *MemStore) Verify(_ context.Context, client string) (VerifyResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := NewVerifier(client)
	for _, e := range m.chains[client] {
		if !v.Next(e) {
			break
		}
	}
	return v.Result(), nil
}

// Tamper replaces entry n (1-based) of client's chain without resealing it.
// It exists so tests can prove Verify catches edits.
func (m *MemStore) Tamper(client string, n uint64, edit func(*Entry)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	edit(&m.chains[client][n-1])
}
