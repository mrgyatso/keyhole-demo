package companion

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
)

// ceremony is one passkey ceremony in flight: the challenge issued at begin,
// whom and what it is for, and when it began.
type ceremony struct {
	challenge  []byte
	technician string
	subject    string // an enrollment link ID
	issued     time.Time
}

// ceremonies holds ceremonies between begin and finish, each taken at most
// once. Signing in is open to anyone who can reach the companion, so the table
// is bounded: an entry lapses model.CeremonyTimeout after it began, and a full
// table drops its oldest entry. A flood can make a technician start again; it
// cannot grow memory.
type ceremonies struct {
	mu  sync.Mutex
	max int
	m   map[string]ceremony
}

func newCeremonies(max int) *ceremonies {
	return &ceremonies{max: max, m: make(map[string]ceremony)}
}

// put records c under key, replacing whatever was there.
func (cs *ceremonies) put(key string, c ceremony) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for k, old := range cs.m {
		if lapsed(old, c.issued) {
			delete(cs.m, k)
		}
	}
	if _, ok := cs.m[key]; !ok && len(cs.m) >= cs.max {
		var oldest string
		for k, old := range cs.m {
			if oldest == "" || old.issued.Before(cs.m[oldest].issued) {
				oldest = k
			}
		}
		delete(cs.m, oldest)
	}
	cs.m[key] = c
}

// take removes the ceremony under key, and returns it if it has not lapsed at
// now.
func (cs *ceremonies) take(key string, now time.Time) (ceremony, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	c, ok := cs.m[key]
	delete(cs.m, key)
	if !ok || lapsed(c, now) {
		return ceremony{}, false
	}
	return c, true
}

func (cs *ceremonies) size() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.m)
}

// lapsed reports whether c began more than model.CeremonyTimeout before now.
func lapsed(c ceremony, now time.Time) bool { return now.Sub(c.issued) > model.CeremonyTimeout }

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return b
}

// newChallenge is a fresh WebAuthn challenge.
func newChallenge() []byte { return random(32) }

// newToken is an unguessable identifier: a ceremony ID, or an unlock's nonce.
func newToken() string { return base64.RawURLEncoding.EncodeToString(random(32)) }
