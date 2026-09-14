package model

import (
	"errors"
	"testing"
	"time"
)

func TestEnrollSecretNamesItsClient(t *testing.T) {
	s := NewEnrollSecret("acme-corp")
	if c, ok := EnrollSecretClient(s); !ok || c != "acme-corp" {
		t.Fatalf("got %q %v from %q", c, ok, s)
	}
	for _, bad := range []string{"khs_abc", "khe_", "khe__x", "khe_ACME_x"} {
		if _, ok := EnrollSecretClient(bad); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func TestValidSlug(t *testing.T) {
	for s, want := range map[string]bool{
		"acme": true, "acme-corp": true, "a1": true,
		"a": false, "-acme": false, "Acme": false, "acme_corp": false, "acme.corp": false,
	} {
		if ValidSlug(s) != want {
			t.Errorf("ValidSlug(%q) != %v", s, want)
		}
	}
}

func TestTokenUsable(t *testing.T) {
	now := time.Now()
	tok := EnrollToken{ExpiresAt: now.Add(time.Hour), MaxUses: 2, Uses: 1}
	if err := tok.Usable(now); err != nil {
		t.Fatal(err)
	}
	tok.Uses = 2
	if !errors.Is(tok.Usable(now), ErrExhausted) {
		t.Fatal("want exhausted")
	}
	tok.Uses, tok.ExpiresAt = 0, now
	if !errors.Is(tok.Usable(now), ErrExpired) {
		t.Fatal("want expired")
	}
}
