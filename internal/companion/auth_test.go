package companion_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/passkey"
	"github.com/mrgyatso/keyhole/internal/passkey/passkeytest"
	"github.com/mrgyatso/keyhole/internal/proto"
)

func TestEnrollAndSignIn(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice)
	secret := h.mintLink(alice)
	r := h.post("/api/enroll/begin", "", map[string]string{"token": secret})
	h.must(r, http.StatusOK)
	var b beginReply
	decodeJSON(t, r.body, &b)
	var o creationOptions
	decodeJSON(t, b.Options, &o)
	user := sha256.Sum256([]byte("keyhole-user:" + alice))
	switch {
	case b.Technician != alice, o.RP.ID != rpID, o.RP.Name != "Keyhole":
		t.Fatalf("relying party: %s", b.Options)
	case o.User.ID != base64.RawURLEncoding.EncodeToString(user[:16]), o.User.Name != alice, o.User.DisplayName != alice:
		t.Fatalf("user: %s", b.Options)
	case len(o.PubKeyCredParams) != 1 || o.PubKeyCredParams[0].Type != "public-key" || o.PubKeyCredParams[0].Alg != passkey.AlgES256:
		t.Fatalf("algorithms: %s", b.Options)
	case o.AuthenticatorSelection.ResidentKey != "required", o.AuthenticatorSelection.UserVerification != "required",
		o.Attestation != "none", len(o.ExcludeCredentials) != 0, len(challengeOf(t, o.Challenge)) != 32:
		t.Fatalf("options: %s", b.Options)
	}

	r = h.post("/api/enroll/finish", "", a.registration(secret, challengeOf(t, o.Challenge)))
	h.must(r, http.StatusOK)
	var in struct {
		Technician string `json:"technician"`
		Passkey    string `json:"passkey"`
	}
	decodeJSON(t, r.body, &in)
	if in.Technician != alice || in.Passkey != "idp|alice's laptop" {
		t.Fatalf("enrolled as %+v", in)
	}
	a.cookie = r.cookie().Value
	p, err := h.st.Passkey(bg, a.key.CredentialID())
	if err != nil || p.Technician != alice || p.Algorithm != passkey.AlgES256 || string(p.PublicKey) != string(a.key.PublicKey()) ||
		p.Name != "idp|alice's laptop" {
		t.Fatalf("stored passkey %+v, %v", p, err)
	}
	var st struct {
		Technician string `json:"technician"`
	}
	r = h.get("/api/state", a.cookie)
	h.must(r, http.StatusOK)
	if decodeJSON(t, r.body, &st); st.Technician != alice {
		t.Fatalf("signed in as %q", st.Technician)
	}

	// The link is spent.
	if r := h.post("/api/enroll/begin", "", map[string]string{"token": secret}); r.status != http.StatusGone {
		t.Fatalf("a used link: %d", r.status)
	}
	// A second link excludes the passkey already enrolled.
	if o := h.enrollBegin(h.mintLink(alice)); len(o.ExcludeCredentials) != 1 || o.ExcludeCredentials[0].ID != a.key.CredentialID() {
		t.Fatalf("excludeCredentials %+v", o.ExcludeCredentials)
	}

	// Sign in on another device, with a discoverable login.
	r = h.post("/api/login/begin", "", nil)
	var lb beginReply
	decodeJSON(t, r.body, &lb)
	var lo requestOptions
	decodeJSON(t, lb.Options, &lo)
	if lo.RPID != rpID || lo.UserVerification != "required" || len(lo.AllowCredentials) != 0 || lb.Ceremony == "" {
		t.Fatalf("login options: %s", r.body)
	}
	a.key.UserHandle = user[:16] // what a discoverable credential returns
	r = h.post("/api/login/finish", "", loginBody{Ceremony: lb.Ceremony, PasskeyAssertion: a.key.Get(challengeOf(t, lo.Challenge))})
	h.must(r, http.StatusOK)
	other := r.cookie()
	if other == nil || other.Value == a.cookie {
		t.Fatal("sign-in set no new cookie")
	}
	h.must(h.get("/api/state", other.Value), http.StatusOK)
	if p, _ := h.st.Passkey(bg, a.key.CredentialID()); p.LastUsedAt == nil {
		t.Fatal("sign-in did not record the passkey's use")
	}
}

func TestEnrollRefusals(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice)
	for token, status := range map[string]int{
		"": http.StatusNotFound, "khe_acme_xyz": http.StatusNotFound, model.NewSecret(model.SecretPasskeyLink): http.StatusNotFound,
	} {
		if r := h.post("/api/enroll/begin", "", map[string]string{"token": token}); r.status != status {
			t.Errorf("token %q: %d, want %d", token, r.status, status)
		}
	}
	secret := h.mintLink(alice)
	finish := func(body map[string]any) reply { return h.post("/api/enroll/finish", "", body) }
	for name, tc := range map[string]struct {
		body   func(ch []byte) map[string]any
		status int
	}{
		"another origin": {func(ch []byte) map[string]any {
			return a.registration(secret, ch, func(c *passkeytest.Ceremony) { c.Origin = "https://evil.test" })
		}, http.StatusForbidden},
		"no user verification": {func(ch []byte) map[string]any {
			return a.registration(secret, ch, func(c *passkeytest.Ceremony) { c.Flags &^= passkey.FlagUserVerified })
		}, http.StatusForbidden},
		"a challenge nobody issued": {func([]byte) map[string]any { return a.registration(secret, randomChallenge(t)) }, http.StatusForbidden},
		"an RS256 key": {func(ch []byte) map[string]any {
			body := a.registration(secret, ch)
			body["algorithm"] = -257
			return body
		}, http.StatusForbidden},
		"a name with a newline": {func(ch []byte) map[string]any {
			body := a.registration(secret, ch)
			body["name"] = "laptop\nof alice"
			return body
		}, http.StatusBadRequest},
	} {
		o := h.enrollBegin(secret)
		r := finish(tc.body(challengeOf(t, o.Challenge)))
		if r.status != tc.status || r.cookie() != nil {
			t.Errorf("%s: %d, want %d, cookie %v", name, r.status, tc.status, r.cookie())
		}
	}
	if _, err := h.st.Passkey(bg, a.key.CredentialID()); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("a refused registration stored the passkey: %v", err)
	}

	// A registration after the ceremony timeout, and one without a begin.
	o := h.enrollBegin(secret)
	h.advance(model.CeremonyTimeout + time.Second)
	if r := finish(a.registration(secret, challengeOf(t, o.Challenge))); r.status != http.StatusGone {
		t.Fatalf("a lapsed ceremony: %d", r.status)
	}
	if r := finish(a.registration(secret, challengeOf(t, o.Challenge))); r.status != http.StatusGone {
		t.Fatalf("no ceremony: %d", r.status)
	}
	// The refusals left the link unused: it still enrolls, once.
	o = h.enrollBegin(secret)
	h.must(finish(a.registration(secret, challengeOf(t, o.Challenge))), http.StatusOK)

	// The same passkey cannot be enrolled again.
	again := h.mintLink(alice)
	o = h.enrollBegin(again)
	if r := finish(a.registration(again, challengeOf(t, o.Challenge))); r.status != http.StatusConflict {
		t.Fatalf("enrolled twice: %d", r.status)
	}
	// A link lapses fifteen minutes after it was minted.
	late := h.mintLink(bob)
	h.advance(model.PasskeyLinkTTL)
	if r := h.post("/api/enroll/begin", "", map[string]string{"token": late}); r.status != http.StatusGone {
		t.Fatalf("an expired link: %d", r.status)
	}
}

func TestSignInRefusals(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	finish := func(id string, as proto.PasskeyAssertion) reply {
		return h.post("/api/login/finish", "", loginBody{Ceremony: id, PasskeyAssertion: as})
	}
	refused := func(what string, r reply, status int) {
		t.Helper()
		if r.status != status || r.cookie() != nil {
			t.Errorf("%s: %d, want %d, cookie %v", what, r.status, status, r.cookie())
		}
	}

	id, _ := h.loginBegin()
	refused("a challenge nobody issued", finish(id, a.key.Get(randomChallenge(t))), http.StatusUnauthorized)

	id, ch := h.loginBegin()
	h.must(finish(id, a.key.Get(ch)), http.StatusOK)
	refused("a ceremony used twice", finish(id, a.key.Get(ch)), http.StatusGone)

	id, ch = h.loginBegin()
	h.advance(model.CeremonyTimeout + time.Second)
	refused("a lapsed ceremony", finish(id, a.key.Get(ch)), http.StatusGone)

	id, ch = h.loginBegin()
	refused("an unknown passkey", finish(id, h.newTech(alice).key.Get(ch)), http.StatusUnauthorized)

	id, ch = h.loginBegin()
	refused("another origin", finish(id, a.key.Get(ch, func(c *passkeytest.Ceremony) { c.Origin = "https://evil.test" })),
		http.StatusUnauthorized)

	id, ch = h.loginBegin()
	refused("no user verification", finish(id, a.key.Get(ch, func(c *passkeytest.Ceremony) { c.Flags = passkey.FlagUserPresent })),
		http.StatusUnauthorized)

	a.key.UserHandle = []byte("someone else's handle")
	id, ch = h.loginBegin()
	refused("another technician's user handle", finish(id, a.key.Get(ch)), http.StatusUnauthorized)
	a.key.UserHandle = nil

	if err := h.st.RevokePasskey(bg, a.key.CredentialID(), h.clock()); err != nil {
		t.Fatal(err)
	}
	id, ch = h.loginBegin()
	refused("a revoked passkey", finish(id, a.key.Get(ch)), http.StatusForbidden)
}

func TestSignInCookie(t *testing.T) {
	for _, tc := range []struct {
		origin string
		secure bool
	}{{"https://keyhole.test", true}, {"http://localhost:7803", false}} {
		h := newHarnessAt(t, tc.origin)
		a := h.newTech(alice)
		secret := h.mintLink(alice)
		o := h.enrollBegin(secret)
		r := h.post("/api/enroll/finish", "", a.registration(secret, challengeOf(t, o.Challenge)))
		h.must(r, http.StatusOK)
		c := r.cookie()
		if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Secure != tc.secure || c.Path != "/" ||
			c.MaxAge != int(model.CompanionSessionTTL/time.Second) || !strings.HasPrefix(c.Value, model.SecretCompanion+"_") {
			t.Fatalf("%s: cookie %+v", tc.origin, c)
		}
		// Only the hash of the secret is stored.
		cs, err := h.st.CompanionSessionByToken(bg, c.Value)
		if err != nil || cs.Hash != model.HashSecret(c.Value) || cs.Technician != alice || cs.Credential != a.key.CredentialID() ||
			cs.ExpiresAt.Sub(cs.CreatedAt) != model.CompanionSessionTTL {
			t.Fatalf("%s: stored sign-in %+v, %v", tc.origin, cs, err)
		}
	}
}

func TestSignOutLocksAndEndsEverySignIn(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	r := a.signIn()
	h.must(r, http.StatusOK)
	other := r.cookie().Value // alice on a second device
	b := h.newTech(bob).enroll()

	r = h.post("/api/logout", a.cookie, nil)
	h.must(r, http.StatusOK)
	if c := r.cookie(); c == nil || c.MaxAge >= 0 || c.Value != "" {
		t.Fatalf("sign-out left the cookie: %+v", c)
	}
	calls := h.gate.Calls("")
	if len(calls) != 1 || calls[0].Method != "LockAll" || calls[0].Technician != alice || calls[0].Reason != model.ReasonSignedOut {
		t.Fatalf("gate calls %+v", calls)
	}
	for name, secret := range map[string]string{"this device": a.cookie, "the other device": other} {
		if r := h.get("/api/state", secret); r.status != http.StatusUnauthorized {
			t.Errorf("%s is still signed in: %d", name, r.status)
		}
		if cs, _ := h.st.CompanionSessionByToken(bg, secret); cs.RevokedAt == nil {
			t.Errorf("%s: the sign-in is not revoked", name)
		}
	}
	h.must(h.get("/api/state", b.cookie), http.StatusOK)

	// When the unlock cannot be locked, signing out still ends every sign-in,
	// and says what is left to do.
	h.gate.setErr(errors.New("gateway unavailable"))
	r = h.post("/api/logout", b.cookie, nil)
	if r.status != http.StatusInternalServerError || !strings.Contains(string(r.body), "press Lock") || r.cookie() == nil {
		t.Fatalf("sign-out with the gate down: %d %s", r.status, r.body)
	}
	if strings.Contains(string(r.body), "gateway unavailable") {
		t.Fatal("an internal error reached the page")
	}
	if r := h.get("/api/state", b.cookie); r.status != http.StatusUnauthorized {
		t.Fatalf("still signed in after a failed lock: %d", r.status)
	}
}

func TestRevokingAPasskeyEndsItsSignIns(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	spare := h.newTech(alice).enroll()
	h.must(h.get("/api/state", a.cookie), http.StatusOK)
	if err := h.st.RevokePasskey(bg, a.key.CredentialID(), h.clock()); err != nil {
		t.Fatal(err)
	}
	if r := h.get("/api/state", a.cookie); r.status != http.StatusUnauthorized {
		t.Fatalf("a sign-in outlived its passkey: %d", r.status)
	}
	h.must(h.get("/api/state", spare.cookie), http.StatusOK)
}
