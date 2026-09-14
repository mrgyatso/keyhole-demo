package passkey_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/mrgyatso/keyhole/internal/passkey"
	"github.com/mrgyatso/keyhole/internal/passkey/passkeytest"
	"github.com/mrgyatso/keyhole/internal/proto"
)

const (
	rpID   = "keyhole.test"
	origin = "https://keyhole.test"
)

var rp = passkey.RP{ID: rpID, Origin: origin}

func challenge(t *testing.T) []byte {
	t.Helper()
	c := make([]byte, 32)
	if _, err := rand.Read(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVerifyRegistration(t *testing.T) {
	a := passkeytest.New(t, rpID, origin)
	ch := challenge(t)
	cred, err := passkey.VerifyRegistration(rp, ch, a.Create(ch))
	if err != nil {
		t.Fatal(err)
	}
	if cred.ID != a.CredentialID() || cred.Algorithm != passkey.AlgES256 || cred.SignCount != 0 {
		t.Fatalf("credential %+v", cred)
	}
	if string(cred.PublicKey) != string(a.PublicKey()) {
		t.Fatal("the stored key is not the presented one")
	}

	// A security key's first count is kept, so its next assertion must exceed it.
	counting := passkeytest.New(t, rpID, origin)
	counting.Counter = true
	cred, err = passkey.VerifyRegistration(rp, ch, counting.Create(ch))
	if err != nil || cred.SignCount != 1 {
		t.Fatalf("counting authenticator: %+v, %v", cred, err)
	}
}

func TestVerifyRegistrationRefuses(t *testing.T) {
	a := passkeytest.New(t, rpID, origin)
	ch := challenge(t)
	yes := true
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)

	for name, tc := range map[string]struct {
		rp   *passkey.RP
		ch   []byte
		edit func(*passkeytest.Ceremony)
		att  func(*passkey.Attestation)
		want error
	}{
		"empty relying party":  {rp: &passkey.RP{}, want: passkey.ErrRP},
		"RS256":                {att: func(x *passkey.Attestation) { x.Algorithm = -257 }, want: passkey.ErrAlgorithm},
		"garbage key":          {att: func(x *passkey.Attestation) { x.PublicKey = []byte("not a key") }, want: passkey.ErrPublicKey},
		"P-384 key":            {att: func(x *passkey.Attestation) { x.PublicKey = p384DER }, want: passkey.ErrPublicKey},
		"RSA key":              {att: func(x *passkey.Attestation) { x.PublicKey = rsaDER }, want: passkey.ErrPublicKey},
		"client data not JSON": {att: func(x *passkey.Attestation) { x.ClientDataJSON = []byte("{") }, want: passkey.ErrClientData},
		"assertion type":       {edit: func(c *passkeytest.Ceremony) { c.Type = passkey.TypeGet }, want: passkey.ErrType},
		"other challenge":      {edit: func(c *passkeytest.Ceremony) { c.Challenge = challenge(t) }, want: passkey.ErrChallenge},
		"no expected challenge": {ch: []byte{}, edit: func(c *passkeytest.Ceremony) { c.Challenge = nil },
			want: passkey.ErrChallenge},
		"other origin":       {edit: func(c *passkeytest.Ceremony) { c.Origin = "https://evil.test" }, want: passkey.ErrOrigin},
		"origin with a port": {edit: func(c *passkeytest.Ceremony) { c.Origin = origin + ":8443" }, want: passkey.ErrOrigin},
		"cross-origin frame": {edit: func(c *passkeytest.Ceremony) { c.CrossOrigin = &yes }, want: passkey.ErrCrossOrigin},
		"other RP ID":        {edit: func(c *passkeytest.Ceremony) { c.RPID = "evil.test" }, want: passkey.ErrRPID},
		"no user presence":   {edit: func(c *passkeytest.Ceremony) { c.Flags &^= passkey.FlagUserPresent }, want: passkey.ErrUserPresence},
		"no user verification": {edit: func(c *passkeytest.Ceremony) { c.Flags &^= passkey.FlagUserVerified },
			want: passkey.ErrUserVerification},
		"no attested data": {edit: func(c *passkeytest.Ceremony) { c.Flags &^= passkey.FlagAttested; c.Attested = false },
			want: passkey.ErrAttested},
		"attested another ID": {edit: func(c *passkeytest.Ceremony) { c.AttestedID = []byte("another credential") },
			want: passkey.ErrCredentialID},
		"presented another ID": {att: func(x *passkey.Attestation) { x.CredentialID = "b3RoZXI" }, want: passkey.ErrCredentialID},
		"presented ID not base64url": {att: func(x *passkey.Attestation) { x.CredentialID = x.CredentialID + "!" },
			want: passkey.ErrCredentialID},
		"authenticator data too short": {att: func(x *passkey.Attestation) { x.AuthenticatorData = x.AuthenticatorData[:36] },
			want: passkey.ErrAuthData},
		"attested data truncated": {att: func(x *passkey.Attestation) { x.AuthenticatorData = x.AuthenticatorData[:40] },
			want: passkey.ErrAuthData},
		"credential ID overruns": {att: func(x *passkey.Attestation) { x.AuthenticatorData = x.AuthenticatorData[:60] },
			want: passkey.ErrAuthData},
		"empty credential ID": {edit: func(c *passkeytest.Ceremony) { c.AttestedID = nil }, want: passkey.ErrAuthData},
	} {
		t.Run(name, func(t *testing.T) {
			r, c := rp, ch
			if tc.rp != nil {
				r = *tc.rp
			}
			if tc.ch != nil {
				c = tc.ch
			}
			var edits []func(*passkeytest.Ceremony)
			if tc.edit != nil {
				edits = append(edits, tc.edit)
			}
			att := a.Create(ch, edits...)
			if tc.att != nil {
				tc.att(&att)
			}
			if _, err := passkey.VerifyRegistration(r, c, att); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyAssertion(t *testing.T) {
	a := passkeytest.New(t, rpID, origin)
	ch := challenge(t)
	count, err := passkey.VerifyAssertion(rp, ch, a.Credential(), a.Get(ch))
	if err != nil || count != 0 {
		t.Fatalf("synced passkey: %d, %v", count, err)
	}
	// A synced passkey reports 0 every time, which is not a clone.
	if _, err := passkey.VerifyAssertion(rp, ch, a.Credential(), a.Get(ch)); err != nil {
		t.Fatalf("second zero count: %v", err)
	}

	// crossOrigin is optional in client data.
	absent := a.Get(ch, func(c *passkeytest.Ceremony) { c.CrossOrigin = nil })
	if _, err := passkey.VerifyAssertion(rp, ch, a.Credential(), absent); err != nil {
		t.Fatalf("crossOrigin absent: %v", err)
	}

	k := passkeytest.New(t, rpID, origin)
	k.Counter = true
	cred := k.Credential()
	for want := uint32(1); want <= 3; want++ {
		got, err := passkey.VerifyAssertion(rp, ch, cred, k.Get(ch))
		if err != nil || got != want {
			t.Fatalf("assertion %d: count %d, %v", want, got, err)
		}
		cred.SignCount = got
	}
}

func TestVerifyAssertionRefuses(t *testing.T) {
	a := passkeytest.New(t, rpID, origin)
	other := passkeytest.New(t, rpID, origin)
	ch := challenge(t)
	yes := true
	for name, tc := range map[string]struct {
		cred func(*passkey.Credential)
		edit func(*passkeytest.Ceremony)
		as   func(*proto.PasskeyAssertion)
		want error
	}{
		"other credential ID": {as: func(x *proto.PasskeyAssertion) { x.CredentialID = other.CredentialID() },
			want: passkey.ErrCredentialID},
		"no credential ID": {as: func(x *proto.PasskeyAssertion) { x.CredentialID = "" }, want: passkey.ErrCredentialID},
		"stored algorithm": {cred: func(c *passkey.Credential) { c.Algorithm = -8 }, want: passkey.ErrAlgorithm},
		"stored key":       {cred: func(c *passkey.Credential) { c.PublicKey = []byte{1, 2, 3} }, want: passkey.ErrPublicKey},
		"client data not JSON": {as: func(x *proto.PasskeyAssertion) { x.ClientDataJSON = []byte("[]") },
			want: passkey.ErrClientData},
		"registration type":  {edit: func(c *passkeytest.Ceremony) { c.Type = passkey.TypeCreate }, want: passkey.ErrType},
		"other challenge":    {edit: func(c *passkeytest.Ceremony) { c.Challenge = challenge(t) }, want: passkey.ErrChallenge},
		"challenge prefix":   {edit: func(c *passkeytest.Ceremony) { c.Challenge = ch[:31] }, want: passkey.ErrChallenge},
		"other origin":       {edit: func(c *passkeytest.Ceremony) { c.Origin = "https://keyhole.test.evil" }, want: passkey.ErrOrigin},
		"http origin":        {edit: func(c *passkeytest.Ceremony) { c.Origin = "http://keyhole.test" }, want: passkey.ErrOrigin},
		"cross-origin frame": {edit: func(c *passkeytest.Ceremony) { c.CrossOrigin = &yes }, want: passkey.ErrCrossOrigin},
		"authenticator data too short": {as: func(x *proto.PasskeyAssertion) { x.AuthenticatorData = x.AuthenticatorData[:20] },
			want: passkey.ErrAuthData},
		"other RP ID":      {edit: func(c *passkeytest.Ceremony) { c.RPID = "other.keyhole.test" }, want: passkey.ErrRPID},
		"no user presence": {edit: func(c *passkeytest.Ceremony) { c.Flags = passkey.FlagUserVerified }, want: passkey.ErrUserPresence},
		"no user verification": {edit: func(c *passkeytest.Ceremony) { c.Flags = passkey.FlagUserPresent },
			want: passkey.ErrUserVerification},
		"signed by another key": {as: func(x *proto.PasskeyAssertion) {
			x.Signature = other.Sign(x.AuthenticatorData, x.ClientDataJSON)
		}, want: passkey.ErrSignature},
		"authenticator data changed after signing": {as: func(x *proto.PasskeyAssertion) {
			x.AuthenticatorData = append(x.AuthenticatorData, 0) // extension bytes the signature does not cover
		}, want: passkey.ErrSignature},
		"client data changed after signing": {as: func(x *proto.PasskeyAssertion) {
			x.ClientDataJSON = append(x.ClientDataJSON, ' ') // still the same members, a different hash
		}, want: passkey.ErrSignature},
		"no signature":      {as: func(x *proto.PasskeyAssertion) { x.Signature = nil }, want: passkey.ErrSignature},
		"garbage signature": {as: func(x *proto.PasskeyAssertion) { x.Signature = []byte{0x30, 0x00} }, want: passkey.ErrSignature},
	} {
		t.Run(name, func(t *testing.T) {
			cred := a.Credential()
			if tc.cred != nil {
				tc.cred(&cred)
			}
			var edits []func(*passkeytest.Ceremony)
			if tc.edit != nil {
				edits = append(edits, tc.edit)
			}
			as := a.Get(ch, edits...)
			if tc.as != nil {
				tc.as(&as)
			}
			if _, err := passkey.VerifyAssertion(rp, ch, cred, as); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyAssertionSignCount(t *testing.T) {
	a := passkeytest.New(t, rpID, origin)
	ch := challenge(t)
	for _, tc := range []struct {
		stored, presented uint32
		ok                bool
	}{
		{0, 0, true},  // synced passkey
		{0, 7, true},  // first count after a zero registration
		{7, 8, true},  // counting forward
		{7, 7, false}, // replayed or cloned
		{7, 3, false}, // went backwards
		{7, 0, false}, // a counter that stopped counting
	} {
		cred := a.Credential()
		cred.SignCount = tc.stored
		as := a.Get(ch, func(c *passkeytest.Ceremony) { c.SignCount = tc.presented })
		got, err := passkey.VerifyAssertion(rp, ch, cred, as)
		switch {
		case tc.ok && (err != nil || got != tc.presented):
			t.Errorf("stored %d, presented %d: %d, %v", tc.stored, tc.presented, got, err)
		case !tc.ok && !errors.Is(err, passkey.ErrSignCount):
			t.Errorf("stored %d, presented %d: err = %v, want ErrSignCount", tc.stored, tc.presented, err)
		}
	}
}

// TestChallengeIsTheApproval pins the contract the companion and the endpoint
// share: the challenge a technician signs is the approval's own Challenge, so
// an assertion over one approval never verifies against another.
func TestChallengeIsTheApproval(t *testing.T) {
	a := passkeytest.New(t, rpID, origin)
	unlock := proto.TechnicianApproval{Kind: proto.ApprovalUnlock, ID: "unl_1", Technician: "alice", Client: "acme", Nonce: "n1"}
	as := a.Get(unlock.Challenge())
	if _, err := passkey.VerifyAssertion(rp, unlock.Challenge(), a.Credential(), as); err != nil {
		t.Fatal(err)
	}
	moved := unlock
	moved.Client = "globex"
	if _, err := passkey.VerifyAssertion(rp, moved.Challenge(), a.Credential(), as); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("an assertion over acme verified for globex: %v", err)
	}
}
