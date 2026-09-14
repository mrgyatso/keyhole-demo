// Package passkeytest is a software WebAuthn authenticator and browser, for
// tests of the passkey package and of everything that verifies passkeys
// through it. It builds exactly what a browser sends: SPKI public key,
// authenticator data, client data JSON and an ASN.1 ECDSA signature.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/mrgyatso/keyhole/internal/passkey"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Authenticator holds one ES256 passkey for one relying party.
type Authenticator struct {
	RPID   string
	Origin string
	Key    *ecdsa.PrivateKey
	ID     []byte // the raw credential ID
	// UserHandle is returned with every assertion, as a discoverable
	// credential's user.id is.
	UserHandle []byte
	// Counter makes the authenticator count its signatures, as a security
	// key does. Without it the sign count is always 0, as a synced passkey's
	// is.
	Counter bool

	t     testing.TB
	count uint32
}

// New makes an authenticator with a fresh key and credential ID.
func New(t testing.TB, rpID, origin string) *Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &Authenticator{RPID: rpID, Origin: origin, Key: key, ID: id, t: t}
}

// CredentialID is the credential ID as a browser reports it.
func (a *Authenticator) CredentialID() string { return base64.RawURLEncoding.EncodeToString(a.ID) }

// PublicKey is the SubjectPublicKeyInfo DER that getPublicKey returns.
func (a *Authenticator) PublicKey() []byte {
	der, err := x509.MarshalPKIXPublicKey(&a.Key.PublicKey)
	if err != nil {
		a.t.Fatal(err)
	}
	return der
}

// Ceremony is what the browser and authenticator put together before the
// signature. Tests change one field at a time to forge one check.
type Ceremony struct {
	Type        string
	Challenge   []byte
	Origin      string
	CrossOrigin *bool  // nil leaves the member out
	RPID        string // hashed into the authenticator data
	Flags       byte
	SignCount   uint32
	Attested    bool   // registration: append attested credential data
	AttestedID  []byte // the credential ID in it; default the authenticator's
}

func (a *Authenticator) ceremony(typ string, challenge []byte, attested bool) Ceremony {
	no := false
	c := Ceremony{Type: typ, Challenge: challenge, Origin: a.Origin, CrossOrigin: &no, RPID: a.RPID,
		Flags: passkey.FlagUserPresent | passkey.FlagUserVerified, Attested: attested, AttestedID: a.ID}
	if attested {
		c.Flags |= passkey.FlagAttested
	}
	if a.Counter {
		a.count++
		c.SignCount = a.count
	}
	return c
}

// ClientDataJSON serializes c's client data the way browsers do.
func ClientDataJSON(c Ceremony) []byte {
	m := map[string]any{"type": c.Type, "challenge": base64.RawURLEncoding.EncodeToString(c.Challenge), "origin": c.Origin}
	if c.CrossOrigin != nil {
		m["crossOrigin"] = *c.CrossOrigin
	}
	b, _ := json.Marshal(m)
	return b
}

// AuthenticatorData serializes c's authenticator data.
func AuthenticatorData(c Ceremony) []byte {
	h := sha256.Sum256([]byte(c.RPID))
	ad := append([]byte{}, h[:]...)
	ad = append(ad, c.Flags)
	ad = binary.BigEndian.AppendUint32(ad, c.SignCount)
	if c.Attested {
		ad = append(ad, make([]byte, 16)...) // AAGUID: zero, as with attestation "none"
		ad = binary.BigEndian.AppendUint16(ad, uint16(len(c.AttestedID)))
		ad = append(ad, c.AttestedID...)
		ad = append(ad, 0xa5) // the COSE key would follow; it is never parsed
	}
	return ad
}

// Sign signs authenticator data and client data as an authenticator does.
func (a *Authenticator) Sign(authData, clientDataJSON []byte) []byte {
	cd := sha256.Sum256(clientDataJSON)
	h := sha256.Sum256(append(append([]byte{}, authData...), cd[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, h[:])
	if err != nil {
		a.t.Fatal(err)
	}
	return sig
}

// Create registers the passkey against challenge, as
// navigator.credentials.create does. edit, if given, changes the ceremony
// first.
func (a *Authenticator) Create(challenge []byte, edit ...func(*Ceremony)) passkey.Attestation {
	c := a.ceremony(passkey.TypeCreate, challenge, true)
	for _, e := range edit {
		e(&c)
	}
	return passkey.Attestation{CredentialID: a.CredentialID(), PublicKey: a.PublicKey(), Algorithm: passkey.AlgES256,
		AuthenticatorData: AuthenticatorData(c), ClientDataJSON: ClientDataJSON(c)}
}

// Get signs challenge, as navigator.credentials.get does. edit, if given,
// changes the ceremony first.
func (a *Authenticator) Get(challenge []byte, edit ...func(*Ceremony)) proto.PasskeyAssertion {
	c := a.ceremony(passkey.TypeGet, challenge, false)
	for _, e := range edit {
		e(&c)
	}
	ad, cd := AuthenticatorData(c), ClientDataJSON(c)
	return proto.PasskeyAssertion{CredentialID: a.CredentialID(), AuthenticatorData: ad, ClientDataJSON: cd,
		Signature: a.Sign(ad, cd), UserHandle: a.UserHandle}
}

// Credential is the credential a relying party stores for this passkey.
func (a *Authenticator) Credential() passkey.Credential {
	return passkey.Credential{ID: a.CredentialID(), PublicKey: a.PublicKey(), Algorithm: passkey.AlgES256}
}
