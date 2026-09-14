// Package passkey verifies WebAuthn passkeys: the registration a technician
// makes when enrolling one, and the assertion each approval carries. The
// relay's companion uses it in Slice 6; the endpoint reuses it in Slice 7 to
// verify approvals itself, which is why it depends on nothing but the
// standard library and the wire types.
//
// Only ES256 (COSE algorithm -7, ECDSA on P-256 with SHA-256) is accepted. The
// browser hands over the credential's public key as SubjectPublicKeyInfo DER
// (AuthenticatorAttestationResponse.getPublicKey), so no CBOR is parsed.
// Attestation is "none": a registration proves that the browser at the right
// origin completed the ceremony with user verification, not which
// authenticator made the key. What vouches for the technician is the one-time
// enrollment link.
package passkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// AlgES256 is the COSE algorithm identifier of ES256, the only one accepted.
const AlgES256 = -7

// Client data types, one per ceremony.
const (
	TypeCreate = "webauthn.create"
	TypeGet    = "webauthn.get"
)

// Authenticator data flags.
const (
	FlagUserPresent  = 0x01 // UP: someone touched or looked at the authenticator
	FlagUserVerified = 0x04 // UV: and it verified them (PIN, Touch ID, Face ID)
	FlagAttested     = 0x40 // AT: attested credential data follows
)

// Authenticator data layout: rpIdHash (32), flags (1), signCount (4), then
// for a registration AAGUID (16), credential ID length (2, big-endian) and
// the credential ID.
const (
	authDataMin     = 37
	flagsAt         = 32
	signCountAt     = 33
	aaguidLen       = 16
	credIDLenAt     = authDataMin + aaguidLen
	credIDAt        = credIDLenAt + 2
	maxCredentialID = 1023 // WebAuthn's bound on credentialIdLength
)

// RP is the relying party a ceremony must have been made for.
type RP struct {
	ID     string // the RP ID the credential is scoped to, e.g. "library.example.ts.net"
	Origin string // the exact origin the browser must report, e.g. "https://library.example.ts.net"
}

// Credential is a verified passkey, as it is stored.
type Credential struct {
	ID        string // base64url, unpadded
	PublicKey []byte // SubjectPublicKeyInfo, DER
	Algorithm int    // COSE algorithm
	SignCount uint32
}

// Attestation is what the browser returns from navigator.credentials.create,
// in the form the companion's page sends it.
type Attestation struct {
	CredentialID      string // PublicKeyCredential.id: base64url, unpadded
	PublicKey         []byte // getPublicKey(): SubjectPublicKeyInfo, DER
	Algorithm         int    // getPublicKeyAlgorithm()
	AuthenticatorData []byte // getAuthenticatorData()
	ClientDataJSON    []byte
}

// Each check has its own error, so a refusal says which one failed.
var (
	ErrRP               = errors.New("passkey: the relying party ID and origin are required")
	ErrAlgorithm        = errors.New("passkey: the credential does not use ES256")
	ErrPublicKey        = errors.New("passkey: the public key is not an ECDSA P-256 key")
	ErrClientData       = errors.New("passkey: the client data is malformed")
	ErrType             = errors.New("passkey: the client data is from another kind of ceremony")
	ErrChallenge        = errors.New("passkey: the challenge does not match")
	ErrOrigin           = errors.New("passkey: the origin does not match")
	ErrCrossOrigin      = errors.New("passkey: the ceremony ran in a cross-origin frame")
	ErrAuthData         = errors.New("passkey: the authenticator data is malformed")
	ErrRPID             = errors.New("passkey: the authenticator data is for another relying party")
	ErrUserPresence     = errors.New("passkey: the authenticator did not see the user")
	ErrUserVerification = errors.New("passkey: the authenticator did not verify the user")
	ErrAttested         = errors.New("passkey: the registration carries no attested credential")
	ErrCredentialID     = errors.New("passkey: the credential ID does not match")
	ErrSignature        = errors.New("passkey: the signature does not verify")
	ErrSignCount        = errors.New("passkey: the sign count did not increase")
)

// VerifyRegistration checks a new passkey made for rp against the challenge
// the relying party issued, and returns the credential to store.
func VerifyRegistration(rp RP, challenge []byte, a Attestation) (Credential, error) {
	if err := rp.check(); err != nil {
		return Credential{}, err
	}
	if _, err := parseKey(a.Algorithm, a.PublicKey); err != nil {
		return Credential{}, err
	}
	if err := checkClientData(rp, TypeCreate, challenge, a.ClientDataJSON); err != nil {
		return Credential{}, err
	}
	count, err := checkAuthData(rp, a.AuthenticatorData)
	if err != nil {
		return Credential{}, err
	}
	id, err := attestedCredentialID(a.AuthenticatorData)
	if err != nil {
		return Credential{}, err
	}
	// The ID the browser reports must be the one the authenticator attested,
	// or the stored credential could be looked up under a name the
	// authenticator will never present.
	presented, err := base64.RawURLEncoding.DecodeString(a.CredentialID)
	if err != nil || !bytes.Equal(presented, id) {
		return Credential{}, ErrCredentialID
	}
	return Credential{
		ID:        base64.RawURLEncoding.EncodeToString(id),
		PublicKey: bytes.Clone(a.PublicKey),
		Algorithm: AlgES256,
		SignCount: count,
	}, nil
}

// VerifyAssertion checks an assertion by credential c over challenge, made for
// rp, and returns the authenticator's new sign count for the caller to store.
func VerifyAssertion(rp RP, challenge []byte, c Credential, a proto.PasskeyAssertion) (uint32, error) {
	if err := rp.check(); err != nil {
		return 0, err
	}
	if a.CredentialID == "" || a.CredentialID != c.ID {
		return 0, ErrCredentialID
	}
	pub, err := parseKey(c.Algorithm, c.PublicKey)
	if err != nil {
		return 0, err
	}
	if err := checkClientData(rp, TypeGet, challenge, a.ClientDataJSON); err != nil {
		return 0, err
	}
	count, err := checkAuthData(rp, a.AuthenticatorData)
	if err != nil {
		return 0, err
	}
	// The authenticator signs its data followed by the hash of the client
	// data, so the signature covers the challenge, the origin and the flags.
	cdHash := sha256.Sum256(a.ClientDataJSON)
	signed := sha256.Sum256(append(bytes.Clone(a.AuthenticatorData), cdHash[:]...))
	if !ecdsa.VerifyASN1(pub, signed[:], a.Signature) {
		return 0, ErrSignature
	}
	// A counter that fails to move forward means a cloned authenticator.
	// Synced passkeys report 0 every time, and that is not a clone.
	if (c.SignCount != 0 || count != 0) && count <= c.SignCount {
		return 0, fmt.Errorf("%w: stored %d, presented %d", ErrSignCount, c.SignCount, count)
	}
	return count, nil
}

func (rp RP) check() error {
	if rp.ID == "" || rp.Origin == "" {
		return ErrRP
	}
	return nil
}

// parseKey accepts an ES256 key: a P-256 SubjectPublicKeyInfo.
func parseKey(alg int, der []byte) (*ecdsa.PublicKey, error) {
	if alg != AlgES256 {
		return nil, fmt.Errorf("%w: COSE algorithm %d", ErrAlgorithm, alg)
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPublicKey, err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrPublicKey
	}
	return pub, nil
}

// clientData is the part of CollectedClientData the checks read.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin *bool  `json:"crossOrigin"`
}

func checkClientData(rp RP, typ string, challenge, raw []byte) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return fmt.Errorf("%w: %v", ErrClientData, err)
	}
	if cd.Type != typ {
		return fmt.Errorf("%w: %q, want %q", ErrType, cd.Type, typ)
	}
	got, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil || len(challenge) == 0 || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return ErrChallenge
	}
	if cd.Origin != rp.Origin {
		return fmt.Errorf("%w: %q", ErrOrigin, cd.Origin)
	}
	if cd.CrossOrigin != nil && *cd.CrossOrigin {
		return ErrCrossOrigin
	}
	return nil
}

// checkAuthData checks the fixed part of the authenticator data and returns
// its sign count.
func checkAuthData(rp RP, ad []byte) (uint32, error) {
	if len(ad) < authDataMin {
		return 0, fmt.Errorf("%w: %d bytes", ErrAuthData, len(ad))
	}
	want := sha256.Sum256([]byte(rp.ID))
	if !bytes.Equal(ad[:flagsAt], want[:]) {
		return 0, ErrRPID
	}
	flags := ad[flagsAt]
	if flags&FlagUserPresent == 0 {
		return 0, ErrUserPresence
	}
	if flags&FlagUserVerified == 0 {
		return 0, ErrUserVerification
	}
	return binary.BigEndian.Uint32(ad[signCountAt:authDataMin]), nil
}

// attestedCredentialID returns the credential ID in a registration's
// attested credential data.
func attestedCredentialID(ad []byte) ([]byte, error) {
	if ad[flagsAt]&FlagAttested == 0 {
		return nil, ErrAttested
	}
	if len(ad) < credIDAt {
		return nil, fmt.Errorf("%w: attested credential data is truncated", ErrAuthData)
	}
	n := int(binary.BigEndian.Uint16(ad[credIDLenAt:credIDAt]))
	if n == 0 || n > maxCredentialID || len(ad) < credIDAt+n {
		return nil, fmt.Errorf("%w: credential ID length %d", ErrAuthData, n)
	}
	return ad[credIDAt : credIDAt+n], nil
}
