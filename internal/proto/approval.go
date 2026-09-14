package proto

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// Technician approval (Slice 6). A managed endpoint no longer asks the person
// at the machine: the technician signs in to the Keyhole companion with a
// passkey and approves there, and the relay carries that approval to the
// endpoint. An unlock authorises access requests for one client for a bounded
// time; a change approval releases exactly one apply or rollback.
//
// Approvals ride the companion sign-in, with no passkey prompt per approval,
// so Assertion is empty and the endpoint trusts the relay's check of the
// sign-in. Challenge is still defined here, on the wire type both sides share,
// because whatever Slice 7 has the endpoint verify must sign exactly these
// bytes, and the endpoint must be able to compute them alone.

// Approval kinds.
const (
	ApprovalUnlock = "unlock"
	ApprovalChange = "change"
)

// ApprovalClockSkew is how far the endpoint's clock may disagree with the
// relay's when it compares an approval's ExpiresAt with its own clock.
const ApprovalClockSkew = 2 * time.Minute

// ErrApprovalRequired is the endpoint's refusal of a change under a grant
// that came from a technician unlock, when the change carries no technician
// approval that binds exactly it.
const ErrApprovalRequired = "approval_required"

// PasskeyAssertion is one WebAuthn assertion as the technician's browser
// returned it.
type PasskeyAssertion struct {
	CredentialID      string `json:"credential_id"` // base64url, unpadded
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"`
	UserHandle        []byte `json:"user_handle,omitempty"`
}

// TechnicianApproval is one technician decision: an unlock, or a change. The
// fields down to ExpiresAt are the decision (see Challenge); the rest records
// who made it and when.
type TechnicianApproval struct {
	Kind       string    `json:"kind"`
	ID         string    `json:"id"` // unl_… or chg_…
	Technician string    `json:"technician"`
	Client     string    `json:"client"`
	Purpose    string    `json:"purpose,omitempty"`     // unlock: what the technician is unlocking the client for
	Device     string    `json:"device,omitempty"`      // change
	AccessID   string    `json:"access_id,omitempty"`   // change: the grant it runs under
	GrantID    string    `json:"grant_id,omitempty"`    // change
	Op         string    `json:"op,omitempty"`          // change: OpApplyFileChange or OpRollbackFileChange
	PlanID     string    `json:"plan_id,omitempty"`     // change
	PlanDigest string    `json:"plan_digest,omitempty"` // change
	RollbackID string    `json:"rollback_id,omitempty"` // rollback
	Nonce      string    `json:"nonce"`
	ExpiresAt  time.Time `json:"expires_at"` // unlock: end of the unlocked period; change: the last moment it may be applied

	Credential string            `json:"credential,omitempty"` // base64url ID of the passkey the technician signed in with
	ApprovedAt time.Time         `json:"approved_at,omitzero"`
	Assertion  *PasskeyAssertion `json:"assertion,omitempty"` // empty: approvals ride the companion sign-in
}

// approvalDomain keeps this encoding from colliding with any other use of a
// technician's passkey.
const approvalDomain = "keyhole-technician-approval-v1"

// Challenge is the digest that identifies this decision: SHA-256 over a
// length-prefixed encoding of every signed field in a fixed order. The length
// prefixes make the encoding unambiguous whatever a field contains, so two
// different approvals never share a challenge. The signature fields are not
// part of it.
func (a TechnicianApproval) Challenge() []byte {
	var b strings.Builder
	b.WriteString(approvalDomain)
	b.WriteByte('\n')
	for _, f := range [...]struct{ name, value string }{
		{"kind", a.Kind}, {"id", a.ID}, {"technician", a.Technician}, {"client", a.Client},
		{"purpose", a.Purpose}, {"device", a.Device}, {"access_id", a.AccessID}, {"grant_id", a.GrantID},
		{"op", a.Op}, {"plan_id", a.PlanID}, {"plan_digest", a.PlanDigest}, {"rollback_id", a.RollbackID},
		{"nonce", a.Nonce}, {"expires_at", a.ExpiresAt.UTC().Format(time.RFC3339Nano)},
	} {
		fmt.Fprintf(&b, "%s=%d:%s\n", f.name, len(f.value), f.value)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return sum[:]
}

// SameSigned reports whether a and b sign exactly the same decision. It is
// how a presented approval is compared with the stored one it claims to be.
func (a TechnicianApproval) SameSigned(b TechnicianApproval) bool {
	return bytes.Equal(a.Challenge(), b.Challenge())
}

// Signed reports whether the approval records who signed it.
func (a TechnicianApproval) Signed() bool {
	return a.Credential != "" && !a.ApprovedAt.IsZero()
}

// ApproverLabel is how a technician approval is recorded wherever an approver
// is named: in consent events, grants, plan records and audit entries.
func (a TechnicianApproval) ApproverLabel() string {
	cred := a.Credential
	if len(cred) > 12 {
		cred = cred[:12]
	}
	return "technician " + a.Technician + " (passkey " + cred + ")"
}
