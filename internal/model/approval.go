package model

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Technician approval (Slice 6): the technician's passkeys, the client unlocks
// that authorise reads, and the change approvals that gate every write. See
// docs/CONSENTED-ACCESS.md, "Technician approval", and
// docs/handoffs/2026-09-11-slice-6-contract.md.

// ID prefixes.
const (
	PrefixUnlock      = "unl"
	PrefixChange      = "chg"
	PrefixPasskeyLink = "pkl"
	PrefixCompanion   = "cps"
)

// Secret prefixes.
const (
	SecretPasskeyLink = "khp" // one-time passkey enrollment link
	SecretCompanion   = "khc" // companion sign-in cookie
)

// Timing.
const (
	MaxUnlockDuration    = proto.MaxConsentDuration // an unlock lasts at most an hour
	DefaultUnlockIdle    = 15 * time.Minute         // and ends after this long without a call
	UnlockApprovalWindow = 10 * time.Minute         // how long an unlock card waits for the technician
	ChangeApprovalWindow = 15 * time.Minute         // how long a change card waits
	CeremonyTimeout      = 2 * time.Minute          // from a passkey ceremony's begin to its finish
	PasskeyLinkTTL       = 15 * time.Minute         // a one-time enrollment link
	CompanionSessionTTL  = time.Hour                // a companion sign-in, however it was made; then sign in again
	ApprovalRetention    = 24 * time.Hour           // ended unlocks' activity and prepared plans
)

// Unlock states.
const (
	UnlockAwaiting = "awaiting_approval" // on the technician's companion, unanswered
	UnlockActive   = "active"
	UnlockDenied   = "denied"
	UnlockExpired  = "expired"
	UnlockLocked   = "locked" // ended early: Lock, sign-out, or another client unlocked
)

// Why an unlock, or a request waiting for one, ended. Reaching the end of its
// lifetime is proto.ReasonExpired.
const (
	ReasonUnanswered = "unanswered"     // nobody approved it before its deadline
	ReasonIdle       = "idle"           // no call used it for its idle timeout
	ReasonLocked     = "locked"         // the technician pressed Lock
	ReasonSignedOut  = "signed_out"     // the technician signed out of the companion
	ReasonSwitched   = "another_client" // the technician unlocked another client
	ReasonDenied     = "denied"         // the technician denied it
)

// UnlockTerminal reports whether an unlock has ended for good.
func UnlockTerminal(state string) bool {
	return state == UnlockDenied || state == UnlockExpired || state == UnlockLocked
}

// UnlockAdvance is the one transition rule for unlocks, checked by every
// writer against the row it replaces inside the same transaction. Only an
// awaiting unlock can be approved or denied; awaiting and active ones can
// always be ended, which is what makes an unlock fail closed.
func UnlockAdvance(cur, next string) bool {
	if UnlockTerminal(cur) || cur == next {
		return false
	}
	switch next {
	case UnlockActive, UnlockDenied:
		return cur == UnlockAwaiting
	case UnlockExpired, UnlockLocked:
		return cur == UnlockAwaiting || cur == UnlockActive
	}
	return false
}

// Unlock is one technician's authority to use one client's devices for a
// bounded time. The technician grants it with a passkey in the companion;
// while it is active, access requests for devices in that client are approved
// without another prompt. A technician has at most one active unlock: approving
// another locks the first.
//
// EndedAt is set whenever the unlock becomes terminal, and DecidedAt is the
// approval's ApprovedAt exactly, so SignedApproval reproduces what was signed.
type Unlock struct {
	ID          string        `json:"id"`
	Technician  string        `json:"technician"`
	Client      string        `json:"client"`
	Session     string        `json:"session"` // the MCP session that asked for it
	Purpose     string        `json:"purpose"`
	State       string        `json:"state"`
	Duration    time.Duration `json:"duration"`     // how long it lasts once approved; at most MaxUnlockDuration
	IdleTimeout time.Duration `json:"idle_timeout"` // it ends after this long without a call; 0 never idles
	RequestedAt time.Time     `json:"requested_at"`
	Deadline    time.Time     `json:"deadline"`             // still unanswered then, it expires
	Nonce       string        `json:"-"`                    // the current passkey ceremony's challenge nonce
	ExpiresAt   *time.Time    `json:"expires_at,omitempty"` // offered when a ceremony begins; fixed by the approval
	DecidedAt   *time.Time    `json:"decided_at,omitempty"`
	LastUsedAt  *time.Time    `json:"last_used_at,omitempty"`
	EndedAt     *time.Time    `json:"ended_at,omitempty"`
	Reason      string        `json:"reason,omitempty"`
	Credential  string        `json:"credential,omitempty"` // the passkey that approved or denied it
	Assertion   []byte        `json:"-"`                    // the approving proto.PasskeyAssertion, as JSON
	Calls       int64         `json:"calls"`                // device calls made under it
	Devices     []string      `json:"devices"`              // the devices those calls reached
}

// Live reports whether a device call may run under the unlock at now.
func (u Unlock) Live(now time.Time) error {
	switch {
	case u.State == UnlockAwaiting:
		return ErrPending
	case u.State != UnlockActive:
		return ErrRevoked
	case u.ExpiresAt == nil || !now.Before(*u.ExpiresAt), u.idle(now):
		return ErrExpired
	}
	return nil
}

func (u Unlock) idle(now time.Time) bool {
	last := u.LastUsedAt
	if last == nil {
		last = u.DecidedAt
	}
	return u.IdleTimeout > 0 && last != nil && now.Sub(*last) >= u.IdleTimeout
}

// Due reports the state the relay's own deadlines put the unlock in at now,
// and why, or "" when none applies.
func (u Unlock) Due(now time.Time) (state, reason string) {
	switch {
	case u.State == UnlockAwaiting && !now.Before(u.Deadline):
		return UnlockExpired, ReasonUnanswered
	case u.State != UnlockActive:
		return "", ""
	case u.ExpiresAt == nil || !now.Before(*u.ExpiresAt):
		return UnlockExpired, proto.ReasonExpired
	case u.idle(now):
		return UnlockExpired, ReasonIdle
	}
	return "", ""
}

// Approval is what the technician's passkey signs to approve this unlock, as
// the row stands now. ExpiresAt is zero until a ceremony has begun.
func (u Unlock) Approval() proto.TechnicianApproval {
	a := proto.TechnicianApproval{Kind: proto.ApprovalUnlock, ID: u.ID, Technician: u.Technician, Client: u.Client,
		Purpose: u.Purpose, Nonce: u.Nonce}
	if u.ExpiresAt != nil {
		a.ExpiresAt = u.ExpiresAt.UTC()
	}
	return a
}

// SignedApproval is the approval as it was signed, signature included: what
// the relay forwards to an endpoint with each access request made under the
// unlock.
func (u Unlock) SignedApproval() (proto.TechnicianApproval, error) {
	if u.Credential == "" || u.DecidedAt == nil || u.ExpiresAt == nil {
		return proto.TechnicianApproval{}, fmt.Errorf("unlock %s carries no approval: %w", u.ID, ErrInvalid)
	}
	a := u.Approval()
	a.Credential, a.ApprovedAt = u.Credential, u.DecidedAt.UTC()
	if len(u.Assertion) > 0 {
		var as proto.PasskeyAssertion
		if err := json.Unmarshal(u.Assertion, &as); err != nil {
			return proto.TechnicianApproval{}, fmt.Errorf("unlock %s: stored assertion: %w", u.ID, err)
		}
		a.Assertion = &as
	}
	return a, nil
}

// Change approval states.
const (
	ChangeAwaiting = "awaiting_approval" // on the technician's companion, unanswered
	ChangeApproved = "approved"          // approved; being released to the endpoint
	ChangeApplied  = "applied"           // the endpoint made the change (an apply, or a rollback)
	ChangeRefused  = "refused"           // the endpoint refused it; nothing was written
	ChangeFailed   = "failed"            // it could not be delivered, or its outcome was lost
	ChangeDenied   = "denied"
	ChangeExpired  = "expired"
)

// ChangeTerminal reports whether a change approval is finished.
func ChangeTerminal(state string) bool {
	switch state {
	case ChangeApplied, ChangeRefused, ChangeFailed, ChangeDenied, ChangeExpired:
		return true
	}
	return false
}

// ChangeAdvance is the one transition rule for change approvals. Only an
// awaiting approval can be approved, denied or expire; only an approved one
// has an outcome.
func ChangeAdvance(cur, next string) bool {
	if ChangeTerminal(cur) || cur == next {
		return false
	}
	switch next {
	case ChangeApproved, ChangeDenied, ChangeExpired:
		return cur == ChangeAwaiting
	case ChangeApplied, ChangeRefused, ChangeFailed:
		return cur == ChangeApproved
	}
	return false
}

// ChangeApproval gates one apply or rollback. apply_file_change and
// rollback_file_change create it instead of contacting the endpoint; the
// technician approves it on the plan's exact diff in the companion, and the
// approval releases the operation, with RequestID as its request ID so a
// repeated release is idempotent at the endpoint.
//
// ExpiresAt is both the card's deadline and the signed validity the endpoint
// enforces: never later than the plan's or the grant's end.
type ChangeApproval struct {
	ID          string          `json:"id"`
	Op          string          `json:"op"` // proto.OpApplyFileChange or proto.OpRollbackFileChange
	Technician  string          `json:"technician"`
	Client      string          `json:"client"`
	Device      string          `json:"device"`
	AccessID    string          `json:"access_id"`
	GrantID     string          `json:"-"`
	Session     string          `json:"session"` // the MCP session that submitted it
	PlanID      string          `json:"plan_id"`
	PlanDigest  string          `json:"plan_digest"`
	RollbackID  string          `json:"rollback_id,omitempty"`
	State       string          `json:"state"`
	RequestedAt time.Time       `json:"requested_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
	Nonce       string          `json:"-"`
	RequestID   string          `json:"request_id"`
	DecidedAt   *time.Time      `json:"decided_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	Credential  string          `json:"credential,omitempty"`
	Assertion   []byte          `json:"-"`
	Reason      string          `json:"reason,omitempty"`
	ErrorCode   string          `json:"error_code,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"` // the endpoint's result, once applied
}

// Due reports the state the relay's own deadlines put the approval in at now,
// and why, or "" when none applies. A release still unconfirmed once the
// endpoint would refuse its approval anyway has failed.
func (c ChangeApproval) Due(now time.Time) (state, reason string) {
	switch {
	case c.State == ChangeAwaiting && !now.Before(c.ExpiresAt):
		return ChangeExpired, ReasonUnanswered
	case c.State == ChangeApproved && !now.Before(c.ExpiresAt.Add(proto.ApprovalClockSkew)):
		return ChangeFailed, proto.ReasonExpired
	}
	return "", ""
}

// Approval is what the technician's passkey signs to approve this change.
func (c ChangeApproval) Approval() proto.TechnicianApproval {
	return proto.TechnicianApproval{Kind: proto.ApprovalChange, ID: c.ID, Technician: c.Technician, Client: c.Client,
		Device: c.Device, AccessID: c.AccessID, GrantID: c.GrantID, Op: c.Op, PlanID: c.PlanID,
		PlanDigest: c.PlanDigest, RollbackID: c.RollbackID, Nonce: c.Nonce, ExpiresAt: c.ExpiresAt.UTC()}
}

// SignedApproval is the approval as it was signed, signature included: what
// the release carries to the endpoint.
func (c ChangeApproval) SignedApproval() (proto.TechnicianApproval, error) {
	if c.Credential == "" || c.DecidedAt == nil {
		return proto.TechnicianApproval{}, fmt.Errorf("change approval %s is not signed: %w", c.ID, ErrInvalid)
	}
	a := c.Approval()
	a.Credential, a.ApprovedAt = c.Credential, c.DecidedAt.UTC()
	if len(c.Assertion) > 0 {
		var as proto.PasskeyAssertion
		if err := json.Unmarshal(c.Assertion, &as); err != nil {
			return proto.TechnicianApproval{}, fmt.Errorf("change approval %s: stored assertion: %w", c.ID, err)
		}
		a.Assertion = &as
	}
	return a, nil
}

// ChangePlanRecord is the relay's copy of a plan an endpoint prepared, kept so
// the companion can show its diff on the change card. The endpoint holds the
// plan itself and is the authority on it; this copy is for display, and is
// purged ApprovalRetention after it was prepared.
type ChangePlanRecord struct {
	PlanID     string          `json:"plan_id"`
	AccessID   string          `json:"access_id"`
	Client     string          `json:"client"`
	Device     string          `json:"device"`
	Technician string          `json:"technician"`
	Digest     string          `json:"plan_digest"`
	Plan       json.RawMessage `json:"plan"` // the proto.ChangePlan the endpoint returned, diff included
	PreparedAt time.Time       `json:"prepared_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
}

// Passkey is one WebAuthn credential of one technician, enrolled through a
// one-time link. Slice 6 accepts ES256 only.
type Passkey struct {
	CredentialID string     `json:"credential_id"` // base64url, unpadded
	Technician   string     `json:"technician"`
	PublicKey    []byte     `json:"-"`         // SubjectPublicKeyInfo, DER
	Algorithm    int        `json:"algorithm"` // COSE algorithm; -7 is ES256
	SignCount    uint32     `json:"sign_count"`
	Name         string     `json:"name"` // what the technician called it, e.g. "MacBook Touch ID"
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// Live reports whether the passkey may still sign.
func (p Passkey) Live() error {
	if p.RevokedAt != nil {
		return ErrRevoked
	}
	return nil
}

// PasskeyLink is a one-time passkey enrollment link for one technician,
// minted on the admin control plane. Only the hash of its secret is stored.
type PasskeyLink struct {
	ID         string     `json:"id"` // "pkl_…"
	Technician string     `json:"technician"`
	Hash       string     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	UsedAt     *time.Time `json:"used_at,omitempty"`
}

// Usable reports whether the link can still enroll a passkey at now.
func (l PasskeyLink) Usable(now time.Time) error {
	switch {
	case l.UsedAt != nil:
		return ErrExhausted
	case !now.Before(l.ExpiresAt):
		return ErrExpired
	}
	return nil
}

// CompanionSession is one technician's sign-in to the companion, held in a
// cookie. Only the hash of its secret is stored. Signing in shows the
// technician's cards, and every approval rides the sign-in until it ends.
type CompanionSession struct {
	ID         string     `json:"id"` // "cps_…"
	Technician string     `json:"technician"`
	Credential string     `json:"credential"` // the passkey it signed in with
	Hash       string     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// Valid reports whether the sign-in can be used at now. A sign-in ends
// CompanionSessionTTL after it was made even if it was stored with a later
// expiry, so shortening the TTL ends older sign-ins at once.
func (s CompanionSession) Valid(now time.Time) error {
	switch {
	case s.RevokedAt != nil:
		return ErrRevoked
	case !now.Before(s.ExpiresAt), !now.Before(s.CreatedAt.Add(CompanionSessionTTL)):
		return ErrExpired
	}
	return nil
}

// UnlockActivity is one device call made under an unlock: what the companion
// shows the technician, and what the receipt lists.
type UnlockActivity struct {
	Unlock    string    `json:"unlock"`
	Time      time.Time `json:"time"`
	Op        string    `json:"op"`
	Device    string    `json:"device"`
	Path      string    `json:"path,omitempty"`
	Result    string    `json:"result"` // an audit.Result* value
	ErrorCode string    `json:"error_code,omitempty"`
	Bytes     int64     `json:"bytes"`
}
