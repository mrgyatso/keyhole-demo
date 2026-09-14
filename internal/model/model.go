// Package model holds the control plane's domain types, shared by the relay
// store, the MCP gateway and the admin API.
package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Sentinel errors for lookups. Wrap them; callers use errors.Is.
var (
	ErrNotFound  = errors.New("not found")
	ErrExpired   = errors.New("expired")
	ErrRevoked   = errors.New("revoked")
	ErrExhausted = errors.New("max uses reached")
	ErrConflict  = errors.New("already exists")
	ErrInvalid   = errors.New("invalid")
	ErrPaused    = errors.New("paused")
	// ErrPending is a request or unlock nobody has decided yet: the person at
	// the machine, or, under technician approval, the technician.
	ErrPending = errors.New("still waiting for approval")
)

// Client is one MSP customer. It maps 1:1 to a NATS account.
type Client struct {
	Slug       string       `json:"slug"`
	Name       string       `json:"name"`
	AccountKey string       `json:"account_key"` // NATS account public key ("A…")
	Disabled   bool         `json:"disabled"`    // kill switch: the gateway refuses every call
	CreatedAt  time.Time    `json:"created_at"`
	Policy     ClientPolicy `json:"policy"`
}

// ClientPolicy is a client's editable scope. Allow is keyed by GOOS
// ("windows", "linux", "darwin").
type ClientPolicy struct {
	Version            int                          `json:"version"`
	Allow              map[string][]proto.AllowRule `json:"allow"`
	MaxReadBytes       int64                        `json:"max_read_bytes"`
	MaxFileBytes       int64                        `json:"max_file_bytes"`
	MaxListEntries     int                          `json:"max_list_entries"`
	MaxMatches         int                          `json:"max_matches"`
	SessionBudgetBytes int64                        `json:"session_budget_bytes"` // content bytes one MCP session may receive; enforced by the relay
	Redact             bool                         `json:"redact"`
	// ServiceAllow names the services service_restart may restart on this
	// client's devices. Empty, the default, means none. It is client policy,
	// set by the MSP, never something a technician or the assistant supplies.
	ServiceAllow []string `json:"service_allow,omitempty"`
	// EndpointConsent asks the person at the machine to approve each access
	// request as well as the technician (Slice 6). Off by default: on a
	// managed device Keyhole works in the background, like the RMM agent.
	EndpointConsent bool `json:"endpoint_consent,omitempty"`
}

// For returns the per-call policy the relay sends to a device running goos.
func (p ClientPolicy) For(goos string) proto.Policy {
	return proto.Policy{
		Version:        p.Version,
		Allow:          append([]proto.AllowRule(nil), p.Allow[goos]...),
		MaxReadBytes:   p.MaxReadBytes,
		MaxFileBytes:   p.MaxFileBytes,
		MaxListEntries: p.MaxListEntries,
		MaxMatches:     p.MaxMatches,
		Redact:         p.Redact,
		ServiceAllow:   append([]string(nil), p.ServiceAllow...),
	}
}

// Device is one enrolled endpoint. Its identity is its NATS user public key.
type Device struct {
	ID            string     `json:"id"` // "dev_…"
	Client        string     `json:"client"`
	PublicKey     string     `json:"public_key"` // NATS user NKey ("U…"); the credential fingerprint in audit
	Hostname      string     `json:"hostname"`
	MachineID     string     `json:"machine_id"`
	OS            string     `json:"os"`
	OSVersion     string     `json:"os_version"`
	Arch          string     `json:"arch"`
	AgentVersion  string     `json:"agent_version"`
	EnrolledAt    time.Time  `json:"enrolled_at"`
	EnrollTokenID string     `json:"enroll_token_id"`
	LastSeen      *time.Time `json:"last_seen,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	// Ephemeral marks a temporary-install device: it enrolled with a one-use
	// ephemeral token and dies at ExpiresAt whether or not the endpoint is
	// reachable. ExpiresAt is nil for a managed device.
	Ephemeral bool       `json:"ephemeral,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Expired reports whether a temporary device's session is over. The relay's
// reconcile loop turns this into a real revocation; until it runs, every
// admission check must already treat an expired device as revoked.
func (d Device) Expired(now time.Time) bool {
	return d.ExpiresAt != nil && !now.Before(*d.ExpiresAt)
}

// Online reports whether the device has been heard from recently.
func (d Device) Online(now time.Time) bool {
	return d.RevokedAt == nil && !d.Expired(now) &&
		d.LastSeen != nil && now.Sub(*d.LastSeen) < proto.OnlineWindow
}

// EnrollToken is a per-client, reusable, expiring enrollment secret. Only
// the hash of the secret is stored.
type EnrollToken struct {
	ID        string     `json:"id"` // "tok_…"
	Client    string     `json:"client"`
	Hash      string     `json:"-"`
	Note      string     `json:"note,omitempty"` // shown to the endpoint user as the reason
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	MaxUses   int        `json:"max_uses"` // 0 = unlimited
	Uses      int        `json:"uses"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// Ephemeral marks a temporary-install token: exactly one device, which
	// expires DeviceTTL after it enrolls. Technician is the identity shown to
	// the endpoint user before the install; it grants nothing.
	Ephemeral  bool          `json:"ephemeral,omitempty"`
	DeviceTTL  time.Duration `json:"device_ttl,omitempty"`
	Technician string        `json:"technician,omitempty"`
}

// MaxDeviceTTL caps how long one temporary install may live.
const MaxDeviceTTL = 12 * time.Hour

// ValidEphemeral checks the invariants of a temporary-install token: one use,
// and a device lifetime between a minute and MaxDeviceTTL.
func (t EnrollToken) ValidEphemeral() error {
	if !t.Ephemeral {
		return nil
	}
	if t.MaxUses != 1 || t.DeviceTTL < time.Minute || t.DeviceTTL > MaxDeviceTTL {
		return ErrInvalid
	}
	return nil
}

// Usable reports whether the token can enroll another device at now.
func (t EnrollToken) Usable(now time.Time) error {
	switch {
	case t.RevokedAt != nil:
		return ErrRevoked
	case !now.Before(t.ExpiresAt):
		return ErrExpired
	case t.MaxUses > 0 && t.Uses >= t.MaxUses:
		return ErrExhausted
	}
	return nil
}

// Session is an MCP bearer credential for one tech on one client. The
// relay mints it; Claude's own credentials are never passed through.
type Session struct {
	ID        string     `json:"id"` // "ses_…"
	Client    string     `json:"client"`
	Tech      string     `json:"tech"`
	Hash      string     `json:"-"`
	Note      string     `json:"note,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// TechnicianSession is an authenticated MSP technician identity returned by
// an external identity provider. ID is the provider session identifier used
// for budgets and audit correlation; Technician is the provider's stable
// subject, never an email address supplied by the MCP client.
type TechnicianSession struct {
	ID         string
	Technician string
	Name       string
	MFA        bool
	ExpiresAt  time.Time
}

// Valid requires both a live identity-provider session and MFA. The gateway
// checks it on every request, not only when the MCP connection is created.
func (s TechnicianSession) Valid(now time.Time) error {
	switch {
	case s.ID == "" || s.Technician == "" || !s.MFA:
		return ErrInvalid
	case !now.Before(s.ExpiresAt):
		return ErrExpired
	}
	return nil
}

// Valid reports whether the session can be used at now.
func (s Session) Valid(now time.Time) error {
	switch {
	case s.RevokedAt != nil:
		return ErrRevoked
	case !now.Before(s.ExpiresAt):
		return ErrExpired
	}
	return nil
}

// ID prefixes.
const (
	PrefixDevice  = "dev"
	PrefixToken   = "tok"
	PrefixSession = "ses"
	PrefixRequest = "req"
	PrefixAccess  = "acc"
	PrefixGrant   = "grt"
)

// Access states. The ones the endpoint itself reports are the protocol's own
// strings, so the durable record and the wire can never drift apart.
const (
	AccessRequested = "requested"
	// AccessAwaitingUnlock waits for the technician to unlock the request's
	// client in the companion (Slice 6); the endpoint has not seen it yet.
	AccessAwaitingUnlock = "awaiting_unlock"
	AccessAwaiting       = proto.ConsentAwaiting
	AccessNarrowed       = proto.ConsentNarrowed
	AccessApproved       = proto.ConsentApproved
	AccessActive         = "active"
	AccessPaused         = proto.ConsentPaused
	AccessDenied         = proto.ConsentDenied
	AccessExpired        = "expired"
	AccessTerminated     = proto.ConsentTerminated
)

// AccessTerminal reports whether state is final: nothing, not even the
// endpoint, may move a request out of it.
func AccessTerminal(state string) bool {
	return state == AccessDenied || state == AccessExpired || state == AccessTerminated
}

// AccessAdvance reports whether a stored request in state cur may move to
// next. It is the one transition rule for every writer: the relay applying
// an endpoint event and the gateway applying its own deadlines, activation
// and end_access each check it against the row they replace, inside the same
// transaction. Which writer may cause which move is the writer's business:
// only the endpoint decides, pauses and resumes, and only the gateway marks a
// grant active or expired, or moves a request waiting for an unlock on to the
// endpoint.
//
// A request never goes backwards: a terminal state is permanent and a
// decision cannot be un-made. Reducing authority is always possible, so every
// state a request can rest in can still be denied, terminated or expired;
// that is what makes a grant fail closed. Narrowed is an approval of part of
// the request: it is recorded and audited, and approved follows it in the
// same transaction, so it never rests in the store.
func AccessAdvance(cur, next string) bool {
	if AccessTerminal(cur) || cur == next {
		return false
	}
	if AccessTerminal(next) {
		return true
	}
	switch next {
	case AccessAwaitingUnlock:
		return cur == AccessRequested
	case AccessAwaiting:
		// A request reaches the endpoint when it is made or, under technician
		// approval, once the technician has unlocked its client.
		return cur == AccessRequested || cur == AccessAwaitingUnlock
	case AccessNarrowed:
		return cur == AccessAwaiting
	case AccessApproved:
		// A decision lands on a request awaiting one, directly or through
		// narrowed. Resuming returns a paused grant to approved; the next call
		// makes it active again.
		return cur == AccessAwaiting || cur == AccessNarrowed || cur == AccessPaused
	case AccessActive:
		return cur == AccessApproved
	case AccessPaused:
		// Only something already granted can be paused.
		return cur == AccessApproved || cur == AccessNarrowed || cur == AccessActive
	}
	return false
}

// AccessRequest is the durable consent record. Scope contains endpoint-native
// absolute path roots and Operations contains protocol operation names.
type AccessRequest struct {
	ID                  string        `json:"id"`
	Client              string        `json:"client"`
	Device              string        `json:"device"`
	Technician          string        `json:"technician"`
	Session             string        `json:"session"`
	Purpose             string        `json:"purpose"`
	State               string        `json:"state"`
	RequestedScope      []string      `json:"requested_scope"`
	EffectiveScope      []string      `json:"effective_scope"`
	RequestedOperations []string      `json:"requested_operations"`
	EffectiveOperations []string      `json:"effective_operations"`
	RequestedAt         time.Time     `json:"requested_at"`
	ExpiresAt           time.Time     `json:"expires_at"`
	IdleTimeout         time.Duration `json:"idle_timeout"`
	GrantID             string        `json:"-"`
	Nonce               string        `json:"-"`
	Approver            string        `json:"approver,omitempty"`
	ApproverSession     string        `json:"approver_session,omitempty"` // OS session the approver answered in
	Reason              string        `json:"reason,omitempty"`
	// PlanDigest is the change plan this grant may apply: the digest the
	// endpoint issued for the most recent prepare under this grant. An apply
	// that quotes any other digest is refused at the relay, and again at the
	// endpoint, which holds the plan itself.
	PlanDigest string `json:"plan_digest,omitempty"`
	// Unlock is the technician unlock the request was made under or is
	// waiting for (Slice 6); empty for a request the person at the machine
	// decides alone.
	Unlock string `json:"unlock,omitempty"`
	// EndpointConsent says the person at the machine must approve the request
	// as well as the technician, because the client's policy asks for that.
	EndpointConsent bool       `json:"endpoint_consent,omitempty"`
	PolicyVersion   int        `json:"policy_version"`
	ConsentDeadline *time.Time `json:"consent_deadline,omitempty"` // undecided after this is refused
	DecidedAt       *time.Time `json:"decided_at,omitempty"`
	PausedAt        *time.Time `json:"paused_at,omitempty"`
	TerminatedAt    *time.Time `json:"terminated_at,omitempty"`
	EventSeq        uint64     `json:"-"` // last endpoint consent event applied
}

// Usable reports whether an operation may run under this grant now. A
// pending, paused, denied, expired or terminated request fails closed, and
// the endpoint checks the same thing again for itself.
func (a AccessRequest) Usable(now time.Time) error {
	switch {
	case a.State == AccessTerminated:
		return ErrRevoked
	case a.State == AccessPaused:
		return ErrPaused
	case a.State == AccessRequested || a.State == AccessAwaiting || a.State == AccessAwaitingUnlock:
		return ErrPending
	case a.State != AccessApproved && a.State != AccessActive:
		return ErrInvalid
	case !now.Before(a.ExpiresAt):
		return ErrExpired
	}
	return nil
}

// ConsentOverdue reports whether an undecided request has outlived the
// endpoint's consent window, which the relay enforces independently.
func (a AccessRequest) ConsentOverdue(now time.Time) bool {
	if a.State != AccessRequested && a.State != AccessAwaiting && a.State != AccessAwaitingUnlock {
		return false
	}
	deadline := a.RequestedAt.Add(proto.ConsentTimeout)
	if a.ConsentDeadline != nil {
		deadline = *a.ConsentDeadline
	}
	return !now.Before(deadline)
}

// Secret prefixes. They make leaked secrets greppable and self-describing.
const (
	SecretEnroll  = "khe" // enrollment token: khe_<client>_<random>
	SecretSession = "khs" // MCP bearer token
	SecretAdmin   = "kha" // admin API token
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func randomString(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return strings.ToLower(b32.EncodeToString(b))
}

// NewID returns prefix_ plus 80 random bits.
func NewID(prefix string) string { return prefix + "_" + randomString(10) }

// NewSecret returns prefix_ plus 160 random bits.
func NewSecret(prefix string) string { return prefix + "_" + randomString(20) }

// NewEnrollSecret returns an enrollment token secret that names its client,
// so an installer can show which client a token is for without a lookup.
// The client in the secret is a hint only; the relay trusts the stored
// token record, never the string.
func NewEnrollSecret(client string) string {
	return SecretEnroll + "_" + client + "_" + randomString(20)
}

// EnrollSecretClient returns the client slug embedded in an enrollment secret.
func EnrollSecretClient(secret string) (string, bool) {
	rest, ok := strings.CutPrefix(secret, SecretEnroll+"_")
	if !ok {
		return "", false
	}
	i := strings.LastIndex(rest, "_")
	if i <= 0 {
		return "", false
	}
	return rest[:i], ValidSlug(rest[:i])
}

// HashSecret is how every secret (enrollment, session, admin) is stored.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)

// ValidSlug reports whether s can name a client: 2-32 of [a-z0-9-], not
// starting with a hyphen.
func ValidSlug(s string) bool { return slugRE.MatchString(s) }
