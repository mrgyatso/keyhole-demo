package model

import (
	"context"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Directory is the read side of the control plane that the MCP gateway
// needs. The relay store implements it.
type Directory interface {
	// SessionByToken resolves an MCP bearer secret. It returns ErrNotFound
	// for an unknown secret; callers check Session.Valid for expiry and
	// revocation.
	SessionByToken(ctx context.Context, bearer string) (Session, error)
	// Client returns a client by slug, or ErrNotFound.
	Client(ctx context.Context, slug string) (Client, error)
	// Devices returns every device of a client, revoked ones included.
	Devices(ctx context.Context, client string) ([]Device, error)
}

// TechnicianAuthenticator validates an identity-provider bearer and returns
// its verified subject and MFA state. Implementations must validate issuer,
// audience, signature, expiry and revocation before returning successfully.
type TechnicianAuthenticator interface {
	AuthenticateTechnician(ctx context.Context, bearer string) (TechnicianSession, error)
}

// TechnicianACL is the durable authorization mapping between an authenticated
// technician subject and the clients that subject may see.
type TechnicianACL interface {
	ClientsForTechnician(ctx context.Context, technician string) ([]Client, error)
	TechnicianCanAccess(ctx context.Context, technician, client string) (bool, error)
}

// AccessStore is the durable consent state used by the gateway.
type AccessStore interface {
	CreateAccess(context.Context, AccessRequest) error
	Access(context.Context, string) (AccessRequest, error)
	UpdateAccess(context.Context, AccessRequest) error
	// UpdateAccessTx applies fn to the request as it is stored now, under a
	// transaction, and returns the stored row. fn returns an error wrapping
	// ErrConflict to leave the row untouched; the row is returned either way.
	UpdateAccessTx(ctx context.Context, id string, fn func(*AccessRequest) error) (AccessRequest, error)
}

// ApprovalStore is the durable state of technician approval (Slice 6):
// passkeys and their one-time enrollment links, companion sign-ins, client
// unlocks and what was done under them, and the prepared plans and change
// approvals that gate every write. The relay store implements it.
type ApprovalStore interface {
	CreatePasskeyLink(ctx context.Context, l PasskeyLink) error
	// PasskeyLinkByToken returns the link for a one-time enrollment secret if
	// it can still be used at now, and an error wrapping ErrNotFound,
	// ErrExpired or ErrExhausted otherwise.
	PasskeyLinkByToken(ctx context.Context, secret string, now time.Time) (PasskeyLink, error)
	// UsePasskeyLink consumes the link and stores the passkey it enrolled, in
	// one transaction. The passkey must belong to the link's technician; one
	// already enrolled is ErrConflict.
	UsePasskeyLink(ctx context.Context, linkID string, p Passkey, now time.Time) error
	Passkey(ctx context.Context, credentialID string) (Passkey, error)
	// PasskeysForTechnician returns every passkey of a technician, revoked
	// ones included, oldest first.
	PasskeysForTechnician(ctx context.Context, technician string) ([]Passkey, error)
	// TouchPasskey records a verified assertion: its sign count and time.
	TouchPasskey(ctx context.Context, credentialID string, signCount uint32, at time.Time) error
	RevokePasskey(ctx context.Context, credentialID string, at time.Time) error

	CreateCompanionSession(ctx context.Context, s CompanionSession) error
	// CompanionSessionByToken resolves a sign-in cookie secret by its hash.
	// Callers check CompanionSession.Valid.
	CompanionSessionByToken(ctx context.Context, secret string) (CompanionSession, error)
	// RevokeCompanionSessions signs a technician out of the companion
	// everywhere.
	RevokeCompanionSessions(ctx context.Context, technician string, at time.Time) error

	CreateUnlock(ctx context.Context, u Unlock) error
	Unlock(ctx context.Context, id string) (Unlock, error)
	// UpdateUnlockTx applies fn to the unlock as it is stored now, under a
	// transaction, and returns the stored row. fn returns an error wrapping
	// ErrConflict to leave it untouched; the row is returned either way.
	UpdateUnlockTx(ctx context.Context, id string, fn func(*Unlock) error) (Unlock, error)
	// ActivateUnlockTx is UpdateUnlockTx for an approval: fn must leave the
	// unlock active, and in the same transaction every other active unlock of
	// the same technician is locked with ReasonSwitched at now. It returns the
	// stored unlock and the unlocks it locked.
	ActivateUnlockTx(ctx context.Context, id string, fn func(*Unlock) error, now time.Time) (Unlock, []Unlock, error)
	// UnlockFor returns the technician's most recent unlock of client that is
	// in one of states, or ErrNotFound.
	UnlockFor(ctx context.Context, technician, client string, states ...string) (Unlock, error)
	// Unlocks returns a technician's open unlocks and those requested at or
	// after since, newest first.
	Unlocks(ctx context.Context, technician string, since time.Time) ([]Unlock, error)
	// UnlocksOpen returns every unlock awaiting approval or active, for the
	// reconcile loop.
	UnlocksOpen(ctx context.Context) ([]Unlock, error)
	// RecordUnlockUse records one device call under an unlock: its activity
	// row, the call count, the device, and the last-used time.
	RecordUnlockUse(ctx context.Context, id string, a UnlockActivity) error
	// UnlockActivity returns up to limit of an unlock's activity rows, newest
	// first.
	UnlockActivity(ctx context.Context, id string, limit int) ([]UnlockActivity, error)
	// AccessForUnlock returns the access requests made under or waiting for
	// an unlock, oldest first.
	AccessForUnlock(ctx context.Context, unlockID string) ([]AccessRequest, error)

	// CreateChangePlan stores the relay's copy of a prepared plan; a plan ID
	// already stored is ErrConflict.
	CreateChangePlan(ctx context.Context, p ChangePlanRecord) error
	ChangePlan(ctx context.Context, planID string) (ChangePlanRecord, error)
	CreateChangeApproval(ctx context.Context, c ChangeApproval) error
	ChangeApproval(ctx context.Context, id string) (ChangeApproval, error)
	// UpdateChangeApprovalTx has UpdateUnlockTx's contract, for change
	// approvals.
	UpdateChangeApprovalTx(ctx context.Context, id string, fn func(*ChangeApproval) error) (ChangeApproval, error)
	// ChangeApprovalFor returns the most recent approval of op on a plan under
	// an access grant that is in one of states, or ErrNotFound.
	ChangeApprovalFor(ctx context.Context, accessID, planID, op string, states ...string) (ChangeApproval, error)
	// ChangeApprovals returns a technician's open change approvals and those
	// requested at or after since, newest first.
	ChangeApprovals(ctx context.Context, technician string, since time.Time) ([]ChangeApproval, error)
	// ChangeApprovalsOpen returns every change approval awaiting approval or
	// approved, for the reconcile loop.
	ChangeApprovalsOpen(ctx context.Context) ([]ChangeApproval, error)

	// PurgeApprovals deletes what technician approval no longer needs: the
	// activity of unlocks that ended before cutoff, plans prepared before
	// cutoff that no open change approval names, and passkey links and
	// companion sign-ins that expired before cutoff. It reports how many rows
	// it deleted.
	PurgeApprovals(ctx context.Context, cutoff time.Time) (int64, error)
}

// ApprovalGate is what the companion calls once a technician has proved
// presence with a passkey. The gateway implements it: it applies a decision's
// effects (activating an unlock and forwarding the access requests waiting for
// it, ending grants, releasing a change to its endpoint) and audits them.
//
// approval is the signed approval exactly as the companion verified it. The
// gateway still checks that it signs what the stored row says now, and that
// its credential is a live passkey of the row's technician. Deny and lock
// reduce authority, so they need only the technician's sign-in.
type ApprovalGate interface {
	ApproveUnlock(ctx context.Context, id string, approval proto.TechnicianApproval) (Unlock, error)
	DenyUnlock(ctx context.Context, id, technician, credential string) (Unlock, error)
	Lock(ctx context.Context, id, technician, reason string) (Unlock, error)
	LockAll(ctx context.Context, technician, reason string) error
	// ApproveChange releases the change and returns once the endpoint has
	// answered or the release has failed.
	ApproveChange(ctx context.Context, id string, approval proto.TechnicianApproval) (ChangeApproval, error)
	DenyChange(ctx context.Context, id, technician, credential string) (ChangeApproval, error)
}

// Conns hands out the relay's NATS connection inside a client's account.
// That connection is the only route from the relay to a client's devices,
// and it cannot see any other client's subjects.
type Conns interface {
	// Conn returns the connection for client, or an error wrapping
	// ErrNotFound if the relay has no connection for it.
	Conn(client string) (*nats.Conn, error)
}
