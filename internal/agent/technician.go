package agent

import (
	"cmp"
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// TechnicianConsent is the consent adapter of a managed endpoint (Slice 6).
// Nobody at the machine is asked: the technician unlocked the request's
// client with a passkey in the Keyhole companion, the relay attached that
// unlock to the request, and this adapter approves exactly what was requested
// when the unlock covers it. It answers at once and supervises nothing
// afterwards, so its one update is Final.
//
// Approving here does not widen anything. The runner narrows a grant approved
// this way to the client's policy on every call (authorize), and each change
// made under it still needs the technician's approval of that change
// (fstools).
type TechnicianConsent struct {
	Now    func() time.Time // default time.Now
	Logger *slog.Logger     // default slog.Default(); never given the assertion
}

func (t TechnicianConsent) Request(_ context.Context, cr proto.ConsentRequest) (<-chan proto.ConsentUpdate, error) {
	log := cmp.Or(t.Logger, slog.Default())
	if err := checkUnlock(cr, clock(t.Now)); err != nil {
		log.Warn("refused an access request under a technician unlock", "access", cr.AccessID,
			"unlock", unlockID(cr), "technician", cr.Technician, "reason", err)
		return nil, err
	}
	// Slice 7 verifies the unlock here before approving anything: the
	// assertion cr.Approval.Assertion must be a valid signature over
	// cr.Approval.Challenge() by the passkey cr.Approval.Credential, whose
	// public key the endpoint takes from the MSP-signed technician key list it
	// pinned at enrollment. Until then the endpoint trusts the relay, which has
	// verified the assertion before attaching the unlock.
	a := cr.Approval
	log.Info("approved an access request under a technician unlock", "access", cr.AccessID,
		"unlock", a.ID, "technician", a.Technician, "expires_at", a.ExpiresAt)
	ch := make(chan proto.ConsentUpdate, 1)
	ch <- proto.ConsentUpdate{State: proto.ConsentApproved, Approver: a.ApproverLabel(),
		Paths: slices.Clone(cr.Paths), Operations: slices.Clone(cr.Operations), Final: true}
	close(ch)
	return ch, nil
}

// Activity has nobody to show anything to: on a managed device the person at
// the machine sees nothing from Keyhole, and the companion shows the activity.
func (TechnicianConsent) Activity(proto.ConsentActivity) {}

// RoutedConsent sends each access request to the adapter that decides it. A
// request without a technician unlock is the Slice 3 kind, for the person at
// the machine alone. One with an unlock is approved by Technician, unless the
// client's policy asks the person at the machine as well (EndpointConsent),
// in which case the unlock is checked here and the request then goes to
// Endpoint. Endpoint is nil where there is no consent window: such an
// endpoint serves technician-approved access and refuses everything that
// needs a person.
type RoutedConsent struct {
	Technician ConsentAdapter
	Endpoint   ConsentAdapter
	Now        func() time.Time // default time.Now; checks the unlock of a request bound for Endpoint
}

func (r RoutedConsent) Request(ctx context.Context, cr proto.ConsentRequest) (<-chan proto.ConsentUpdate, error) {
	switch {
	case cr.Approval == nil:
		if r.Endpoint == nil {
			return nil, errConsent("this endpoint has no consent window, so it serves only access a technician unlock authorises")
		}
		return r.Endpoint.Request(ctx, cr)
	case cr.EndpointConsent:
		// The window must never show the person at the machine a request that
		// no valid unlock backs: their approval adds to the technician's, it
		// does not replace it.
		if err := checkUnlock(cr, clock(r.Now)); err != nil {
			return nil, err
		}
		if r.Endpoint == nil {
			return nil, errConsent("this client's policy asks the person at the machine as well, and this endpoint has no consent window to ask them in")
		}
		return r.Endpoint.Request(ctx, cr)
	default:
		if r.Technician == nil {
			return nil, errConsent("this endpoint does not accept technician unlocks")
		}
		return r.Technician.Request(ctx, cr)
	}
}

// Activity goes to the consent window, which shows it only for the grants it
// is holding; it has never seen a grant a technician unlock approved alone.
func (r RoutedConsent) Activity(a proto.ConsentActivity) {
	if r.Endpoint != nil {
		r.Endpoint.Activity(a)
	}
}

// checkUnlock is the endpoint's own check that cr's technician approval
// authorises it: a signed unlock of the request's client by the request's
// technician, not expired by the endpoint's clock (allowing
// proto.ApprovalClockSkew), and outlasting the grant it would create. It
// returns why not, or nil.
func checkUnlock(cr proto.ConsentRequest, now time.Time) error {
	a := cr.Approval
	switch {
	case a == nil:
		return errConsent("this request carries no technician unlock")
	case a.Kind != proto.ApprovalUnlock || a.ID == "" || !a.Signed():
		return errConsent("this request's technician approval is not a signed unlock")
	case a.Client != cr.Client:
		return errConsent("the technician unlock is for another client")
	case a.Technician != cr.Technician:
		return errConsent("the technician unlock belongs to another technician")
	}
	end := a.ExpiresAt.Add(proto.ApprovalClockSkew)
	if !now.Before(end) {
		return errConsent("the technician unlock has expired")
	}
	// The same expiry the runner gives the grant: an unlock ends every grant
	// it authorised, so none may be minted to last longer.
	expires := cr.ExpiresAt
	if expires.IsZero() {
		expires = now.Add(cr.Duration)
	}
	if expires.After(end) {
		return errConsent("the requested access would outlast the technician unlock")
	}
	return nil
}

func unlockID(cr proto.ConsentRequest) string {
	if cr.Approval == nil {
		return ""
	}
	return cr.Approval.ID
}

// clock reads f, or the system clock when f is nil.
func clock(f func() time.Time) time.Time {
	if f == nil {
		return time.Now()
	}
	return f()
}
