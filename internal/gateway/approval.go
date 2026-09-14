package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Technician approval (Slice 6). With Config.Approvals set, an access request
// waits for the technician to unlock its client in the companion, and a change
// waits for the technician to approve it there. unlock.go holds the first half
// and gate.go the second; the companion reaches both through
// model.ApprovalGate. Without Approvals the gateway keeps the Slice 3
// endpoint-consent flow. See docs/handoffs/2026-09-11-slice-6-contract.md.

var _ model.ApprovalGate = (*Gateway)(nil)

// errNotBuilt marks the parts of the contract the Slice 6 agents fill in.
var errNotBuilt = errors.New("gateway: technician approval is not built yet")

// reconcileInterval is how often Run applies technician approval's deadlines.
const reconcileInterval = 15 * time.Second

// technicianApproval reports whether access and changes go through the
// companion.
func (g *Gateway) technicianApproval() bool { return g.approvals != nil }

// companionLink is the companion page of one unlock card ("u") or change
// card ("c").
func (g *Gateway) companionLink(kind, id string) string {
	if g.companion == "" {
		return ""
	}
	return g.companion + "/" + kind + "/" + id
}

// checkApproval is the gateway's own check of an approval the companion made
// on the technician's sign-in: it must sign exactly what the stored row says
// now (want), record who approved and when, and name a live passkey of the
// row's technician, the one they signed in with. An approval of something
// else, or by someone else, is never taken as approval of this row. Every gate
// method that grants runs it first.
func (g *Gateway) checkApproval(ctx context.Context, technician string, want, got proto.TechnicianApproval) error {
	switch {
	case got.Kind != want.Kind || !got.SameSigned(want):
		return fmt.Errorf("gateway: the approval does not sign %s %s as it stands now: %w", want.Kind, want.ID, model.ErrInvalid)
	case !got.Signed():
		return fmt.Errorf("gateway: the approval of %s is not signed: %w", want.ID, model.ErrInvalid)
	}
	p, err := g.approvals.Passkey(ctx, got.Credential)
	switch {
	case errors.Is(err, model.ErrNotFound):
		return fmt.Errorf("gateway: the approval of %s names an unknown passkey: %w", want.ID, model.ErrInvalid)
	case err != nil:
		return err
	case p.Technician != technician:
		return fmt.Errorf("gateway: the approval of %s was signed with another technician's passkey: %w", want.ID, model.ErrInvalid)
	case p.Live() != nil:
		return fmt.Errorf("gateway: the approval of %s was signed with a revoked passkey: %w", want.ID, model.ErrRevoked)
	}
	return nil
}

// Run applies technician approval's own deadlines until ctx ends: it expires
// unanswered and idle unlocks and ends their grants, expires unanswered change
// approvals, retries releases whose outcome was lost, and purges what is no
// longer needed. The endpoint enforces its own deadlines as well; this is the
// relay doing its half. Run returns at once when technician approval is off.
func (g *Gateway) Run(ctx context.Context) {
	if !g.technicianApproval() {
		return
	}
	t := time.NewTicker(reconcileInterval)
	defer t.Stop()
	for {
		g.reconcileUnlocks(ctx)
		g.reconcileChanges(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
