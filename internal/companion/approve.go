package companion

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
)

// Approving, denying and locking. The technician proves who they are once, with
// a passkey at sign-in, and every decision rides that sign-in until it ends:
// there is no prompt per card. Approving an unlock or a change builds the
// approval from the card as it is stored now and names the passkey the
// technician signed in with. The gateway checks that the approval signs exactly
// the stored card and that the passkey is still a live one of theirs, then
// applies it.

// errNotYours is a card that does not exist or is another technician's. The
// two answer alike, so the companion never confirms that a card exists.
var errNotYours = fmt.Errorf("companion: no such card: %w", model.ErrNotFound)

func (s *Server) ownUnlock(ctx context.Context, id, technician string) (model.Unlock, error) {
	if !strings.HasPrefix(id, model.PrefixUnlock+"_") {
		return model.Unlock{}, errNotYours
	}
	u, err := s.store.Unlock(ctx, id)
	switch {
	case errors.Is(err, model.ErrNotFound), err == nil && u.Technician != technician:
		return model.Unlock{}, errNotYours
	case err != nil:
		return model.Unlock{}, err
	}
	return u, nil
}

func (s *Server) ownChange(ctx context.Context, id, technician string) (model.ChangeApproval, error) {
	if !strings.HasPrefix(id, model.PrefixChange+"_") {
		return model.ChangeApproval{}, errNotYours
	}
	c, err := s.store.ChangeApproval(ctx, id)
	switch {
	case errors.Is(err, model.ErrNotFound), err == nil && c.Technician != technician:
		return model.ChangeApproval{}, errNotYours
	case err != nil:
		return model.ChangeApproval{}, err
	}
	return c, nil
}

// handleUnlockApprove fixes an awaiting unlock's expiry at now plus its
// duration, with a fresh nonce, and hands the approval of the unlock as stored
// to the gateway.
func (s *Server) handleUnlockApprove(w http.ResponseWriter, r *http.Request, cs model.CompanionSession) {
	if !decode(w, r, &struct{}{}, true) {
		return
	}
	ctx, id, now := r.Context(), r.PathValue("id"), s.now()
	if _, err := s.ownUnlock(ctx, id, cs.Technician); err != nil {
		s.fail(w, err)
		return
	}
	u, err := s.store.UpdateUnlockTx(ctx, id, func(u *model.Unlock) error {
		switch {
		case u.Technician != cs.Technician:
			return errNotYours
		case u.State != model.UnlockAwaiting:
			return fmt.Errorf("unlock %s is %s, not awaiting approval: %w", u.ID, u.State, model.ErrConflict)
		case !now.Before(u.Deadline):
			return fmt.Errorf("unlock %s went unanswered: %w", u.ID, model.ErrExpired)
		}
		exp := now.Add(u.Duration).UTC()
		u.Nonce, u.ExpiresAt = newToken(), &exp
		return nil
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	approval := u.Approval()
	approval.Credential, approval.ApprovedAt = cs.Credential, now.UTC()
	gctx, cancel := s.gateContext(r)
	defer cancel()
	got, err := s.gate.ApproveUnlock(gctx, u.ID, approval)
	if err != nil {
		s.log.Info("unlock approval refused by the gateway", "technician", cs.Technician, "unlock", u.ID, "err", err)
		s.fail(w, err)
		return
	}
	s.log.Info("unlock approved", "technician", cs.Technician, "unlock", u.ID, "client", u.Client, "credential", cs.Credential)
	s.respondUnlock(w, r, got)
}

func (s *Server) handleUnlockDeny(w http.ResponseWriter, r *http.Request, cs model.CompanionSession) {
	s.endUnlock(w, r, cs, "unlock denied", func(ctx context.Context, id string) (model.Unlock, error) {
		return s.gate.DenyUnlock(ctx, id, cs.Technician, cs.Credential)
	})
}

func (s *Server) handleUnlockLock(w http.ResponseWriter, r *http.Request, cs model.CompanionSession) {
	s.endUnlock(w, r, cs, "unlock locked", func(ctx context.Context, id string) (model.Unlock, error) {
		return s.gate.Lock(ctx, id, cs.Technician, model.ReasonLocked)
	})
}

// endUnlock runs a decision that ends one of the technician's unlocks.
func (s *Server) endUnlock(w http.ResponseWriter, r *http.Request, cs model.CompanionSession, what string,
	end func(context.Context, string) (model.Unlock, error)) {
	if !decode(w, r, &struct{}{}, true) {
		return
	}
	id := r.PathValue("id")
	if _, err := s.ownUnlock(r.Context(), id, cs.Technician); err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := s.gateContext(r)
	defer cancel()
	u, err := end(ctx, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.log.Info(what, "technician", cs.Technician, "unlock", id, "state", u.State)
	s.respondUnlock(w, r, u)
}

// changeOpen reports whether c can still be approved at now, answering why
// not.
func changeOpen(w http.ResponseWriter, c model.ChangeApproval, now time.Time) bool {
	switch {
	case c.State != model.ChangeAwaiting:
		writeError(w, http.StatusConflict, codeConflict, "This change is no longer waiting for approval.")
	case !now.Before(c.ExpiresAt):
		writeError(w, http.StatusGone, codeExpired, "This change was not approved in time and has expired.")
	default:
		return true
	}
	return false
}

// handleChangeApprove hands the approval of an awaiting change, as stored, to
// the gateway, which releases it and answers once the endpoint has: applied,
// refused or failed. Nothing about the change moves when it is approved: its
// nonce and expiry were fixed when it was submitted.
func (s *Server) handleChangeApprove(w http.ResponseWriter, r *http.Request, cs model.CompanionSession) {
	if !decode(w, r, &struct{}{}, true) {
		return
	}
	now := s.now()
	c, err := s.ownChange(r.Context(), r.PathValue("id"), cs.Technician)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !changeOpen(w, c, now) {
		return
	}
	approval := c.Approval()
	approval.Credential, approval.ApprovedAt = cs.Credential, now.UTC()
	gctx, cancel := s.gateContext(r)
	defer cancel()
	got, err := s.gate.ApproveChange(gctx, c.ID, approval)
	if err != nil {
		s.log.Info("change approval refused by the gateway", "technician", cs.Technician, "change", c.ID, "err", err)
		s.fail(w, err)
		return
	}
	s.log.Info("change approved", "technician", cs.Technician, "change", c.ID, "op", c.Op, "device", c.Device,
		"state", got.State, "credential", cs.Credential)
	s.respondChange(w, r, got)
}

func (s *Server) handleChangeDeny(w http.ResponseWriter, r *http.Request, cs model.CompanionSession) {
	if !decode(w, r, &struct{}{}, true) {
		return
	}
	id := r.PathValue("id")
	if _, err := s.ownChange(r.Context(), id, cs.Technician); err != nil {
		s.fail(w, err)
		return
	}
	ctx, cancel := s.gateContext(r)
	defer cancel()
	c, err := s.gate.DenyChange(ctx, id, cs.Technician, cs.Credential)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.log.Info("change denied", "technician", cs.Technician, "change", id)
	s.respondChange(w, r, c)
}
