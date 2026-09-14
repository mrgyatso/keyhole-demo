package relay

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Temporary installation (Slice 4). Three pieces live here: the public
// pre-enrolment offer the endpoint user consents to, the sweep that revokes
// expired temporary devices, and the relay's half of an endpoint's
// self-revocation.
const (
	toolDeviceExpire     = "device.expire"
	toolDeviceSelfRevoke = "device.self_revoke"
)

// maxOfferPaths bounds how much of a client's allow list the offer shows.
const maxOfferPaths = 12

// handleTempOffer answers "what would this install let the MSP do?" before
// anything is installed. The technician's own command line is not a
// trustworthy source for that, so the endpoint reads the terms from the relay
// that minted the token.
//
// It consumes no token use and hands out no credential. Every unusable token
// gets the same invalid_token refusal as enrolment, so this is no better an
// oracle than the enrolment route it precedes, and it shares the per-IP rate
// limit.
func (s *Server) handleTempOffer(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.limiter.allow(ip) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, codeRateLimited, "too many enrollment attempts; retry later")
		return
	}
	var req proto.TempOfferRequest
	if !decodeBody(w, r, enrollBodyLimit, &req) {
		return
	}
	switch {
	case len(req.Token) > maxEnrollField || len(req.OS) > maxEnrollField:
		writeError(w, http.StatusBadRequest, proto.ErrBadRequest, "token or os is too long")
		return
	case strings.TrimSpace(req.Token) == "":
		writeError(w, http.StatusBadRequest, proto.ErrBadRequest, "token is required")
		return
	case req.OS != "" && !supportedOS[req.OS]:
		writeError(w, http.StatusBadRequest, proto.ErrBadRequest, "os must be windows, linux or darwin")
		return
	}
	ctx := r.Context()
	refuse := func(err error) {
		s.log.Info("temporary offer refused", "ip", ip, "err", err)
		writeError(w, http.StatusUnauthorized, proto.ErrInvalidToken, "the enrollment token is not valid")
	}
	tok, err := s.st.TokenBySecret(ctx, strings.TrimSpace(req.Token))
	if err != nil {
		refuse(err)
		return
	}
	if err := tok.Usable(time.Now()); err != nil {
		refuse(err)
		return
	}
	if !tok.Ephemeral {
		// A managed token installs a permanent service; it has no temporary
		// offer to consent to, and saying so leaks nothing a valid holder
		// does not already know.
		writeError(w, http.StatusConflict, proto.ErrBadRequest,
			"this token enrolls a managed installation, not a temporary one; run: keyhole-agent install")
		return
	}
	client, err := s.st.Client(ctx, tok.Client)
	if err != nil {
		s.log.Error("temporary offer: client lookup", "client", tok.Client, "err", err)
		writeError(w, http.StatusInternalServerError, proto.ErrInternal, "offer unavailable")
		return
	}
	if client.Disabled {
		writeError(w, http.StatusForbidden, proto.ErrClientDisabled, "the MSP has switched off access for this client")
		return
	}
	writeJSON(w, http.StatusOK, proto.TempOffer{
		Client:      client.Slug,
		ClientName:  client.Name,
		Technician:  tok.Technician,
		Reason:      tok.Note,
		Operations:  slices.Clone(proto.ReadOps),
		Paths:       offerPaths(client.Policy, req.OS),
		MaxDuration: tok.DeviceTTL,
		Ephemeral:   true,
	})
}

// offerPaths summarises what the client's policy currently allows on this OS.
// It is what the user is shown, not what is enforced: the endpoint applies the
// policy it is sent on every call, plus its compiled-in hard-deny list.
func offerPaths(p model.ClientPolicy, goos string) []string {
	if goos == "" {
		return nil
	}
	rules := p.Allow[goos]
	out := make([]string, 0, min(len(rules), maxOfferPaths))
	for _, rule := range rules {
		if len(out) == maxOfferPaths {
			break
		}
		out = append(out, rule.Path)
	}
	return out
}

// expireTemporaryDevices revokes every temporary device past its deadline and
// pushes the revocation into its client's account JWT. It runs at the top of
// each reconcile, so the same pass re-signs the account.
//
// This is what actually ends a temporary session. The endpoint revokes itself
// too, but a machine that was switched off, killed or disconnected at its
// deadline is revoked here regardless.
func (s *Server) expireTemporaryDevices(ctx context.Context) {
	expired, err := s.st.ExpireEphemeralDevices(ctx, s.now())
	if err != nil {
		s.log.Error("reconcile: expire temporary devices", "err", err)
		return
	}
	for _, d := range expired {
		s.log.Info("temporary device expired", "client", d.Client, "device", d.ID,
			"hostname", d.Hostname, "expires_at", d.ExpiresAt)
		s.auditDeviceRevocation(ctx, d, toolDeviceExpire, "expired")
	}
}

// auditDeviceRevocation records a revocation the relay made without an admin
// actor. A failed append cannot undo the revocation, which is the fail-closed
// direction, so it is logged rather than retried.
func (s *Server) auditDeviceRevocation(ctx context.Context, d model.Device, tool, reason string) {
	err := s.appendAudit(ctx, &audit.Entry{
		Kind:         audit.KindAdmin,
		Client:       d.Client,
		DeviceID:     d.ID,
		DeviceKey:    d.PublicKey,
		Hostname:     d.Hostname,
		AgentVersion: d.AgentVersion,
		Tech:         "relay",
		Tool:         tool,
		Result:       audit.ResultOK,
	}, map[string]any{"reason": reason, "ephemeral": d.Ephemeral, "expires_at": d.ExpiresAt})
	if err != nil {
		s.log.Error("revocation not audited", "client", d.Client, "device", d.ID, "tool", tool, "err", err)
	}
}

// onDeviceSelfRevoked is the ConnManager's callback for an endpoint that gave
// up its own credential: audit it and get the revocation into NATS now,
// rather than waiting for the next reconcile.
func (s *Server) onDeviceSelfRevoked(d model.Device, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), reconcileInterval)
	defer cancel()
	s.log.Info("device revoked its own credential", "client", d.Client, "device", d.ID,
		"hostname", d.Hostname, "reason", reason)
	s.auditDeviceRevocation(ctx, d, toolDeviceSelfRevoke, reason)
	if err := s.syncAccount(ctx, d.Client); err != nil {
		s.log.Warn("self-revocation not yet pushed to nats; will retry", "client", d.Client, "device", d.ID, "err", err)
	}
}

// selfRevoke records a device's own revoke event. The subject already proved
// which device published it (a device credential may publish only its own
// subjects), so the payload is a cross-check: an event whose body names a
// different device is refused, and one for another client's device cannot be
// found at all.
func (m *ConnManager) selfRevoke(ctx context.Context, client, id string, rev proto.Revoke) error {
	if rev.DeviceID != "" && rev.DeviceID != id {
		return fmt.Errorf("revoke event on %s names device %q: %w", id, rev.DeviceID, model.ErrInvalid)
	}
	d, err := m.st.RevokeDeviceOwned(ctx, client, id, time.Now())
	if err != nil {
		return err
	}
	if m.onSelfRevoke != nil {
		go m.onSelfRevoke(d, revokeReason(rev.Reason))
	}
	return nil
}

// revokeReason bounds the self-reported reason to the known ones; anything
// else is recorded as "unspecified" rather than echoed into the audit log.
func revokeReason(s string) string {
	switch s {
	case proto.RevokeExpired, proto.RevokeTerminated, proto.RevokeInterrupted:
		return s
	default:
		return "unspecified"
	}
}
