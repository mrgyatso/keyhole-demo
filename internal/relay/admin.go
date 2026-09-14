package relay

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/companion"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/version"
)

// Audited actions, as audit.Entry.Tool.
const (
	toolClientCreate  = "client.create"
	toolClientDisable = "client.disable"
	toolClientEnable  = "client.enable"
	toolPolicySet     = "policy.set"
	toolTokenMint     = "token.mint"
	toolTokenRevoke   = "token.revoke"
	toolDeviceRevoke  = "device.revoke"
	toolSessionMint   = "session.mint"
	toolSessionRevoke = "session.revoke"
	toolACLGrant      = "technician_acl.grant"
	toolACLRevoke     = "technician_acl.revoke"
	toolEnroll        = "device.enroll"
)

// Error codes the relay's HTTP APIs add to those in proto.
const (
	codeConflict        = "conflict"
	codeRateLimited     = "rate_limited"
	codeNATSUnavailable = "nats_unavailable"
	codeUnavailable     = "unavailable"
)

// Admin input limits and defaults.
const (
	adminBodyLimit       = 1 << 20
	defaultTokenTTLDays  = 90
	maxTokenTTLDays      = 3650
	defaultDeviceTTLMin  = 60 // temporary install lifetime, when none is given
	defaultSessionTTLMin = 720
	maxSessionTTLMin     = 7 * 24 * 60
	maxNameLen           = 128
	maxNoteLen           = 256
	maxReasonLen         = 512
	maxActorLen          = 128
)

// defaultActor names admin changes made without an X-Keyhole-Actor header.
const defaultActor = "admin"

// errAudit marks a failed audit append.
var errAudit = errors.New("audit entry not written")

// PrivateHandler serves the Tailscale-only listener: health, the admin API
// (admin token required) and the MCP endpoint (the gateway authenticates its
// own bearers).
func (s *Server) PrivateHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(adminapi.RouteHealth, s.handlePrivateHealth)
	mux.HandleFunc("/mcp", s.handleMCP)
	for route, h := range map[string]http.HandlerFunc{
		adminapi.RouteListClients:            s.handleListClients,
		adminapi.RouteCreateClient:           s.handleCreateClient,
		adminapi.RouteGetClient:              s.handleGetClient,
		adminapi.RouteDisableClient:          s.handleDisableClient,
		adminapi.RouteEnableClient:           s.handleEnableClient,
		adminapi.RouteGetPolicy:              s.handleGetPolicy,
		adminapi.RoutePutPolicy:              s.handlePutPolicy,
		adminapi.RouteListTokens:             s.handleListTokens,
		adminapi.RouteMintToken:              s.handleMintToken,
		adminapi.RouteRevokeToken:            s.handleRevokeToken,
		adminapi.RouteListDevices:            s.handleListDevices,
		adminapi.RouteRevokeDevice:           s.handleRevokeDevice,
		adminapi.RouteListSessions:           s.handleListSessions,
		adminapi.RouteMintSession:            s.handleMintSession,
		adminapi.RouteRevokeSession:          s.handleRevokeSession,
		adminapi.RouteListTechnicianClients:  s.handleListTechnicianClients,
		adminapi.RouteGrantTechnicianClient:  s.handleGrantTechnicianClient,
		adminapi.RouteRevokeTechnicianClient: s.handleRevokeTechnicianClient,
		adminapi.RouteMintPasskeyLink:        s.handleMintPasskeyLink,
		adminapi.RouteListPasskeys:           s.handleListPasskeys,
		adminapi.RouteRevokePasskey:          s.handleRevokePasskey,
		adminapi.RouteAuditExport:            s.handleAuditExport,
		adminapi.RouteAuditVerify:            s.handleAuditVerify,
	} {
		mux.Handle(route, s.requireAdmin(h))
	}
	return s.logRequests("private", mux)
}

func (s *Server) technicianACLRequest(w http.ResponseWriter, r *http.Request) (adminapi.TechnicianACLRequest, bool) {
	var req adminapi.TechnicianACLRequest
	if !decodeBody(w, r, adminBodyLimit, &req) {
		return req, false
	}
	req.Technician, req.Client = strings.TrimSpace(req.Technician), strings.TrimSpace(req.Client)
	if req.Technician == "" || !model.ValidSlug(req.Client) {
		badRequest(w, "technician and a valid client slug are required")
		return req, false
	}
	if err := checkText("technician", req.Technician, maxActorLen); err != nil {
		badRequest(w, err.Error())
		return req, false
	}
	if _, err := s.st.Client(r.Context(), req.Client); err != nil {
		s.fail(w, err)
		return req, false
	}
	return req, true
}

func (s *Server) handleListTechnicianClients(w http.ResponseWriter, r *http.Request) {
	technician := strings.TrimSpace(r.URL.Query().Get("technician"))
	if technician == "" {
		badRequest(w, "technician query parameter is required")
		return
	}
	if err := checkText("technician", technician, maxActorLen); err != nil {
		badRequest(w, err.Error())
		return
	}
	clients, err := s.st.ClientsForTechnician(r.Context(), technician)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]adminapi.ClientInfo, 0, len(clients))
	for _, client := range clients {
		info, err := s.clientInfo(r.Context(), client)
		if err != nil {
			s.fail(w, err)
			return
		}
		out = append(out, info)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGrantTechnicianClient(w http.ResponseWriter, r *http.Request) {
	req, ok := s.technicianACLRequest(w, r)
	if !ok {
		return
	}
	already, err := s.st.TechnicianCanAccess(r.Context(), req.Technician, req.Client)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.st.GrantTechnicianClient(r.Context(), req.Technician, req.Client, time.Now().UTC()); err != nil {
		s.fail(w, err)
		return
	}
	err = s.auditAdmin(r.Context(), r, audit.Entry{Client: req.Client, Tool: toolACLGrant}, req)
	if err != nil {
		if !already {
			_ = s.st.RevokeTechnicianClient(r.Context(), req.Technician, req.Client)
		}
		writeError(w, http.StatusInternalServerError, proto.ErrAuditFailed, "no ACL was granted: its audit entry could not be written")
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleRevokeTechnicianClient(w http.ResponseWriter, r *http.Request) {
	req, ok := s.technicianACLRequest(w, r)
	if !ok {
		return
	}
	if err := s.st.RevokeTechnicianClient(r.Context(), req.Technician, req.Client); err != nil {
		s.fail(w, err)
		return
	}
	auditErr := s.auditAdmin(r.Context(), r, audit.Entry{Client: req.Client, Tool: toolACLRevoke}, req)
	respondApplied(w, req, auditErr)
}

// ----- technician passkeys (Slice 6) -----
//
// A passkey belongs to a technician, not to a client, so these changes have
// no client audit chain to go in. They are logged instead, without the link
// secret.

// handleMintPasskeyLink mints a one-time passkey enrollment link. Only the
// hash of its secret is stored; the link, which carries the secret in its
// fragment, is returned once and never logged.
func (s *Server) handleMintPasskeyLink(w http.ResponseWriter, r *http.Request) {
	if s.cfg.CompanionURL == "" {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable,
			"technician approval is off: this relay serves no companion (KEYHOLE_COMPANION_ORIGIN), so there is nowhere to enroll a passkey")
		return
	}
	var req adminapi.PasskeyLinkRequest
	if !decodeBody(w, r, adminBodyLimit, &req) {
		return
	}
	req.Technician = strings.TrimSpace(req.Technician)
	if req.Technician == "" {
		badRequest(w, "technician is required")
		return
	}
	if err := checkText("technician", req.Technician, maxActorLen); err != nil {
		badRequest(w, err.Error())
		return
	}
	secret := model.NewSecret(model.SecretPasskeyLink)
	now := s.now().UTC()
	l := model.PasskeyLink{ID: model.NewID(model.PrefixPasskeyLink), Technician: req.Technician,
		Hash: model.HashSecret(secret), CreatedAt: now, ExpiresAt: now.Add(model.PasskeyLinkTTL)}
	if err := s.st.CreatePasskeyLink(r.Context(), l); err != nil {
		s.fail(w, err)
		return
	}
	s.log.Info("passkey link minted", "technician", l.Technician, "link", l.ID, "expires_at", l.ExpiresAt, "actor", actor(r))
	writeJSON(w, http.StatusOK, adminapi.PasskeyLinkResponse{ID: l.ID, Technician: l.Technician,
		URL: companion.EnrollURL(s.cfg.CompanionURL, secret), ExpiresAt: l.ExpiresAt})
}

func (s *Server) handleListPasskeys(w http.ResponseWriter, r *http.Request) {
	technician := strings.TrimSpace(r.URL.Query().Get("technician"))
	if technician == "" {
		badRequest(w, "technician query parameter is required")
		return
	}
	if err := checkText("technician", technician, maxActorLen); err != nil {
		badRequest(w, err.Error())
		return
	}
	list, err := s.st.PasskeysForTechnician(r.Context(), technician)
	if err != nil {
		s.fail(w, err)
		return
	}
	if list == nil {
		list = []model.Passkey{}
	}
	writeJSON(w, http.StatusOK, list)
}

// handleRevokePasskey revokes a passkey. It can no longer approve, and the
// companion refuses the sign-ins made with it from their next request on.
func (s *Server) handleRevokePasskey(w http.ResponseWriter, r *http.Request) {
	ctx, id := r.Context(), r.PathValue("id")
	if err := s.st.RevokePasskey(ctx, id, s.now()); err != nil {
		s.fail(w, err)
		return
	}
	p, err := s.st.Passkey(ctx, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.log.Info("passkey revoked", "technician", p.Technician, "credential", p.CredentialID, "actor", actor(r))
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handlePrivateHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"version":        version.Version,
		"nats_connected": s.sys != nil && s.sys.IsConnected(),
	})
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if s.cfg.MCP == nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, "the MCP gateway is not configured")
		return
	}
	s.cfg.MCP.ServeHTTP(w, r)
}

// requireAdmin admits requests bearing the admin token. The presented token
// is hashed and compared in constant time with the stored hash.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.adminAuthorized(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="keyhole-admin"`)
			writeError(w, http.StatusUnauthorized, proto.ErrUnauthorized, "missing or invalid admin token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) adminAuthorized(r *http.Request) bool {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	tok = strings.TrimSpace(tok)
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return false
	}
	want, err := s.st.AdminTokenHash(r.Context())
	if err != nil {
		if !errors.Is(err, model.ErrNotFound) {
			s.log.Error("load admin token hash", "err", err)
		}
		return false
	}
	return subtle.ConstantTimeCompare([]byte(model.HashSecret(tok)), []byte(want)) == 1
}

// actor is the self-asserted human behind an admin call, for the audit log.
func actor(r *http.Request) string {
	a := strings.Map(func(c rune) rune {
		if unicode.IsControl(c) {
			return -1
		}
		return c
	}, strings.TrimSpace(r.Header.Get(adminapi.ActorHeader)))
	if a == "" {
		return defaultActor
	}
	return truncate(a, maxActorLen)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// appendAudit fills e's time and args and appends it to the client's chain.
func (s *Server) appendAudit(ctx context.Context, e *audit.Entry, args any) error {
	e.Time = time.Now().UTC()
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return fmt.Errorf("%w: %w", errAudit, err)
		}
		e.Args = b
	}
	if err := s.audit.Append(ctx, e); err != nil {
		s.log.Error("audit append failed", "client", e.Client, "kind", e.Kind, "tool", e.Tool, "err", err)
		return fmt.Errorf("%w: %w", errAudit, err)
	}
	return nil
}

// auditAdmin records a control-plane change made by r's actor.
func (s *Server) auditAdmin(ctx context.Context, r *http.Request, e audit.Entry, args any) error {
	e.Kind, e.Tech, e.Result = audit.KindAdmin, actor(r), audit.ResultOK
	return s.appendAudit(ctx, &e, args)
}

// respondApplied answers a mutation that has taken effect: with v, or, if
// its audit entry could not be written, with an audit_failed error that
// says the change stands.
func respondApplied(w http.ResponseWriter, v any, auditErr error) {
	if auditErr != nil {
		writeError(w, http.StatusInternalServerError, proto.ErrAuditFailed,
			"the change was applied, but its audit entry could not be written")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// fail answers with the HTTP status for err.
func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, model.ErrNotFound):
		writeError(w, http.StatusNotFound, proto.ErrNotFound, err.Error())
	case errors.Is(err, model.ErrConflict):
		writeError(w, http.StatusConflict, codeConflict, err.Error())
	case errors.Is(err, model.ErrInvalid):
		writeError(w, http.StatusBadRequest, proto.ErrBadRequest, err.Error())
	case errors.Is(err, errNATS):
		s.log.Error("nats unavailable", "err", err)
		writeError(w, http.StatusBadGateway, codeNATSUnavailable, err.Error())
	default:
		s.log.Error("admin request failed", "err", err)
		writeError(w, http.StatusInternalServerError, proto.ErrInternal, "internal error")
	}
}

func badRequest(w http.ResponseWriter, msg string) {
	writeError(w, http.StatusBadRequest, proto.ErrBadRequest, msg)
}

// checkText rejects over-long or control-character text.
func checkText(field, v string, max int) error {
	if len(v) > max {
		return fmt.Errorf("%s is longer than %d bytes", field, max)
	}
	if strings.ContainsFunc(v, unicode.IsControl) {
		return fmt.Errorf("%s contains control characters", field)
	}
	return nil
}

// ----- clients -----

func (s *Server) clientInfo(ctx context.Context, c model.Client) (adminapi.ClientInfo, error) {
	devices, err := s.st.Devices(ctx, c.Slug)
	if err != nil {
		return adminapi.ClientInfo{}, err
	}
	info := adminapi.ClientInfo{
		Slug: c.Slug, Name: c.Name, AccountKey: c.AccountKey, Disabled: c.Disabled, CreatedAt: c.CreatedAt,
	}
	now := time.Now()
	for _, d := range devices {
		if d.RevokedAt == nil {
			info.Devices++
			if d.Online(now) {
				info.Online++
			}
		}
	}
	return info, nil
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.st.Clients(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := make([]adminapi.ClientInfo, 0, len(clients))
	for _, c := range clients {
		info, err := s.clientInfo(r.Context(), c)
		if err != nil {
			s.fail(w, err)
			return
		}
		out = append(out, info)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req adminapi.CreateClientRequest
	if !decodeBody(w, r, adminBodyLimit, &req) {
		return
	}
	if !model.ValidSlug(req.Slug) {
		badRequest(w, "slug must be 2-32 characters of a-z, 0-9 and -, not starting with -")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = req.Slug
	}
	if err := checkText("name", req.Name, maxNameLen); err != nil {
		badRequest(w, err.Error())
		return
	}
	ctx := r.Context()
	c, err := s.provisionClient(ctx, req.Slug, req.Name)
	if err != nil {
		s.fail(w, err)
		return
	}
	auditErr := s.auditAdmin(ctx, r, audit.Entry{Client: c.Slug, Tool: toolClientCreate},
		map[string]string{"slug": c.Slug, "name": c.Name, "account_key": c.AccountKey})
	info, err := s.clientInfo(ctx, c)
	if err != nil {
		s.fail(w, err)
		return
	}
	respondApplied(w, info, auditErr)
}

func (s *Server) handleGetClient(w http.ResponseWriter, r *http.Request) {
	c, err := s.st.Client(r.Context(), r.PathValue("slug"))
	if err != nil {
		s.fail(w, err)
		return
	}
	info, err := s.clientInfo(r.Context(), c)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleDisableClient(w http.ResponseWriter, r *http.Request) {
	var req adminapi.DisableRequest
	if !decodeOptionalBody(w, r, adminBodyLimit, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if err := checkText("reason", req.Reason, maxReasonLen); err != nil {
		badRequest(w, err.Error())
		return
	}
	s.setDisabled(w, r, true, req.Reason)
}

func (s *Server) handleEnableClient(w http.ResponseWriter, r *http.Request) {
	s.setDisabled(w, r, false, "")
}

// setDisabled flips the kill switch. The gateway reads Client.Disabled on
// every call, so the change takes effect on the next tool call.
func (s *Server) setDisabled(w http.ResponseWriter, r *http.Request, disabled bool, reason string) {
	ctx := r.Context()
	c, err := s.st.SetDisabled(ctx, r.PathValue("slug"), disabled, reason, time.Now())
	if err != nil {
		s.fail(w, err)
		return
	}
	tool, args := toolClientEnable, any(nil)
	if disabled {
		tool, args = toolClientDisable, map[string]string{"reason": reason}
	}
	s.log.Info("kill switch", "client", c.Slug, "disabled", disabled, "actor", actor(r))
	auditErr := s.auditAdmin(ctx, r, audit.Entry{Client: c.Slug, Tool: tool}, args)
	info, err := s.clientInfo(ctx, c)
	if err != nil {
		s.fail(w, err)
		return
	}
	respondApplied(w, info, auditErr)
}

// ----- policy -----

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := s.st.Policy(r.Context(), r.PathValue("slug"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	var p model.ClientPolicy
	if !decodeBody(w, r, adminBodyLimit, &p) {
		return
	}
	if err := validatePolicy(p); err != nil {
		badRequest(w, "invalid policy: "+err.Error())
		return
	}
	ctx := r.Context()
	stored, err := s.st.SetPolicy(ctx, r.PathValue("slug"), p)
	if err != nil {
		s.fail(w, err)
		return
	}
	auditErr := s.auditAdmin(ctx, r, audit.Entry{Client: r.PathValue("slug"), Tool: toolPolicySet}, stored)
	respondApplied(w, stored, auditErr)
}

// ----- enrollment tokens -----

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if _, err := s.st.Client(r.Context(), slug); err != nil {
		s.fail(w, err)
		return
	}
	toks, err := s.st.Tokens(r.Context(), slug)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toks)
}

func (s *Server) handleMintToken(w http.ResponseWriter, r *http.Request) {
	var req adminapi.MintTokenRequest
	if !decodeOptionalBody(w, r, adminBodyLimit, &req) {
		return
	}
	if req.TTLDays == 0 {
		req.TTLDays = defaultTokenTTLDays
		if req.Ephemeral {
			// A temporary install is used now or not at all.
			req.TTLDays = 1
		}
	}
	if req.Ephemeral {
		if req.DeviceTTLMinutes == 0 {
			req.DeviceTTLMinutes = defaultDeviceTTLMin
		}
		if req.MaxUses == 0 {
			req.MaxUses = 1
		}
	}
	switch {
	case req.TTLDays < 1 || req.TTLDays > maxTokenTTLDays:
		badRequest(w, fmt.Sprintf("ttl_days must be between 1 and %d", maxTokenTTLDays))
		return
	case req.MaxUses < 0:
		badRequest(w, "max_uses must not be negative")
		return
	case req.Ephemeral && req.MaxUses != 1:
		badRequest(w, "an ephemeral token enrolls exactly one device: max_uses must be 1")
		return
	case !req.Ephemeral && req.DeviceTTLMinutes != 0:
		badRequest(w, "device_ttl_minutes applies only to an ephemeral token")
		return
	case req.Ephemeral && (req.DeviceTTLMinutes < 1 || time.Duration(req.DeviceTTLMinutes)*time.Minute > model.MaxDeviceTTL):
		badRequest(w, fmt.Sprintf("device_ttl_minutes must be between 1 and %d", int(model.MaxDeviceTTL/time.Minute)))
		return
	}
	if err := checkText("note", req.Note, maxNoteLen); err != nil {
		badRequest(w, err.Error())
		return
	}
	if err := checkText("technician", req.Technician, maxNameLen); err != nil {
		badRequest(w, err.Error())
		return
	}
	ctx, slug := r.Context(), r.PathValue("slug")
	if _, err := s.st.Client(ctx, slug); err != nil {
		s.fail(w, err)
		return
	}
	secret := model.NewEnrollSecret(slug)
	now := time.Now().UTC()
	tok := model.EnrollToken{
		ID:         model.NewID(model.PrefixToken),
		Client:     slug,
		Hash:       model.HashSecret(secret),
		Note:       req.Note,
		CreatedAt:  now,
		ExpiresAt:  now.AddDate(0, 0, req.TTLDays),
		MaxUses:    req.MaxUses,
		Ephemeral:  req.Ephemeral,
		DeviceTTL:  time.Duration(req.DeviceTTLMinutes) * time.Minute,
		Technician: req.Technician,
	}
	if err := s.st.CreateToken(ctx, tok); err != nil {
		s.fail(w, err)
		return
	}
	err := s.auditAdmin(ctx, r, audit.Entry{Client: slug, Tool: toolTokenMint}, map[string]any{
		"token_id": tok.ID, "expires_at": tok.ExpiresAt, "max_uses": tok.MaxUses, "note": tok.Note,
		"ephemeral": tok.Ephemeral, "device_ttl": tok.DeviceTTL.String(), "technician": tok.Technician,
	})
	if err != nil {
		// A secret whose minting is not on record must not exist.
		if _, rerr := s.st.RevokeToken(ctx, tok.ID, time.Now()); rerr != nil {
			s.log.Error("withdraw unaudited token", "token", tok.ID, "err", rerr)
		}
		writeError(w, http.StatusInternalServerError, proto.ErrAuditFailed,
			"no token was issued: its audit entry could not be written")
		return
	}
	s.log.Info("enrollment token minted", "client", slug, "token", tok.ID, "actor", actor(r))
	writeJSON(w, http.StatusOK, adminapi.MintTokenResponse{Token: tok, Secret: secret})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tok, err := s.st.RevokeToken(ctx, r.PathValue("id"), time.Now())
	if err != nil {
		s.fail(w, err)
		return
	}
	auditErr := s.auditAdmin(ctx, r, audit.Entry{Client: tok.Client, Tool: toolTokenRevoke},
		map[string]string{"token_id": tok.ID})
	respondApplied(w, tok, auditErr)
}

// ----- devices -----

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if _, err := s.st.Client(r.Context(), slug); err != nil {
		s.fail(w, err)
		return
	}
	devices, err := s.st.Devices(r.Context(), slug)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

// handleRevokeDevice revokes a device in the store (the gateway stops
// routing to it at once) and in its account JWT (NATS disconnects it and
// refuses its credential from then on).
func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d, err := s.st.RevokeDevice(ctx, r.PathValue("id"), time.Now())
	if err != nil {
		s.fail(w, err)
		return
	}
	auditErr := s.auditAdmin(ctx, r, audit.Entry{
		Client: d.Client, Tool: toolDeviceRevoke,
		DeviceID: d.ID, DeviceKey: d.PublicKey, Hostname: d.Hostname, AgentVersion: d.AgentVersion,
	}, nil)
	if err := s.syncAccount(ctx, d.Client); err != nil {
		s.log.Error("device revoked in the store; nats revocation pending", "client", d.Client, "device", d.ID, "err", err)
		writeError(w, http.StatusBadGateway, codeNATSUnavailable,
			"the device is revoked in the relay, but NATS has not accepted the revocation yet (it is retried automatically): "+err.Error())
		return
	}
	s.log.Info("device revoked", "client", d.Client, "device", d.ID, "actor", actor(r))
	respondApplied(w, d, auditErr)
}

// ----- sessions -----

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if _, err := s.st.Client(r.Context(), slug); err != nil {
		s.fail(w, err)
		return
	}
	sessions, err := s.st.Sessions(r.Context(), slug)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (s *Server) handleMintSession(w http.ResponseWriter, r *http.Request) {
	var req adminapi.MintSessionRequest
	if !decodeBody(w, r, adminBodyLimit, &req) {
		return
	}
	req.Tech = strings.TrimSpace(req.Tech)
	if req.TTLMinutes == 0 {
		req.TTLMinutes = defaultSessionTTLMin
	}
	switch {
	case req.Tech == "":
		badRequest(w, "tech is required")
		return
	case req.TTLMinutes < 1 || req.TTLMinutes > maxSessionTTLMin:
		badRequest(w, fmt.Sprintf("ttl_minutes must be between 1 and %d", maxSessionTTLMin))
		return
	}
	for _, f := range []struct {
		name, val string
		max       int
	}{{"tech", req.Tech, maxActorLen}, {"note", req.Note, maxNoteLen}} {
		if err := checkText(f.name, f.val, f.max); err != nil {
			badRequest(w, err.Error())
			return
		}
	}
	ctx, slug := r.Context(), r.PathValue("slug")
	if _, err := s.st.Client(ctx, slug); err != nil {
		s.fail(w, err)
		return
	}
	bearer := model.NewSecret(model.SecretSession)
	now := time.Now().UTC()
	ses := model.Session{
		ID:        model.NewID(model.PrefixSession),
		Client:    slug,
		Tech:      req.Tech,
		Hash:      model.HashSecret(bearer),
		Note:      req.Note,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(req.TTLMinutes) * time.Minute),
	}
	if err := s.st.CreateSession(ctx, ses); err != nil {
		s.fail(w, err)
		return
	}
	err := s.auditAdmin(ctx, r, audit.Entry{Client: slug, Tool: toolSessionMint, SessionID: ses.ID}, map[string]any{
		"tech": ses.Tech, "expires_at": ses.ExpiresAt, "note": ses.Note,
	})
	if err != nil {
		if _, rerr := s.st.RevokeSession(ctx, ses.ID, time.Now()); rerr != nil {
			s.log.Error("withdraw unaudited session", "session", ses.ID, "err", rerr)
		}
		writeError(w, http.StatusInternalServerError, proto.ErrAuditFailed,
			"no session was issued: its audit entry could not be written")
		return
	}
	s.log.Info("session minted", "client", slug, "session", ses.ID, "tech", ses.Tech, "actor", actor(r))
	writeJSON(w, http.StatusOK, adminapi.MintSessionResponse{
		Session:          ses,
		Bearer:           bearer,
		MCPURL:           s.cfg.MCPURL,
		ClaudeAddCommand: claudeAddCommand(slug, s.cfg.MCPURL, bearer),
	})
}

// claudeAddCommand is the ready-to-paste command that adds a session's MCP
// server to Claude Code.
func claudeAddCommand(slug, mcpURL, bearer string) string {
	return fmt.Sprintf(`claude mcp add --transport http keyhole-%s %s --header "Authorization: Bearer %s"`,
		slug, mcpURL, bearer)
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ses, err := s.st.RevokeSession(ctx, r.PathValue("id"), time.Now())
	if err != nil {
		s.fail(w, err)
		return
	}
	auditErr := s.auditAdmin(ctx, r, audit.Entry{Client: ses.Client, Tool: toolSessionRevoke, SessionID: ses.ID}, nil)
	respondApplied(w, ses, auditErr)
}
