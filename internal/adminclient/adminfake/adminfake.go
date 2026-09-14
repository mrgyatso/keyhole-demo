// Package adminfake is an in-memory stand-in for the relay's admin API, for
// tests of the admin client and the keyhole CLI. It serves every route in
// internal/adminapi with the contract's shapes and proto.HTTPError bodies,
// checks the admin bearer, and records each request.
package adminfake

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/companion"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Request is one request the fake received.
type Request struct {
	Method string
	Path   string
	Query  url.Values
	Auth   string // Authorization header
	Actor  string // adminapi.ActorHeader
	Body   []byte
}

// Server is a running fake admin API on 127.0.0.1.
type Server struct {
	*httptest.Server

	// Token is the admin bearer the fake accepts.
	Token string
	// MCPURL is returned in session mint responses.
	MCPURL string

	mu        sync.Mutex
	now       func() time.Time
	companion string // the companion origin; "" answers passkey-link mints 503
	clients   map[string]*model.Client
	reasons   map[string]string
	tokens    map[string]*model.EnrollToken
	devices   map[string]*model.Device
	sessions  map[string]*model.Session
	passkeys  map[string]*model.Passkey
	links     []model.PasskeyLink
	exports   map[string][]byte
	verify    map[string]audit.VerifyResult
	fail      map[string]proto.Error
	failCode  map[string]int
	reqs      []Request
}

// New starts a fake that accepts token as the admin bearer. Close it when
// done.
func New(token string) *Server {
	s := &Server{
		Token:     token,
		MCPURL:    "http://127.0.0.1:7802/mcp",
		now:       time.Now,
		companion: DefaultCompanionURL,
		passkeys:  map[string]*model.Passkey{},
		clients:   map[string]*model.Client{},
		reasons:   map[string]string{},
		tokens:    map[string]*model.EnrollToken{},
		devices:   map[string]*model.Device{},
		sessions:  map[string]*model.Session{},
		exports:   map[string][]byte{},
		verify:    map[string]audit.VerifyResult{},
		fail:      map[string]proto.Error{},
		failCode:  map[string]int{},
	}
	mux := http.NewServeMux()
	for route, h := range map[string]http.HandlerFunc{
		adminapi.RouteHealth:          func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") },
		adminapi.RouteListClients:     s.listClients,
		adminapi.RouteCreateClient:    s.createClient,
		adminapi.RouteGetClient:       s.getClient,
		adminapi.RouteDisableClient:   s.setDisabled(true),
		adminapi.RouteEnableClient:    s.setDisabled(false),
		adminapi.RouteGetPolicy:       s.getPolicy,
		adminapi.RoutePutPolicy:       s.putPolicy,
		adminapi.RouteListTokens:      s.listTokens,
		adminapi.RouteMintToken:       s.mintToken,
		adminapi.RouteRevokeToken:     s.revokeToken,
		adminapi.RouteListDevices:     s.listDevices,
		adminapi.RouteRevokeDevice:    s.revokeDevice,
		adminapi.RouteListSessions:    s.listSessions,
		adminapi.RouteMintSession:     s.mintSession,
		adminapi.RouteRevokeSession:   s.revokeSession,
		adminapi.RouteMintPasskeyLink: s.mintPasskeyLink,
		adminapi.RouteListPasskeys:    s.listPasskeys,
		adminapi.RouteRevokePasskey:   s.revokePasskey,
		adminapi.RouteAuditExport:     s.auditExport,
		adminapi.RouteAuditVerify:     s.auditVerify,
	} {
		mux.Handle(route, s.wrap(route, h))
	}
	s.Server = httptest.NewServer(mux)
	return s
}

// SetNow replaces the fake's clock.
func (s *Server) SetNow(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// AddClient seeds a client with the default policy.
func (s *Server) AddClient(slug, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[slug] = &model.Client{
		Slug: slug, Name: name, AccountKey: "A" + slug, CreatedAt: s.now().UTC(),
		Policy: policy.DefaultClientPolicy(),
	}
}

// AddDevice seeds a device.
func (s *Server) AddDevice(d model.Device) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[d.ID] = &d
}

// AddToken seeds an enrollment token.
func (s *Server) AddToken(t model.EnrollToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.ID] = &t
}

// SetExport sets the body RouteAuditExport returns for slug in format.
func (s *Server) SetExport(slug, format string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exports[slug+"/"+format] = body
}

// SetVerify sets the result RouteAuditVerify returns for slug.
func (s *Server) SetVerify(slug string, res audit.VerifyResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verify[slug] = res
}

// Fail makes route answer status with a proto.HTTPError until cleared by
// Fail(route, 0, "", "").
func (s *Server) Fail(route string, status int, code, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status == 0 {
		delete(s.fail, route)
		delete(s.failCode, route)
		return
	}
	s.fail[route] = proto.Error{Code: code, Message: msg}
	s.failCode[route] = status
}

// Requests returns every request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

// Client returns a stored client, policy included.
func (s *Server) Client(slug string) (model.Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[slug]
	if !ok {
		return model.Client{}, false
	}
	return *c, true
}

// DisableReason returns the reason given when slug was last disabled.
func (s *Server) DisableReason(slug string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reasons[slug]
}

// EnrollToken returns a stored enrollment token.
func (s *Server) EnrollToken(id string) (model.EnrollToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return model.EnrollToken{}, false
	}
	return *t, true
}

// Device returns a stored device.
func (s *Server) Device(id string) (model.Device, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return model.Device{}, false
	}
	return *d, true
}

// Session returns a stored session.
func (s *Server) Session(id string) (model.Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sessions[id]
	if !ok {
		return model.Session{}, false
	}
	return *x, true
}

// DefaultCompanionURL is the companion origin a new fake builds enrollment
// links with.
const DefaultCompanionURL = "https://companion.test"

// SetCompanionURL replaces the companion origin. "" makes passkey-link mints
// answer 503, as a relay without a companion does.
func (s *Server) SetCompanionURL(origin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.companion = origin
}

// AddPasskey seeds an enrolled passkey.
func (s *Server) AddPasskey(p model.Passkey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passkeys[p.CredentialID] = &p
}

// Passkey returns a stored passkey.
func (s *Server) Passkey(id string) (model.Passkey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.passkeys[id]
	if !ok {
		return model.Passkey{}, false
	}
	return *p, true
}

// PasskeyLinks returns every enrollment link minted so far, hashes only.
func (s *Server) PasskeyLinks() []model.PasskeyLink {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.PasskeyLink(nil), s.links...)
}

func (s *Server) mintPasskeyLink(w http.ResponseWriter, r *http.Request) {
	var req adminapi.PasskeyLinkRequest
	if err := decode(r, &req); err != nil || req.Technician == "" {
		writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, "technician is required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.companion == "" {
		writeErr(w, http.StatusServiceUnavailable, "unavailable", "technician approval is off: this relay serves no companion")
		return
	}
	secret := model.NewSecret(model.SecretPasskeyLink)
	now := s.now().UTC()
	l := model.PasskeyLink{ID: model.NewID(model.PrefixPasskeyLink), Technician: req.Technician,
		Hash: model.HashSecret(secret), CreatedAt: now, ExpiresAt: now.Add(model.PasskeyLinkTTL)}
	s.links = append(s.links, l)
	writeJSON(w, http.StatusOK, adminapi.PasskeyLinkResponse{ID: l.ID, Technician: l.Technician,
		URL: companion.EnrollURL(s.companion, secret), ExpiresAt: l.ExpiresAt})
}

func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request) {
	tech := r.URL.Query().Get("technician")
	if tech == "" {
		writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, "technician query parameter is required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.Passkey{}
	for _, p := range s.passkeys {
		if p.Technician == tech {
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].CredentialID < out[j].CredentialID
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) revokePasskey(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.passkeys[r.PathValue("id")]
	if !ok {
		writeErr(w, http.StatusNotFound, proto.ErrNotFound, "passkey not found")
		return
	}
	if p.RevokedAt == nil {
		now := s.now().UTC()
		p.RevokedAt = &now
	}
	writeJSON(w, http.StatusOK, *p)
}

var errBadJSON = errors.New("malformed JSON body")

// wrap records the request, enforces the bearer, and applies injected
// failures.
func (s *Server) wrap(route string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		s.mu.Lock()
		s.reqs = append(s.reqs, Request{
			Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(),
			Auth: r.Header.Get("Authorization"), Actor: r.Header.Get(adminapi.ActorHeader), Body: body,
		})
		failErr, failing := s.fail[route]
		failStatus := s.failCode[route]
		s.mu.Unlock()

		if route != adminapi.RouteHealth && r.Header.Get("Authorization") != "Bearer "+s.Token {
			writeErr(w, http.StatusUnauthorized, proto.ErrUnauthorized, "admin token required")
			return
		}
		if failing {
			writeErr(w, failStatus, failErr.Code, failErr.Message)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		h(w, r)
	})
}

func (s *Server) info(c *model.Client) adminapi.ClientInfo {
	ci := adminapi.ClientInfo{
		Slug: c.Slug, Name: c.Name, AccountKey: c.AccountKey, Disabled: c.Disabled, CreatedAt: c.CreatedAt,
	}
	now := s.now()
	for _, d := range s.devices {
		if d.Client != c.Slug || d.RevokedAt != nil {
			continue
		}
		ci.Devices++
		if d.Online(now) {
			ci.Online++
		}
	}
	return ci
}

// client looks up the {slug} of r, answering 404 when it is unknown.
// Callers hold s.mu.
func (s *Server) client(w http.ResponseWriter, r *http.Request) (*model.Client, bool) {
	c, ok := s.clients[r.PathValue("slug")]
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", fmt.Sprintf("client %q not found", r.PathValue("slug")))
	}
	return c, ok
}

func (s *Server) listClients(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []adminapi.ClientInfo{}
	for _, c := range s.clients {
		out = append(out, s.info(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	var req adminapi.CreateClientRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, err.Error())
		return
	}
	if !model.ValidSlug(req.Slug) {
		writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, fmt.Sprintf("invalid slug %q", req.Slug))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[req.Slug]; ok {
		writeErr(w, http.StatusConflict, "conflict", fmt.Sprintf("client %q already exists", req.Slug))
		return
	}
	name := req.Name
	if name == "" {
		name = req.Slug
	}
	c := &model.Client{
		Slug: req.Slug, Name: name, AccountKey: "A" + req.Slug, CreatedAt: s.now().UTC(),
		Policy: policy.DefaultClientPolicy(),
	}
	s.clients[c.Slug] = c
	writeJSON(w, http.StatusCreated, s.info(c))
}

func (s *Server) getClient(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.client(w, r); ok {
		writeJSON(w, http.StatusOK, s.info(c))
	}
}

func (s *Server) setDisabled(disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req adminapi.DisableRequest
		if disabled {
			if err := decode(r, &req); err != nil {
				writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, err.Error())
				return
			}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		c, ok := s.client(w, r)
		if !ok {
			return
		}
		c.Disabled = disabled
		if disabled {
			s.reasons[c.Slug] = req.Reason
		}
		writeJSON(w, http.StatusOK, s.info(c))
	}
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.client(w, r); ok {
		writeJSON(w, http.StatusOK, c.Policy)
	}
}

func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request) {
	var p model.ClientPolicy
	if err := decode(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.client(w, r)
	if !ok {
		return
	}
	p.Version = c.Policy.Version + 1
	c.Policy = p
	writeJSON(w, http.StatusOK, c.Policy)
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.client(w, r)
	if !ok {
		return
	}
	out := []model.EnrollToken{}
	for _, t := range s.tokens {
		if t.Client == c.Slug {
			out = append(out, *t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) mintToken(w http.ResponseWriter, r *http.Request) {
	var req adminapi.MintTokenRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, err.Error())
		return
	}
	if req.TTLDays < 0 || req.MaxUses < 0 {
		writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, "ttl_days and max_uses must not be negative")
		return
	}
	if req.TTLDays == 0 {
		req.TTLDays = 90
	}
	if req.Ephemeral {
		if req.DeviceTTLMinutes == 0 {
			req.DeviceTTLMinutes = 60
		}
		if req.MaxUses == 0 {
			req.MaxUses = 1
		}
		if req.MaxUses != 1 {
			writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, "an ephemeral token enrolls exactly one device")
			return
		}
	} else if req.DeviceTTLMinutes != 0 {
		writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, "device_ttl_minutes applies only to an ephemeral token")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.client(w, r)
	if !ok {
		return
	}
	now := s.now().UTC()
	secret := model.NewEnrollSecret(c.Slug)
	t := &model.EnrollToken{
		ID: model.NewID(model.PrefixToken), Client: c.Slug, Hash: model.HashSecret(secret), Note: req.Note,
		CreatedAt: now, ExpiresAt: now.AddDate(0, 0, req.TTLDays), MaxUses: req.MaxUses,
		Ephemeral: req.Ephemeral, DeviceTTL: time.Duration(req.DeviceTTLMinutes) * time.Minute,
		Technician: req.Technician,
	}
	s.tokens[t.ID] = t
	writeJSON(w, http.StatusCreated, adminapi.MintTokenResponse{Token: *t, Secret: secret})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[r.PathValue("id")]
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "token not found")
		return
	}
	if t.RevokedAt == nil {
		now := s.now().UTC()
		t.RevokedAt = &now
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.client(w, r)
	if !ok {
		return
	}
	out := []model.Device{}
	for _, d := range s.devices {
		if d.Client == c.Slug {
			out = append(out, *d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[r.PathValue("id")]
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "device not found")
		return
	}
	if d.RevokedAt == nil {
		now := s.now().UTC()
		d.RevokedAt = &now
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.client(w, r)
	if !ok {
		return
	}
	out := []model.Session{}
	for _, x := range s.sessions {
		if x.Client == c.Slug {
			out = append(out, *x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) mintSession(w http.ResponseWriter, r *http.Request) {
	var req adminapi.MintSessionRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, err.Error())
		return
	}
	if req.Tech == "" {
		writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, "tech is required")
		return
	}
	if req.TTLMinutes == 0 {
		req.TTLMinutes = 720
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.client(w, r)
	if !ok {
		return
	}
	now := s.now().UTC()
	bearer := model.NewSecret(model.SecretSession)
	x := &model.Session{
		ID: model.NewID(model.PrefixSession), Client: c.Slug, Tech: req.Tech, Hash: model.HashSecret(bearer),
		Note: req.Note, CreatedAt: now, ExpiresAt: now.Add(time.Duration(req.TTLMinutes) * time.Minute),
	}
	s.sessions[x.ID] = x
	writeJSON(w, http.StatusCreated, adminapi.MintSessionResponse{
		Session: *x, Bearer: bearer, MCPURL: s.MCPURL,
		ClaudeAddCommand: fmt.Sprintf("claude mcp add --transport http keyhole-%s %s --header \"Authorization: Bearer %s\"",
			c.Slug, s.MCPURL, bearer),
	})
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sessions[r.PathValue("id")]
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	if x.RevokedAt == nil {
		now := s.now().UTC()
		x.RevokedAt = &now
	}
	writeJSON(w, http.StatusOK, x)
}

var contentTypes = map[string]string{
	"csv":   "text/csv; charset=utf-8",
	"jsonl": "application/x-ndjson",
	"pdf":   "application/pdf",
}

func (s *Server) auditExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	ct, ok := contentTypes[format]
	if !ok {
		writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, fmt.Sprintf("unknown format %q", format))
		return
	}
	for _, k := range []string{"from", "to"} {
		if v := r.URL.Query().Get(k); v != "" {
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				writeErr(w, http.StatusBadRequest, proto.ErrBadRequest, fmt.Sprintf("%s: %v", k, err))
				return
			}
		}
	}
	s.mu.Lock()
	c, ok := s.client(w, r)
	var body []byte
	if ok {
		body = s.exports[c.Slug+"/"+format]
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.client(w, r)
	if !ok {
		return
	}
	res, ok := s.verify[c.Slug]
	if !ok {
		res = audit.VerifyResult{Client: c.Slug, OK: true}
	}
	writeJSON(w, http.StatusOK, res)
}

// decode reads an optional JSON body; an empty body leaves v untouched.
func decode(r *http.Request, v any) error {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %v", errBadJSON, err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, proto.HTTPError{Error: proto.Error{Code: code, Message: msg}})
}
