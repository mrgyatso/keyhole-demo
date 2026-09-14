// Package ninjafake mocks the parts of the NinjaOne Public API v2 that
// Keyhole uses: the client-credentials token endpoint, organizations, and
// organization custom fields. It listens on 127.0.0.1 and records every
// request. It does not import package ninja, so ninja's own tests can use it.
package ninjafake

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Org is an organization as the API returns it.
type Org struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Request is one request the mock received.
type Request struct {
	Method string
	Path   string
	Query  url.Values
	Form   url.Values // token requests only
	Auth   string
	Body   []byte
}

// Server is a running mock.
type Server struct {
	*httptest.Server

	ClientID     string
	ClientSecret string
	// TokenTTL is the expires_in, in seconds, of issued tokens.
	TokenTTL int

	mu     sync.Mutex
	orgs   map[int]*Org
	fields map[int]map[string]any
	denied map[string]string
	tokens map[string]bool
	issued int
	reqs   []Request
}

// New starts a mock that accepts one client app's credentials.
func New(clientID, clientSecret string) *Server {
	s := &Server{
		ClientID: clientID, ClientSecret: clientSecret, TokenTTL: 3600,
		orgs: map[int]*Org{}, fields: map[int]map[string]any{}, denied: map[string]string{}, tokens: map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ws/oauth/token", s.token)
	mux.HandleFunc("GET /v2/organizations", s.auth(s.listOrgs))
	mux.HandleFunc("GET /v2/organization/{id}", s.auth(s.getOrg))
	mux.HandleFunc("GET /v2/organization/{id}/custom-fields", s.auth(s.getFields))
	mux.HandleFunc("PATCH /v2/organization/{id}/custom-fields", s.auth(s.patchFields))
	s.Server = httptest.NewServer(s.record(mux))
	return s
}

// AddOrg adds an organization.
func (s *Server) AddOrg(id int, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgs[id] = &Org{ID: id, Name: name}
}

// SetField sets an organization custom field value.
func (s *Server) SetField(org int, name string, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fields[org] == nil {
		s.fields[org] = map[string]any{}
	}
	s.fields[org][name] = v
}

// Fields returns a copy of an organization's custom field values.
func (s *Server) Fields(org int) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.fields[org])
}

// DenyField makes any PATCH that includes field fail with 403 and msg, as
// NinjaOne does when a field's API permission forbids writes.
func (s *Server) DenyField(field, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denied[field] = msg
}

// RevokeTokens invalidates every issued token.
func (s *Server) RevokeTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.tokens)
}

// Requests returns every request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reqs)
}

// TokenRequests counts requests to the token endpoint.
func (s *Server) TokenRequests() int {
	n := 0
	for _, r := range s.Requests() {
		if r.Path == "/ws/oauth/token" {
			n++
		}
	}
	return n
}

func (s *Server) record(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		req := Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Auth: r.Header.Get("Authorization"), Body: body}
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			req.Form, _ = url.ParseQuery(string(body))
		}
		s.mu.Lock()
		s.reqs = append(s.reqs, req)
		s.mu.Unlock()
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		next.ServeHTTP(w, r)
	})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	if r.PostForm.Get("client_id") != s.ClientID || r.PostForm.Get("client_secret") != s.ClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client", "error_description": "Bad client credentials"})
		return
	}
	scopes := strings.Fields(r.PostForm.Get("scope"))
	if !slices.Contains(scopes, "monitoring") || !slices.Contains(scopes, "management") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_scope"})
		return
	}
	s.mu.Lock()
	s.issued++
	tok := fmt.Sprintf("tok-%d", s.issued)
	s.tokens[tok] = true
	ttl := s.TokenTTL
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok, "token_type": "bearer", "expires_in": ttl, "scope": strings.Join(scopes, " "),
	})
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		ok := s.tokens[tok]
		s.mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		h(w, r)
	}
}

func (s *Server) listOrgs(w http.ResponseWriter, r *http.Request) {
	pageSize, after := 1000, 0
	if v := r.URL.Query().Get("pageSize"); v != "" {
		pageSize, _ = strconv.Atoi(v)
	}
	if v := r.URL.Query().Get("after"); v != "" {
		after, _ = strconv.Atoi(v)
	}
	s.mu.Lock()
	ids := slices.Sorted(maps.Keys(s.orgs))
	out := []Org{}
	for _, id := range ids {
		if id > after && len(out) < pageSize {
			out = append(out, *s.orgs[id])
		}
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

// org resolves {id}, answering 404 for an unknown organization. Callers
// hold s.mu.
func (s *Server) org(w http.ResponseWriter, r *http.Request) (int, bool) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || s.orgs[id] == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"resultCode": "FAILURE", "errorMessage": "Organization not found"})
		return 0, false
	}
	return id, true
}

func (s *Server) getOrg(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.org(w, r); ok {
		writeJSON(w, http.StatusOK, s.orgs[id])
	}
}

func (s *Server) getFields(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.org(w, r); ok {
		out := maps.Clone(s.fields[id])
		if out == nil {
			out = map[string]any{}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) patchFields(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"errorMessage": "malformed body"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.org(w, r)
	if !ok {
		return
	}
	for k := range in {
		if msg, denied := s.denied[k]; denied {
			writeJSON(w, http.StatusForbidden, map[string]string{"resultCode": "FAILURE", "errorMessage": msg})
			return
		}
	}
	if s.fields[id] == nil {
		s.fields[id] = map[string]any{}
	}
	maps.Copy(s.fields[id], in)
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
