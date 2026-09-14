// Package adminclient is a typed client for the relay's admin API, the
// routes in internal/adminapi. The keyhole CLI uses it, and so do the e2e
// tests.
//
// Every method maps to exactly one route. Non-2xx answers come back as
// *Error, which carries the proto error code from the body.
package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/version"
)

// Client calls one relay's admin API. It is safe for concurrent use.
type Client struct {
	base  string
	token string
	actor string
	hc    *http.Client
}

// New returns a client for the admin API at baseURL, for example
// "http://relay.example.invalid:7802". token is the admin bearer. actor, when not
// empty, is sent as adminapi.ActorHeader so the audit log names the human.
//
// A nil hc gets a client that does not follow redirects, so the admin
// token is never replayed to a URL the caller did not name. Deadlines come
// from each call's context.
func New(baseURL, token, actor string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), token: token, actor: actor, hc: hc}
}

// Error is a non-2xx answer from the admin API.
type Error struct {
	Status  int    // HTTP status code
	Code    string // proto error code from the body, e.g. "unauthorized"; empty if the body carried none
	Message string
}

func (e *Error) Error() string {
	switch {
	case e.Code != "" && e.Message != "":
		return e.Code + ": " + e.Message
	case e.Code != "":
		return e.Code
	case e.Message != "":
		return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("HTTP %d %s", e.Status, http.StatusText(e.Status))
}

// ErrorCode returns the admin API error code carried by err, or "" if err
// is not an *Error or its body had no code.
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Health checks RouteHealth. It sends no credentials.
func (c *Client) Health(ctx context.Context) error {
	return c.call(ctx, adminapi.RouteHealth, nil, nil, nil, nil)
}

// ListClients returns every client.
func (c *Client) ListClients(ctx context.Context) ([]adminapi.ClientInfo, error) {
	var out []adminapi.ClientInfo
	return out, c.call(ctx, adminapi.RouteListClients, nil, nil, nil, &out)
}

// CreateClient creates a client with the default policy.
func (c *Client) CreateClient(ctx context.Context, req adminapi.CreateClientRequest) (adminapi.ClientInfo, error) {
	var out adminapi.ClientInfo
	return out, c.call(ctx, adminapi.RouteCreateClient, nil, nil, req, &out)
}

// GetClient returns one client.
func (c *Client) GetClient(ctx context.Context, slug string) (adminapi.ClientInfo, error) {
	var out adminapi.ClientInfo
	return out, c.call(ctx, adminapi.RouteGetClient, []string{slug}, nil, nil, &out)
}

// DisableClient turns the client's kill switch on. reason may be empty.
func (c *Client) DisableClient(ctx context.Context, slug, reason string) (adminapi.ClientInfo, error) {
	var out adminapi.ClientInfo
	return out, c.call(ctx, adminapi.RouteDisableClient, []string{slug}, nil, adminapi.DisableRequest{Reason: reason}, &out)
}

// EnableClient turns the client's kill switch off.
func (c *Client) EnableClient(ctx context.Context, slug string) (adminapi.ClientInfo, error) {
	var out adminapi.ClientInfo
	return out, c.call(ctx, adminapi.RouteEnableClient, []string{slug}, nil, nil, &out)
}

// GetPolicy returns the client's policy.
func (c *Client) GetPolicy(ctx context.Context, slug string) (model.ClientPolicy, error) {
	var out model.ClientPolicy
	return out, c.call(ctx, adminapi.RouteGetPolicy, []string{slug}, nil, nil, &out)
}

// PutPolicy replaces the client's policy and returns the stored policy,
// with its bumped Version. If the relay answers without a body, the stored
// policy is read back with GetPolicy.
func (c *Client) PutPolicy(ctx context.Context, slug string, p model.ClientPolicy) (model.ClientPolicy, error) {
	var raw json.RawMessage
	if err := c.call(ctx, adminapi.RoutePutPolicy, []string{slug}, nil, p, &raw); err != nil {
		return model.ClientPolicy{}, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return c.GetPolicy(ctx, slug)
	}
	var out model.ClientPolicy
	if err := json.Unmarshal(raw, &out); err != nil {
		return model.ClientPolicy{}, fmt.Errorf("admin API: decode policy: %w", err)
	}
	return out, nil
}

// ListTokens returns the client's enrollment tokens, secrets excluded.
func (c *Client) ListTokens(ctx context.Context, slug string) ([]model.EnrollToken, error) {
	var out []model.EnrollToken
	return out, c.call(ctx, adminapi.RouteListTokens, []string{slug}, nil, nil, &out)
}

// MintToken mints an enrollment token. The response carries the secret,
// which the relay never returns again.
func (c *Client) MintToken(ctx context.Context, slug string, req adminapi.MintTokenRequest) (adminapi.MintTokenResponse, error) {
	var out adminapi.MintTokenResponse
	return out, c.call(ctx, adminapi.RouteMintToken, []string{slug}, nil, req, &out)
}

// RevokeToken revokes an enrollment token. Enrolled devices are unaffected.
func (c *Client) RevokeToken(ctx context.Context, id string) error {
	return c.call(ctx, adminapi.RouteRevokeToken, []string{id}, nil, nil, nil)
}

// ListDevices returns every device of the client, revoked ones included.
func (c *Client) ListDevices(ctx context.Context, slug string) ([]model.Device, error) {
	var out []model.Device
	return out, c.call(ctx, adminapi.RouteListDevices, []string{slug}, nil, nil, &out)
}

// RevokeDevice revokes a device's credential.
func (c *Client) RevokeDevice(ctx context.Context, id string) error {
	return c.call(ctx, adminapi.RouteRevokeDevice, []string{id}, nil, nil, nil)
}

// ListSessions returns the client's MCP sessions, bearers excluded.
func (c *Client) ListSessions(ctx context.Context, slug string) ([]model.Session, error) {
	var out []model.Session
	return out, c.call(ctx, adminapi.RouteListSessions, []string{slug}, nil, nil, &out)
}

// MintSession mints an MCP bearer for one tech. The response carries the
// bearer, which the relay never returns again.
func (c *Client) MintSession(ctx context.Context, slug string, req adminapi.MintSessionRequest) (adminapi.MintSessionResponse, error) {
	var out adminapi.MintSessionResponse
	return out, c.call(ctx, adminapi.RouteMintSession, []string{slug}, nil, req, &out)
}

// RevokeSession revokes an MCP session.
func (c *Client) RevokeSession(ctx context.Context, id string) error {
	return c.call(ctx, adminapi.RouteRevokeSession, []string{id}, nil, nil, nil)
}

func (c *Client) TechnicianClients(ctx context.Context, technician string) ([]adminapi.ClientInfo, error) {
	var out []adminapi.ClientInfo
	q := url.Values{"technician": {technician}}
	return out, c.call(ctx, adminapi.RouteListTechnicianClients, nil, q, nil, &out)
}

func (c *Client) GrantTechnicianClient(ctx context.Context, technician, client string) error {
	return c.call(ctx, adminapi.RouteGrantTechnicianClient, nil, nil,
		adminapi.TechnicianACLRequest{Technician: technician, Client: client}, nil)
}

func (c *Client) RevokeTechnicianClient(ctx context.Context, technician, client string) error {
	return c.call(ctx, adminapi.RouteRevokeTechnicianClient, nil, nil,
		adminapi.TechnicianACLRequest{Technician: technician, Client: client}, nil)
}

// MintPasskeyLink mints a one-time passkey enrollment link for a technician.
// The link holds a secret, which the relay never returns again.
func (c *Client) MintPasskeyLink(ctx context.Context, technician string) (adminapi.PasskeyLinkResponse, error) {
	var out adminapi.PasskeyLinkResponse
	return out, c.call(ctx, adminapi.RouteMintPasskeyLink, nil, nil, adminapi.PasskeyLinkRequest{Technician: technician}, &out)
}

// Passkeys returns every passkey of a technician, revoked ones included.
func (c *Client) Passkeys(ctx context.Context, technician string) ([]model.Passkey, error) {
	var out []model.Passkey
	return out, c.call(ctx, adminapi.RouteListPasskeys, nil, url.Values{"technician": {technician}}, nil, &out)
}

// RevokePasskey revokes a passkey by credential ID and returns it.
func (c *Client) RevokePasskey(ctx context.Context, credentialID string) (model.Passkey, error) {
	var out model.Passkey
	return out, c.call(ctx, adminapi.RouteRevokePasskey, []string{credentialID}, nil, nil, &out)
}

// Audit export formats accepted by RouteAuditExport.
const (
	FormatCSV   = "csv"
	FormatJSONL = "jsonl"
	FormatPDF   = "pdf"
)

// AuditQuery selects what AuditExport returns.
type AuditQuery struct {
	From   time.Time // inclusive; zero means from the first entry
	To     time.Time // exclusive; zero means through the last entry
	Format string    // FormatCSV (the relay's default when empty), FormatJSONL or FormatPDF
}

// AuditExport streams the client's audit log into w and returns the number
// of bytes written. A stream cut short by the relay returns an error, so a
// caller writing to a file should discard it on error.
func (c *Client) AuditExport(ctx context.Context, slug string, q AuditQuery, w io.Writer) (int64, error) {
	v := url.Values{}
	if !q.From.IsZero() {
		v.Set("from", q.From.UTC().Format(time.RFC3339Nano))
	}
	if !q.To.IsZero() {
		v.Set("to", q.To.UTC().Format(time.RFC3339Nano))
	}
	if q.Format != "" {
		v.Set("format", q.Format)
	}
	resp, err := c.send(ctx, adminapi.RouteAuditExport, []string{slug}, v, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return n, fmt.Errorf("admin API: audit export for %s: %w", slug, err)
	}
	return n, nil
}

// AuditVerify walks the client's audit chain on the relay.
func (c *Client) AuditVerify(ctx context.Context, slug string) (audit.VerifyResult, error) {
	var out audit.VerifyResult
	return out, c.call(ctx, adminapi.RouteAuditVerify, []string{slug}, nil, nil, &out)
}

// call sends one request and decodes a JSON answer into out, or discards
// the body when out is nil.
func (c *Client) call(ctx context.Context, route string, params []string, query url.Values, in, out any) error {
	resp, err := c.send(ctx, route, params, query, in)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	if raw, ok := out.(*json.RawMessage); ok {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("admin API: %s: read response: %w", route, err)
		}
		*raw = b
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("admin API: %s: decode response: %w", route, err)
	}
	return nil
}

// send builds and sends one request and turns a non-2xx answer into *Error.
// On success the caller owns resp.Body.
func (c *Client) send(ctx context.Context, route string, params []string, query url.Values, in any) (*http.Response, error) {
	method, pattern := adminapi.Split(route)
	esc := make([]string, len(params))
	for i, p := range params {
		if p == "" {
			return nil, fmt.Errorf("admin API: %s: empty path parameter", route)
		}
		esc[i] = url.PathEscape(p)
	}
	u := c.base + adminapi.Fill(pattern, esc...)
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, fmt.Errorf("admin API: %s: encode request: %w", route, err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, fmt.Errorf("admin API: %s: %w", route, err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "keyhole/"+version.Version)
	if route != adminapi.RouteHealth {
		req.Header.Set("Authorization", "Bearer "+c.token)
		if c.actor != "" {
			req.Header.Set(adminapi.ActorHeader, c.actor)
		}
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("admin API: %s %s: %w", method, u, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		return nil, decodeError(resp)
	}
	return resp, nil
}

// decodeError reads a proto.HTTPError body, falling back to the raw text.
func decodeError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	e := &Error{Status: resp.StatusCode}
	var he proto.HTTPError
	if json.Unmarshal(b, &he) == nil && he.Error.Code != "" {
		e.Code, e.Message = he.Error.Code, he.Error.Message
		return e
	}
	msg := strings.TrimSpace(string(b))
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	e.Message = msg
	return e
}
