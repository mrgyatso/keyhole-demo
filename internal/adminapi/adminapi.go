// Package adminapi is the contract between the relay's admin HTTP API and
// the keyhole CLI.
//
// Every route lives on the relay's private (Tailscale-only) listener and
// requires "Authorization: Bearer <admin token>". The optional header
// X-Keyhole-Actor names the human making the change; it is self-asserted
// and recorded in the audit log. Errors use proto.HTTPError.
package adminapi

import (
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
)

// ActorHeader names the human behind an admin call, for the audit log.
const ActorHeader = "X-Keyhole-Actor"

// Routes, in net/http ServeMux pattern syntax ("METHOD /path/{param}").
const (
	RouteHealth = "GET /healthz" // both listeners, no auth

	RouteListClients   = "GET /v1/admin/clients"
	RouteCreateClient  = "POST /v1/admin/clients"
	RouteGetClient     = "GET /v1/admin/clients/{slug}"
	RouteDisableClient = "POST /v1/admin/clients/{slug}/disable" // kill switch on
	RouteEnableClient  = "POST /v1/admin/clients/{slug}/enable"

	RouteGetPolicy = "GET /v1/admin/clients/{slug}/policy"
	RoutePutPolicy = "PUT /v1/admin/clients/{slug}/policy"

	RouteListTokens  = "GET /v1/admin/clients/{slug}/tokens"
	RouteMintToken   = "POST /v1/admin/clients/{slug}/tokens"
	RouteRevokeToken = "POST /v1/admin/tokens/{id}/revoke"

	RouteListDevices  = "GET /v1/admin/clients/{slug}/devices"
	RouteRevokeDevice = "POST /v1/admin/devices/{id}/revoke"

	RouteListSessions  = "GET /v1/admin/clients/{slug}/sessions"
	RouteMintSession   = "POST /v1/admin/clients/{slug}/sessions"
	RouteRevokeSession = "POST /v1/admin/sessions/{id}/revoke"

	RouteListTechnicianClients  = "GET /v1/admin/technician-acls"
	RouteGrantTechnicianClient  = "POST /v1/admin/technician-acls/grant"
	RouteRevokeTechnicianClient = "POST /v1/admin/technician-acls/revoke"

	// Technician passkeys (Slice 6). Minting a link needs the relay's
	// companion: without one, technician approval is off and the route
	// answers 503 unavailable.
	RouteMintPasskeyLink = "POST /v1/admin/passkey-links"
	RouteListPasskeys    = "GET /v1/admin/passkeys" // query: technician
	RouteRevokePasskey   = "POST /v1/admin/passkeys/{id}/revoke"

	// RouteAuditExport streams the client's audit log. Query: from, to
	// (RFC 3339, optional), format = csv (default) | jsonl | pdf.
	RouteAuditExport = "GET /v1/admin/clients/{slug}/audit"
	RouteAuditVerify = "GET /v1/admin/clients/{slug}/audit/verify" // returns audit.VerifyResult
)

// Split separates a route into its method and path pattern.
func Split(route string) (method, pattern string) {
	method, pattern, _ = strings.Cut(route, " ")
	return method, pattern
}

// Fill replaces the {param} placeholders in pattern, in order, with vals.
func Fill(pattern string, vals ...string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(pattern, '{')
		if i < 0 || len(vals) == 0 {
			b.WriteString(pattern)
			return b.String()
		}
		j := strings.IndexByte(pattern[i:], '}')
		if j < 0 {
			b.WriteString(pattern)
			return b.String()
		}
		b.WriteString(pattern[:i])
		b.WriteString(vals[0])
		vals, pattern = vals[1:], pattern[i+j+1:]
	}
}

// CreateClientRequest creates a client with the default policy, its NATS
// account, and its audit stream. Returns ClientInfo.
type CreateClientRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// ClientInfo is the summary returned by list, get, create, disable, enable.
type ClientInfo struct {
	Slug       string    `json:"slug"`
	Name       string    `json:"name"`
	AccountKey string    `json:"account_key"`
	Disabled   bool      `json:"disabled"`
	CreatedAt  time.Time `json:"created_at"`
	Devices    int       `json:"devices"` // enrolled and not revoked
	Online     int       `json:"online"`
}

// DisableRequest is the optional body of RouteDisableClient.
type DisableRequest struct {
	Reason string `json:"reason,omitempty"`
}

// Policy bodies for RouteGetPolicy and RoutePutPolicy are model.ClientPolicy.
// A PUT replaces the whole policy and bumps its Version.

// MintTokenRequest mints an enrollment token.
//
// Ephemeral mints a temporary-install token instead: MaxUses is forced to 1
// and the device it enrolls expires DeviceTTLMinutes after enrolment.
// Technician and Note are shown to the endpoint user before the install; they
// authorise nothing.
type MintTokenRequest struct {
	TTLDays          int    `json:"ttl_days,omitempty"` // default 90; default 1 when Ephemeral
	MaxUses          int    `json:"max_uses,omitempty"` // default 0 = unlimited
	Note             string `json:"note,omitempty"`
	Ephemeral        bool   `json:"ephemeral,omitempty"`
	DeviceTTLMinutes int    `json:"device_ttl_minutes,omitempty"` // default 60; ephemeral only
	Technician       string `json:"technician,omitempty"`
}

// MintTokenResponse carries the secret, which is shown exactly once.
type MintTokenResponse struct {
	Token  model.EnrollToken `json:"token"`
	Secret string            `json:"secret"`
}

// MintSessionRequest mints an MCP bearer for one tech on one client.
type MintSessionRequest struct {
	Tech       string `json:"tech"`
	TTLMinutes int    `json:"ttl_minutes,omitempty"` // default 720 (12h)
	Note       string `json:"note,omitempty"`
}

// MintSessionResponse carries the bearer, shown exactly once, and a
// ready-to-paste Claude Code command.
type MintSessionResponse struct {
	Session          model.Session `json:"session"`
	Bearer           string        `json:"bearer"`
	MCPURL           string        `json:"mcp_url"`
	ClaudeAddCommand string        `json:"claude_add_command"`
}

type TechnicianACLRequest struct {
	Technician string `json:"technician"`
	Client     string `json:"client"`
}

// PasskeyLinkRequest mints a one-time passkey enrollment link for a
// technician, named by the identity-provider subject the gateway knows them
// by.
type PasskeyLinkRequest struct {
	Technician string `json:"technician"`
}

// PasskeyLinkResponse carries the link. It holds a secret and is shown
// exactly once: whoever opens it first enrolls a passkey that approves as the
// technician. RouteListPasskeys returns a JSON array of model.Passkey, public
// keys excluded, and RouteRevokePasskey the revoked model.Passkey.
type PasskeyLinkResponse struct {
	ID         string    `json:"id"`
	Technician string    `json:"technician"`
	URL        string    `json:"url"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// List responses are JSON arrays of: ClientInfo, model.EnrollToken,
// model.Device, model.Session.
