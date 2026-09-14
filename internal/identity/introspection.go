// Package identity integrates the MCP gateway with an MFA-backed OAuth 2
// identity provider without binding Keyhole to a specific vendor.
package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
)

const responseLimit = 64 << 10

type Config struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	Audience     string
	HTTPClient   *http.Client
	Now          func() time.Time
}

// Introspector validates opaque OAuth access tokens using RFC 7662. The
// provider must return a stable sub, exp, the configured audience, and an amr
// value containing "mfa". Introspection on every MCP request makes provider
// revocation effective without restarting the relay.
type Introspector struct {
	endpoint, clientID, clientSecret, audience string
	httpClient                                 *http.Client
	now                                        func() time.Time
}

func NewIntrospector(cfg Config) (*Introspector, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("identity: valid introspection endpoint is required")
	}
	if u.Scheme != "https" && u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" {
		return nil, errors.New("identity: introspection endpoint must use HTTPS")
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.Audience == "" {
		return nil, errors.New("identity: client ID, client secret and audience are required")
	}
	c := cfg.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Introspector{endpoint: u.String(), clientID: cfg.ClientID, clientSecret: cfg.ClientSecret,
		audience: cfg.Audience, httpClient: c, now: now}, nil
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var many []string
	if err := json.Unmarshal(b, &many); err == nil {
		*a = many
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*a = []string{one}
	return nil
}

type response struct {
	Active bool     `json:"active"`
	Sub    string   `json:"sub"`
	Name   string   `json:"name"`
	Exp    int64    `json:"exp"`
	Aud    audience `json:"aud"`
	AMR    []string `json:"amr"`
}

func (i *Introspector) AuthenticateTechnician(ctx context.Context, bearer string) (model.TechnicianSession, error) {
	form := url.Values{"token": {bearer}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return model.TechnicianSession{}, fmt.Errorf("identity: introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(i.clientID, i.clientSecret)
	resp, err := i.httpClient.Do(req)
	if err != nil {
		return model.TechnicianSession{}, fmt.Errorf("identity: introspection: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, responseLimit))
		return model.TechnicianSession{}, fmt.Errorf("identity: introspection returned HTTP %d", resp.StatusCode)
	}
	var body response
	dec := json.NewDecoder(io.LimitReader(resp.Body, responseLimit))
	if err := dec.Decode(&body); err != nil {
		return model.TechnicianSession{}, fmt.Errorf("identity: introspection response: %w", err)
	}
	if !body.Active {
		return model.TechnicianSession{}, fmt.Errorf("identity: inactive token: %w", model.ErrNotFound)
	}
	if strings.TrimSpace(body.Sub) == "" || body.Exp == 0 || !slices.Contains(body.Aud, i.audience) || !slices.Contains(body.AMR, "mfa") {
		return model.TechnicianSession{}, fmt.Errorf("identity: token lacks required subject, audience, expiry or MFA: %w", model.ErrInvalid)
	}
	expires := time.Unix(body.Exp, 0).UTC()
	if !i.now().Before(expires) {
		return model.TechnicianSession{}, fmt.Errorf("identity: token: %w", model.ErrExpired)
	}
	h := sha256.Sum256([]byte(bearer))
	return model.TechnicianSession{ID: "idp_" + hex.EncodeToString(h[:16]), Technician: body.Sub,
		Name: body.Name, MFA: true, ExpiresAt: expires}, nil
}
