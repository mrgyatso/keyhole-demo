// Package ninja is a small NinjaOne Public API v2 client: OAuth2 client
// credentials, organizations, and organization custom fields. Keyhole uses
// it to put a client's enrollment token into that client's NinjaOne
// organization, where the install automation reads it.
//
// Writes are railed. A Client refuses to write to any organization outside
// the allowlist it was built with, before any request is made.
package ninja

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Custom fields the Keyhole install automation reads. Both are defined at
// organization scope and inherited by devices.
const (
	FieldEnrollToken = "keyholeEnrollToken" // secure text: the client's enrollment token
	FieldDeploy      = "keyholeDeploy"      // checkbox: deploy Keyhole to this org's devices
)

// Scopes is what every token asks for: read organizations (monitoring) and
// write their custom fields (management).
const Scopes = "monitoring management"

// Environment variables, also the keys of the credentials file.
const (
	EnvBaseURL      = "NINJA_BASE_URL"
	EnvClientID     = "NINJA_CLIENT_ID"
	EnvClientSecret = "NINJA_CLIENT_SECRET"
)

const tokenPath = "/ws/oauth/token"

// Credentials identify one NinjaOne API client app. Formatting or logging
// Credentials never shows the secret.
type Credentials struct {
	BaseURL      string // the instance, e.g. https://app.ninjarmm.com or https://eu.ninjarmm.com
	ClientID     string
	ClientSecret string
}

func (c Credentials) String() string {
	secret := "<empty>"
	if c.ClientSecret != "" {
		secret = "<redacted>"
	}
	return fmt.Sprintf("{BaseURL:%s ClientID:%s ClientSecret:%s}", c.BaseURL, c.ClientID, secret)
}

// GoString keeps %#v from printing the secret.
func (c Credentials) GoString() string { return "ninja.Credentials" + c.String() }

// LogValue keeps slog from printing the secret.
func (c Credentials) LogValue() slog.Value {
	return slog.GroupValue(slog.String("base_url", c.BaseURL), slog.String("client_id", c.ClientID))
}

// LoadCredentials reads KEY=VALUE lines from the file at path, then lets
// each variable set in the environment (via getenv) override the file. A
// missing file is fine when the environment has everything. The file must
// not be readable by group or others, since it holds the client secret.
func LoadCredentials(path string, getenv func(string) string) (Credentials, error) {
	vals := map[string]string{}
	b, err := readPrivateFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return Credentials{}, err
	default:
		if vals, err = parseEnv(b); err != nil {
			return Credentials{}, fmt.Errorf("%s: %w", path, err)
		}
	}
	for _, k := range []string{EnvBaseURL, EnvClientID, EnvClientSecret} {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			vals[k] = v
		}
	}
	c := Credentials{BaseURL: vals[EnvBaseURL], ClientID: vals[EnvClientID], ClientSecret: vals[EnvClientSecret]}
	var missing []string
	for _, k := range []string{EnvBaseURL, EnvClientID, EnvClientSecret} {
		if vals[k] == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return Credentials{}, fmt.Errorf("NinjaOne credentials incomplete: %s not set in %s or the environment",
			strings.Join(missing, ", "), path)
	}
	return c, nil
}

func readPrivateFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by others (mode %04o); it holds the NinjaOne client secret. Run: chmod 600 %s",
			path, fi.Mode().Perm(), path)
	}
	return os.ReadFile(path)
}

// parseEnv reads KEY=VALUE lines; blank lines, # comments, a leading
// "export " and matching quotes around the value are allowed. Errors name
// the line number only, never its content, which may be a secret.
func parseEnv(b []byte) (map[string]string, error) {
	out := map[string]string{}
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("line %d: want KEY=VALUE", i+1)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out, nil
}

// normalizeBaseURL accepts an https instance URL with no path. Plain http
// is accepted only for loopback hosts, so the client secret never crosses a
// network in the clear.
func normalizeBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%s %q is not a URL like https://app.ninjarmm.com", EnvBaseURL, raw)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopback(u.Hostname()):
	default:
		return "", fmt.Errorf("%s must use https (got %q)", EnvBaseURL, raw)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return "", fmt.Errorf("%s must be the bare instance URL, like https://app.ninjarmm.com (got %q)", EnvBaseURL, raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Organization is a NinjaOne organization (one MSP client).
type Organization struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// NotAllowedError is returned for a write to an organization outside the
// allowlist. No request is made.
type NotAllowedError struct {
	OrgID   int
	Allowed []int
}

func (e *NotAllowedError) Error() string {
	allowed := "none"
	if len(e.Allowed) > 0 {
		s := make([]string, len(e.Allowed))
		for i, id := range e.Allowed {
			s[i] = strconv.Itoa(id)
		}
		allowed = strings.Join(s, ", ")
	}
	return fmt.Sprintf("refusing to write to NinjaOne organization %d: it is not in the allowed organizations (%s)", e.OrgID, allowed)
}

// APIError is a non-2xx answer from NinjaOne.
type APIError struct {
	Op         string // "METHOD /path"
	Status     int
	Message    string // from the body, when NinjaOne sent one
	RetryAfter string // on 429
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("NinjaOne %s: HTTP %d", e.Op, e.Status)
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.RetryAfter != "" {
		msg += " (retry after " + e.RetryAfter + "s)"
	}
	return msg
}

// Client talks to one NinjaOne instance. It is safe for concurrent use.
type Client struct {
	creds   Credentials
	base    string
	allowed []int
	hc      *http.Client
	now     func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// New returns a client for creds. allowedOrgs is the write allowlist; every
// write to another organization fails with *NotAllowedError. A nil hc gets
// a client with a 30 second timeout that does not follow redirects.
func New(creds Credentials, allowedOrgs []int, hc *http.Client) (*Client, error) {
	base, err := normalizeBaseURL(creds.BaseURL)
	if err != nil {
		return nil, err
	}
	if creds.ClientID == "" || creds.ClientSecret == "" {
		return nil, errors.New("NinjaOne client ID and secret are required")
	}
	if hc == nil {
		hc = &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Client{creds: creds, base: base, allowed: slices.Clone(allowedOrgs), hc: hc, now: time.Now}, nil
}

// Allowed reports whether writes to org are permitted.
func (c *Client) Allowed(org int) bool { return slices.Contains(c.allowed, org) }

// Organizations lists every organization, following pagination.
func (c *Client) Organizations(ctx context.Context) ([]Organization, error) {
	const pageSize = 100
	var all []Organization
	seen := map[int]bool{}
	after := 0
	for {
		q := url.Values{"pageSize": {strconv.Itoa(pageSize)}}
		if after > 0 {
			q.Set("after", strconv.Itoa(after))
		}
		var page []Organization
		if err := c.do(ctx, http.MethodGet, "/v2/organizations", q, nil, &page); err != nil {
			return nil, err
		}
		for _, o := range page {
			if !seen[o.ID] {
				seen[o.ID] = true
				all = append(all, o)
			}
		}
		if len(page) < pageSize || page[len(page)-1].ID <= after {
			return all, nil
		}
		after = page[len(page)-1].ID
	}
}

// Organization returns one organization.
func (c *Client) Organization(ctx context.Context, id int) (Organization, error) {
	var o Organization
	return o, c.do(ctx, http.MethodGet, fmt.Sprintf("/v2/organization/%d", id), nil, nil, &o)
}

// OrganizationCustomFields returns an organization's custom field values,
// keyed by field name, as NinjaOne sent them.
func (c *Client) OrganizationCustomFields(ctx context.Context, id int) (map[string]json.RawMessage, error) {
	out := map[string]json.RawMessage{}
	return out, c.do(ctx, http.MethodGet, fmt.Sprintf("/v2/organization/%d/custom-fields", id), nil, nil, &out)
}

// UpdateOrganizationCustomFields sets the given fields on an organization,
// leaving the others alone. It refuses organizations outside the
// allowlist before making any request.
func (c *Client) UpdateOrganizationCustomFields(ctx context.Context, id int, fields map[string]any) error {
	if !c.Allowed(id) {
		return &NotAllowedError{OrgID: id, Allowed: slices.Clone(c.allowed)}
	}
	if len(fields) == 0 {
		return nil
	}
	err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/v2/organization/%d/custom-fields", id), nil, fields, nil)
	var apiErr *APIError
	if errors.As(err, &apiErr) && (apiErr.Status == http.StatusBadRequest || apiErr.Status == http.StatusForbidden) {
		names := make([]string, 0, len(fields))
		for k := range fields {
			names = append(names, k)
		}
		slices.Sort(names)
		return fmt.Errorf("%w\nNinjaOne refused to write %s. Check that each field exists with exactly that name, "+
			"that its definition scope includes Organization, and that its API permission allows writes "+
			"(a secure field is writable through the API only when its API permission is Read/Write or Write Only)",
			err, strings.Join(names, ", "))
	}
	return err
}

// do sends one API request with a bearer token, refetching the token once
// if NinjaOne rejects it.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	op := method + " " + path
	var body []byte
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("NinjaOne %s: encode request: %w", op, err)
		}
		body = b
	}
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	for attempt := 0; ; attempt++ {
		tok, err := c.accessToken(ctx)
		if err != nil {
			return err
		}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, rd)
		if err != nil {
			return fmt.Errorf("NinjaOne %s: %w", op, err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			return fmt.Errorf("NinjaOne %s: %w", op, err)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			drain(resp)
			c.invalidate(tok)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			defer resp.Body.Close()
			return apiError(op, resp)
		}
		defer resp.Body.Close()
		if out == nil || resp.StatusCode == http.StatusNoContent {
			drain(resp)
			return nil
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("NinjaOne %s: decode response: %w", op, err)
		}
		return nil
	}
}

// accessToken returns a cached token, fetching a new one with the client
// credentials grant when there is none or it is about to expire.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Before(c.expires) {
		return c.token, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.creds.ClientID},
		"client_secret": {c.creds.ClientSecret},
		"scope":         {Scopes},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+tokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("NinjaOne token: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("NinjaOne token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e := apiError("POST "+tokenPath, resp).(*APIError)
		return "", fmt.Errorf("%w (check %s and %s, and that the API client app allows the client credentials grant with the monitoring and management scopes)",
			e, EnvClientID, EnvClientSecret)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("NinjaOne token: decode response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", errors.New("NinjaOne token: response had no access_token")
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	// Refresh a minute early, or halfway through a short-lived token.
	ttl -= min(time.Minute, ttl/2)
	c.token, c.expires = tr.AccessToken, c.now().Add(ttl)
	return c.token, nil
}

func (c *Client) invalidate(tok string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == tok {
		c.token = ""
	}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
}

// apiError builds an *APIError from a non-2xx response, taking a message
// from the common JSON error shapes or, failing that, the raw text.
func apiError(op string, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	e := &APIError{Op: op, Status: resp.StatusCode}
	if resp.StatusCode == http.StatusTooManyRequests {
		e.RetryAfter = resp.Header.Get("Retry-After")
	}
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		for _, k := range []string{"errorMessage", "error_description", "message", "error", "resultCode"} {
			if s, ok := m[k].(string); ok && s != "" {
				e.Message = s
				return e
			}
		}
	}
	msg := strings.TrimSpace(string(b))
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	e.Message = msg
	return e
}
