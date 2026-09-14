package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/mrgyatso/keyhole/internal/agent/hostinfo"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/version"
)

// EnrollOptions configures Enroll.
type EnrollOptions struct {
	RelayURL string // https://…; plain http:// only for a loopback host
	// Token is the enrollment secret. It is held in memory for the one
	// request and is never written to disk or logged.
	Token      string
	Org        string // optional client slug the token must belong to
	DataDir    DataDir
	Host       hostinfo.Info // facts about this machine; an empty MachineID gets a generated one
	HTTPClient *http.Client  // nil: a client with timeouts that refuses redirects
}

// maxEnrollResponse bounds what Enroll reads from the relay.
const maxEnrollResponse = 1 << 20

// Enroll registers this machine with the relay. It generates a NATS user
// NKey, sends the public half with the token, and stores the signed user
// JWT with the seed as device.creds and the rest as agent.json. The seed
// never leaves the machine.
//
// A refusal from the relay is returned as an error wrapping *proto.Error, so
// callers can tell proto.ErrInvalidToken from proto.ErrOrgMismatch.
func Enroll(ctx context.Context, o EnrollOptions) (*Enrollment, error) {
	relay, err := relayBase(o.RelayURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(o.Token) == "" {
		return nil, errors.New("enroll: no enrollment token")
	}
	if err := o.DataDir.Ensure(); err != nil {
		return nil, err
	}
	host := o.Host
	if host.MachineID == "" {
		if host.MachineID, err = o.DataDir.fallbackMachineID(); err != nil {
			return nil, err
		}
	}

	kp, err := nkeys.CreateUser()
	if err != nil {
		return nil, fmt.Errorf("enroll: create NKey: %w", err)
	}
	defer kp.Wipe()
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("enroll: NKey public key: %w", err)
	}
	seed, err := kp.Seed()
	if err != nil {
		return nil, fmt.Errorf("enroll: NKey seed: %w", err)
	}
	defer wipe(seed)

	er, err := postEnroll(ctx, o.HTTPClient, relay+proto.EnrollPath, proto.EnrollRequest{
		Token:        strings.TrimSpace(o.Token),
		Org:          o.Org,
		PublicKey:    pub,
		Hostname:     host.Hostname,
		MachineID:    host.MachineID,
		OS:           host.OS,
		OSVersion:    host.OSVersion,
		Arch:         host.Arch,
		AgentVersion: version.Version,
	})
	if err != nil {
		return nil, err
	}
	if err := checkEnrollResponse(er, pub); err != nil {
		return nil, err
	}

	creds, err := jwt.FormatUserConfig(er.UserJWT, seed)
	if err != nil {
		return nil, fmt.Errorf("enroll: build credentials file: %w", err)
	}
	defer wipe(creds)
	// device.creds first: agent.json is what marks the agent as enrolled.
	if err := writePrivate(o.DataDir.CredsPath(), creds); err != nil {
		return nil, fmt.Errorf("enroll: write %s: %w", CredsFile, err)
	}
	e := &Enrollment{
		RelayURL:   relay,
		DeviceID:   er.DeviceID,
		Client:     er.Client,
		PublicKey:  pub,
		NATSURLs:   er.NATSURLs,
		EnrolledAt: time.Now().UTC(),
	}
	if err := o.DataDir.save(e); err != nil {
		return nil, err
	}
	return e, nil
}

func postEnroll(ctx context.Context, client *http.Client, endpoint string, body proto.EnrollRequest) (*proto.EnrollResponse, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("enroll: encode request: %w", err)
	}
	defer wipe(b) // holds the token
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "keyhole-agent/"+version.Version)
	if client == nil {
		client = defaultHTTPClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll: POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollResponse))
	if err != nil {
		return nil, fmt.Errorf("enroll: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var he proto.HTTPError
		if json.Unmarshal(data, &he) == nil && he.Error.Code != "" {
			return nil, fmt.Errorf("enroll: relay refused (HTTP %d): %w", resp.StatusCode, &he.Error)
		}
		return nil, fmt.Errorf("enroll: relay returned HTTP %d: %s", resp.StatusCode, snippet(data))
	}
	var er proto.EnrollResponse
	if err := json.Unmarshal(data, &er); err != nil {
		return nil, fmt.Errorf("enroll: decode response: %w", err)
	}
	return &er, nil
}

// checkEnrollResponse verifies the relay's answer before anything is
// written: the JWT must be a user JWT for the key this machine generated,
// and every NATS URL must be encrypted.
func checkEnrollResponse(er *proto.EnrollResponse, pub string) error {
	switch {
	case er.DeviceID == "":
		return errors.New("enroll: relay response has no device_id")
	case er.Client == "":
		return errors.New("enroll: relay response has no client")
	case len(er.NATSURLs) == 0:
		return errors.New("enroll: relay response has no nats_urls")
	}
	for _, u := range er.NATSURLs {
		if err := checkNATSURL(u); err != nil {
			return fmt.Errorf("enroll: %w", err)
		}
	}
	claims, err := jwt.DecodeUserClaims(er.UserJWT)
	if err != nil {
		return fmt.Errorf("enroll: relay returned an invalid user JWT: %w", err)
	}
	if claims.Subject != pub {
		return fmt.Errorf("enroll: relay signed a JWT for %s, not this device's key %s", claims.Subject, pub)
	}
	return nil
}

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		// A redirect would re-send the token somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("relay redirected the enrollment request; not following")
		},
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
}

// relayBase validates the relay URL and returns it without a trailing
// slash. Enrollment carries a secret, so plain http is refused unless the
// host is loopback (tests, local development).
func relayBase(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("relay URL %q: want an absolute URL such as https://keyhole.example.com", raw)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopback(u.Hostname()):
	case u.Scheme == "http":
		return "", fmt.Errorf("relay URL %q: refusing plain http, enrollment sends a secret; use https", raw)
	default:
		return "", fmt.Errorf("relay URL %q: scheme must be https", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("relay URL %q: must not carry credentials, a query or a fragment", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// checkNATSURL accepts encrypted NATS URLs (wss://, tls://), and plain
// ones only for a loopback host.
func checkNATSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("NATS URL %q is not an absolute URL", raw)
	}
	switch u.Scheme {
	case "wss", "tls":
		return nil
	case "ws", "nats":
		if isLoopback(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("NATS URL %q is unencrypted; want wss:// or tls://", raw)
	}
	return fmt.Errorf("NATS URL %q: unsupported scheme %q", raw, u.Scheme)
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// snippet makes an unexpected response body safe to put in an error.
func snippet(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, string(b))
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
