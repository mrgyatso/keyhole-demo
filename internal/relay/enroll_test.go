package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

func tokenUses(h *harness, slug, id string) int {
	h.t.Helper()
	var toks []model.EnrollToken
	h.must(adminapi.RouteListTokens, []string{slug}, nil, &toks)
	for _, tok := range toks {
		if tok.ID == id {
			return tok.Uses
		}
	}
	h.t.Fatalf("token %s not listed", id)
	return 0
}

func TestEnrollment(t *testing.T) {
	h := newHarness(t)
	acme := h.createClient("acme")
	h.createClient("beta")
	tok := h.mintToken("acme", adminapi.MintTokenRequest{})

	k := newDeviceKey(t)
	req := enrollRequest(tok.Secret, k, "m-1")
	req.Org = "acme"
	r := h.enroll(req, nil)
	if r.status != http.StatusOK {
		t.Fatalf("enroll: %d %s", r.status, r.body)
	}
	var resp proto.EnrollResponse
	if err := json.Unmarshal(r.body, &resp); err != nil {
		t.Fatal(err)
	}

	t.Run("the credential is confined to the device", func(t *testing.T) {
		if resp.Client != "acme" || !strings.HasPrefix(resp.DeviceID, model.PrefixDevice+"_") {
			t.Fatalf("response %+v", resp)
		}
		if !slices.Equal(resp.NATSURLs, []string{"wss://keyhole.test/nats"}) {
			t.Fatalf("nats urls %v", resp.NATSURLs)
		}
		uc, err := jwt.DecodeUserClaims(resp.UserJWT)
		if err != nil {
			t.Fatal(err)
		}
		if uc.Subject != k.pub || uc.IssuerAccount != acme.AccountKey {
			t.Fatalf("jwt for %s in %s", uc.Subject, uc.IssuerAccount)
		}
		if !slices.Equal([]string(uc.Pub.Allow), []string{proto.EventWildcard(resp.DeviceID)}) ||
			!slices.Equal([]string(uc.Sub.Allow), []string{proto.RPCWildcard(resp.DeviceID)}) ||
			uc.Resp == nil || uc.Resp.MaxMsgs != 1 || len(uc.Pub.Deny)+len(uc.Sub.Deny) != 0 {
			t.Fatalf("device permissions %+v", uc.Permissions)
		}
		d := h.device(resp.DeviceID)
		if d.Client != "acme" || d.PublicKey != k.pub || d.OS != "windows" || d.MachineID != "m-1" || d.EnrollTokenID != tok.Token.ID {
			t.Fatalf("stored device %+v", d)
		}
		if n := tokenUses(h, "acme", tok.Token.ID); n != 1 {
			t.Fatalf("token uses %d", n)
		}
		entries := h.entries("acme")
		last := entries[len(entries)-1]
		if last.Kind != audit.KindEnroll || last.DeviceID != resp.DeviceID || last.DeviceKey != k.pub || last.Tool != toolEnroll {
			t.Fatalf("enroll audit entry %+v", last)
		}
	})

	t.Run("every token failure looks the same", func(t *testing.T) {
		now := time.Now()
		expired := model.NewEnrollSecret("acme")
		if err := h.st.CreateToken(bg, model.EnrollToken{
			ID: "tok_expired", Client: "acme", Hash: model.HashSecret(expired),
			CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		revoked := h.mintToken("acme", adminapi.MintTokenRequest{})
		h.must(adminapi.RouteRevokeToken, []string{revoked.Token.ID}, nil, nil)
		once := h.mintToken("acme", adminapi.MintTokenRequest{MaxUses: 1})
		h.enrollDevice(once.Secret, "m-once")

		var bodies []string
		for name, secret := range map[string]string{
			"unknown":   model.NewEnrollSecret("acme"),
			"expired":   expired,
			"revoked":   revoked.Secret,
			"exhausted": once.Secret,
		} {
			r := h.enroll(enrollRequest(secret, newDeviceKey(t), "m-x"), nil)
			if r.status != http.StatusUnauthorized || r.errCode() != proto.ErrInvalidToken {
				t.Errorf("%s token: %d %s", name, r.status, r.body)
			}
			bodies = append(bodies, string(r.body))
		}
		for _, b := range bodies[1:] {
			if b != bodies[0] {
				t.Fatalf("token failures are distinguishable: %q vs %q", b, bodies[0])
			}
		}
	})

	t.Run("org mismatch is refused without using the token", func(t *testing.T) {
		before := tokenUses(h, "acme", tok.Token.ID)
		req := enrollRequest(tok.Secret, newDeviceKey(t), "m-2")
		req.Org = "beta"
		if r := h.enroll(req, nil); r.status != http.StatusForbidden || r.errCode() != proto.ErrOrgMismatch {
			t.Fatalf("org mismatch: %d %s", r.status, r.body)
		}
		if after := tokenUses(h, "acme", tok.Token.ID); after != before {
			t.Fatalf("org mismatch used the token: %d -> %d", before, after)
		}
	})

	t.Run("malformed requests are refused without using the token", func(t *testing.T) {
		before := tokenUses(h, "acme", tok.Token.ID)
		for name, mutate := range map[string]func(*proto.EnrollRequest){
			"account key as device key": func(r *proto.EnrollRequest) { r.PublicKey = acme.AccountKey },
			"garbage key":               func(r *proto.EnrollRequest) { r.PublicKey = "UNOTAKEY" },
			"no key":                    func(r *proto.EnrollRequest) { r.PublicKey = "" },
			"no token":                  func(r *proto.EnrollRequest) { r.Token = "" },
			"no hostname":               func(r *proto.EnrollRequest) { r.Hostname = "" },
			"unsupported os":            func(r *proto.EnrollRequest) { r.OS = "plan9" },
			"control characters":        func(r *proto.EnrollRequest) { r.Hostname = "srv\n01" },
			"overlong field":            func(r *proto.EnrollRequest) { r.MachineID = strings.Repeat("a", 300) },
			"org is not a slug":         func(r *proto.EnrollRequest) { r.Org = "Not A Slug" },
		} {
			req := enrollRequest(tok.Secret, newDeviceKey(t), "m-3")
			mutate(&req)
			if r := h.enroll(req, nil); r.status != http.StatusBadRequest || r.errCode() != proto.ErrBadRequest {
				t.Errorf("%s: %d %s", name, r.status, r.body)
			}
		}
		for name, body := range map[string]string{
			"truncated json": "{",
			"trailing data":  `{"token":"a"}{"token":"b"}`,
		} {
			if r := h.enroll(body, nil); r.status != http.StatusBadRequest {
				t.Errorf("%s: %d", name, r.status)
			}
		}
		big := `{"token":"` + strings.Repeat("a", 17<<10) + `"}`
		if r := h.enroll(big, nil); r.status != http.StatusRequestEntityTooLarge {
			t.Errorf("oversized body: %d", r.status)
		}
		if after := tokenUses(h, "acme", tok.Token.ID); after != before {
			t.Fatalf("a malformed request used the token: %d -> %d", before, after)
		}
	})

	t.Run("a key is never enrolled twice", func(t *testing.T) {
		if r := h.enroll(enrollRequest(tok.Secret, k, "m-4"), nil); r.status != http.StatusConflict {
			t.Fatalf("reused key: %d %s", r.status, r.body)
		}
	})

	t.Run("re-enrolling a machine revokes its previous device", func(t *testing.T) {
		old := h.connectAgent(resp, k)
		fresh, freshKey := h.enrollDevice(tok.Secret, "m-1")
		if d := h.device(resp.DeviceID); d.RevokedAt == nil {
			t.Fatal("previous device still live in the store")
		}
		old.waitClosed(t)
		if a, err := dialAgent(h.nats.ClientURL(), resp.UserJWT, k.seed); err == nil {
			a.Close()
			t.Fatal("the previous device's credential is still accepted")
		}
		if a := h.connectAgent(fresh, freshKey); !a.IsConnected() {
			t.Fatal("the new device cannot connect")
		}
		entries := h.entries("acme")
		if last := entries[len(entries)-1]; !strings.Contains(string(last.Args), resp.DeviceID) {
			t.Fatalf("enroll entry does not name the replaced device: %s", last.Args)
		}
	})
}

func TestEnrollRateLimit(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.EnrollPerMinute = 3 })
	from := func(ip string) http.Header { return http.Header{"Cf-Connecting-Ip": {ip}} }
	req := enrollRequest(model.NewEnrollSecret("acme"), newDeviceKey(t), "m")
	for i := range 3 {
		if r := h.enroll(req, from("203.0.113.7")); r.status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i+1, r.status)
		}
	}
	r := h.enroll(req, from("203.0.113.7"))
	if r.status != http.StatusTooManyRequests || r.errCode() != codeRateLimited || r.header.Get("Retry-After") == "" {
		t.Fatalf("4th attempt: %d %s", r.status, r.body)
	}
	if r := h.enroll(req, from("203.0.113.8")); r.status != http.StatusUnauthorized {
		t.Fatalf("another client IP was limited: %d", r.status)
	}
}

func TestClientIP(t *testing.T) {
	for _, c := range []struct {
		remote, cf, want string
	}{
		{"198.51.100.1:5555", "203.0.113.9", "198.51.100.1"}, // only a loopback peer is trusted
		{"127.0.0.1:5555", "203.0.113.9", "203.0.113.9"},
		{"[::1]:5555", "2001:db8::1", "2001:db8::1"},
		{"127.0.0.1:5555", "not an ip", "127.0.0.1"},
		{"127.0.0.1:5555", "", "127.0.0.1"},
	} {
		r := httptest.NewRequest(http.MethodPost, proto.EnrollPath, nil)
		r.RemoteAddr = c.remote
		if c.cf != "" {
			r.Header.Set("CF-Connecting-IP", c.cf)
		}
		if got := clientIP(r); got != c.want {
			t.Errorf("clientIP(%s, CF %q) = %s, want %s", c.remote, c.cf, got, c.want)
		}
	}
}

func TestRateLimiterRefills(t *testing.T) {
	l := newRateLimiter(2)
	now := time.Unix(1_800_000_000, 0)
	l.now = func() time.Time { return now }
	if !l.allow("a") || !l.allow("a") || l.allow("a") {
		t.Fatal("burst of 2 not enforced")
	}
	if !l.allow("b") {
		t.Fatal("one key's limit applied to another")
	}
	now = now.Add(30 * time.Second)
	if !l.allow("a") || l.allow("a") {
		t.Fatal("did not refill one token in 30s at 2/min")
	}
	now = now.Add(time.Hour)
	l.allow("c")
	if _, ok := l.buckets["a"]; ok {
		t.Fatal("idle bucket not swept")
	}
}
