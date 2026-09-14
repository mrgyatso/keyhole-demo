package relay

import (
	"encoding/json"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// ephemeralMint is a well-formed temporary-install mint request.
func ephemeralMint(minutes int) adminapi.MintTokenRequest {
	return adminapi.MintTokenRequest{
		Ephemeral: true, DeviceTTLMinutes: minutes, Technician: "alice@msp", Note: "ticket 4471",
	}
}

func (h *harness) offer(body any) reply {
	h.t.Helper()
	return h.do(http.MethodPost, h.pub.URL+proto.TempOfferPath, body, nil)
}

// testClock is the relay's clock in tests, so a session's hour can run out
// without waiting an hour.
type testClock struct{ skew atomic.Int64 }

func (c *testClock) now() time.Time       { return time.Now().Add(time.Duration(c.skew.Load())) }
func (c *testClock) skip(d time.Duration) { c.skew.Add(int64(d)) }

func TestMintEphemeralToken(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")

	var out adminapi.MintTokenResponse
	h.must(adminapi.RouteMintToken, []string{"acme"}, ephemeralMint(30), &out)
	switch tok := out.Token; {
	case !tok.Ephemeral:
		t.Fatal("minted a managed token")
	case tok.MaxUses != 1:
		t.Fatalf("max uses %d; a temporary install enrolls exactly one device", tok.MaxUses)
	case tok.DeviceTTL != 30*time.Minute:
		t.Fatalf("device ttl %s", tok.DeviceTTL)
	case tok.Technician != "alice@msp" || tok.Note != "ticket 4471":
		t.Fatalf("token %+v", tok)
	}

	t.Run("defaults", func(t *testing.T) {
		var d adminapi.MintTokenResponse
		h.must(adminapi.RouteMintToken, []string{"acme"}, adminapi.MintTokenRequest{Ephemeral: true}, &d)
		if d.Token.DeviceTTL != time.Hour || d.Token.MaxUses != 1 {
			t.Fatalf("defaults %+v", d.Token)
		}
	})

	for name, req := range map[string]adminapi.MintTokenRequest{
		"reusable":              {Ephemeral: true, MaxUses: 5},
		"unbounded":             {Ephemeral: true, DeviceTTLMinutes: int((model.MaxDeviceTTL + time.Hour) / time.Minute)},
		"ttl without ephemeral": {DeviceTTLMinutes: 30},
	} {
		t.Run(name, func(t *testing.T) {
			if r := h.call(adminapi.RouteMintToken, []string{"acme"}, req); r.status != http.StatusBadRequest {
				t.Fatalf("accepted %+v: %d %s", req, r.status, r.body)
			}
		})
	}

	t.Run("the mint is audited as temporary", func(t *testing.T) {
		entries := h.entries("acme")
		var found bool
		for _, e := range entries {
			if e.Tool == toolTokenMint && string(e.Args) != "" {
				var args map[string]any
				if json.Unmarshal(e.Args, &args) == nil && args["ephemeral"] == true {
					found = true
				}
			}
		}
		if !found {
			t.Fatal("no audit entry records an ephemeral mint")
		}
	})
}

func TestTemporaryOfferShowsTheMSPsTerms(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")
	tok := h.mintToken("acme", ephemeralMint(30))

	r := h.offer(proto.TempOfferRequest{Token: tok.Secret, OS: "windows"})
	if r.status != http.StatusOK {
		t.Fatalf("offer: %d %s", r.status, r.body)
	}
	var o proto.TempOffer
	if err := json.Unmarshal(r.body, &o); err != nil {
		t.Fatal(err)
	}
	switch {
	case o.Client != "acme" || o.ClientName != "ACME":
		t.Fatalf("offer names %q/%q", o.Client, o.ClientName)
	case o.Technician != "alice@msp" || o.Reason != "ticket 4471":
		t.Fatalf("offer %+v", o)
	case o.MaxDuration != 30*time.Minute || !o.Ephemeral:
		t.Fatalf("offer %+v", o)
	case !slices.Equal(o.Operations, proto.ReadOps):
		t.Fatalf("offer powers %v", o.Operations)
	case len(o.Paths) == 0:
		t.Fatal("offer shows no paths for windows")
	}

	t.Run("the offer consumes nothing", func(t *testing.T) {
		if n := tokenUses(h, "acme", tok.Token.ID); n != 0 {
			t.Fatalf("token uses %d after an offer", n)
		}
		// And the install that follows still works.
		if _, _ = h.enrollDevice(tok.Secret, "m-1"); tokenUses(h, "acme", tok.Token.ID) != 1 {
			t.Fatal("enrollment after an offer did not consume the token")
		}
	})

	t.Run("an unusable token is refused the same way as enrollment", func(t *testing.T) {
		// The token above is now used up.
		r := h.offer(proto.TempOfferRequest{Token: tok.Secret, OS: "windows"})
		if r.status != http.StatusUnauthorized || r.errCode() != proto.ErrInvalidToken {
			t.Fatalf("used-up token: %d %s", r.status, r.body)
		}
		unknown := h.offer(proto.TempOfferRequest{Token: model.NewEnrollSecret("acme"), OS: "windows"})
		if unknown.status != r.status || unknown.errCode() != r.errCode() {
			t.Fatalf("unknown token answered differently: %d %s", unknown.status, unknown.body)
		}
	})

	t.Run("a managed token has no temporary offer", func(t *testing.T) {
		managed := h.mintToken("acme", adminapi.MintTokenRequest{})
		if r := h.offer(proto.TempOfferRequest{Token: managed.Secret}); r.status != http.StatusConflict {
			t.Fatalf("managed token offered a temporary install: %d %s", r.status, r.body)
		}
	})

	t.Run("a disabled client offers nothing", func(t *testing.T) {
		other := h.mintToken("acme", ephemeralMint(30))
		h.must(adminapi.RouteDisableClient, []string{"acme"}, adminapi.DisableRequest{Reason: "kill switch"}, &adminapi.ClientInfo{})
		if r := h.offer(proto.TempOfferRequest{Token: other.Secret}); r.status != http.StatusForbidden {
			t.Fatalf("disabled client offered access: %d %s", r.status, r.body)
		}
		h.must(adminapi.RouteEnableClient, []string{"acme"}, nil, &adminapi.ClientInfo{})
	})

	t.Run("the offer is not on the private listener", func(t *testing.T) {
		r := h.do(http.MethodPost, h.priv.URL+proto.TempOfferPath, proto.TempOfferRequest{Token: tok.Secret}, nil)
		if r.status != http.StatusNotFound {
			t.Fatalf("offer reachable privately: %d", r.status)
		}
	})
}

func TestReconcileRevokesExpiredTemporaryDevices(t *testing.T) {
	clock := &testClock{}
	h := newHarness(t, func(c *Config) { c.Now = clock.now })
	h.createClient("acme")
	resp, k := h.enrollDevice(h.mintToken("acme", ephemeralMint(60)).Secret, "m-temp")
	managed, _ := h.enrollDevice(h.mintToken("acme", adminapi.MintTokenRequest{}).Secret, "m-managed")
	a := h.connectAgent(resp, k)
	if d := h.device(resp.DeviceID); !d.Ephemeral || d.ExpiresAt == nil {
		t.Fatalf("enrolled device is not temporary: %+v", d)
	}

	// The session's hour runs out while the endpoint is still connected and
	// has said nothing.
	clock.skip(61 * time.Minute)
	h.srv.reconcile(bg)

	d := h.device(resp.DeviceID)
	if d.RevokedAt == nil {
		t.Fatal("the reconcile loop left an expired temporary device enrolled")
	}
	if m := h.device(managed.DeviceID); m.RevokedAt != nil {
		t.Fatal("the sweep revoked a managed device")
	}
	// The revocation is not only in the store: NATS drops the credential, so
	// the endpoint cannot keep using it even if it ignores its own deadline.
	a.waitClosed(t)

	t.Run("the expiry is audited", func(t *testing.T) {
		entries := h.entries("acme")
		i := slices.IndexFunc(entries, func(e audit.Entry) bool {
			return e.Tool == toolDeviceExpire && e.DeviceID == resp.DeviceID
		})
		if i < 0 {
			t.Fatalf("no %s entry for %s", toolDeviceExpire, resp.DeviceID)
		}
		if e := entries[i]; e.Kind != audit.KindAdmin || e.Result != audit.ResultOK || e.DeviceKey != k.pub {
			t.Fatalf("expiry entry %+v", e)
		}
	})

	t.Run("a second reconcile does not re-expire it", func(t *testing.T) {
		before := len(h.entries("acme"))
		h.srv.reconcile(bg)
		if after := len(h.entries("acme")); after != before {
			t.Fatalf("reconcile added %d entries for an already-revoked device", after-before)
		}
	})
}

func TestDeviceRevokesItsOwnCredential(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")
	resp, k := h.enrollDevice(h.mintToken("acme", ephemeralMint(60)).Secret, "m-temp")
	a := h.connectAgent(resp, k)

	body, _ := json.Marshal(proto.Revoke{DeviceID: resp.DeviceID, Reason: proto.RevokeExpired, Time: time.Now()})
	if err := a.Publish(proto.EventSubject(resp.DeviceID, proto.EvtRevoke), body); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the device to be revoked", func() bool { return h.device(resp.DeviceID).RevokedAt != nil })

	t.Run("it is audited as a self-revocation", func(t *testing.T) {
		eventually(t, "the self-revoke audit entry", func() bool {
			return slices.ContainsFunc(h.entries("acme"), func(e audit.Entry) bool {
				return e.Tool == toolDeviceSelfRevoke && e.DeviceID == resp.DeviceID && e.DeviceKey == k.pub
			})
		})
	})

	t.Run("nats stops accepting the credential", func(t *testing.T) {
		a.waitClosed(t)
	})
}

func TestSelfRevokeFromTheWrongDeviceIsIgnored(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")
	victim, _ := h.enrollDevice(h.mintToken("acme", ephemeralMint(60)).Secret, "m-victim")
	attacker, ak := h.enrollDevice(h.mintToken("acme", ephemeralMint(60)).Secret, "m-attacker")
	a := h.connectAgent(attacker, ak)

	// The subject is what NATS lets this device publish on, so the only lever
	// it has is the payload. Naming another device in it must change nothing.
	body, _ := json.Marshal(proto.Revoke{DeviceID: victim.DeviceID, Reason: proto.RevokeTerminated, Time: time.Now()})
	if err := a.Publish(proto.EventSubject(attacker.DeviceID, proto.EvtRevoke), body); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	// Give the relay time to have got it wrong.
	time.Sleep(250 * time.Millisecond)
	if d := h.device(victim.DeviceID); d.RevokedAt != nil {
		t.Fatal("a device revoked another device's credential")
	}
	if d := h.device(attacker.DeviceID); d.RevokedAt != nil {
		t.Fatal("a mismatched payload revoked the publishing device")
	}

	t.Run("publishing on another device's subject is refused by nats", func(t *testing.T) {
		own, _ := json.Marshal(proto.Revoke{DeviceID: victim.DeviceID})
		_ = a.Publish(proto.EventSubject(victim.DeviceID, proto.EvtRevoke), own)
		_ = a.Flush()
		time.Sleep(250 * time.Millisecond)
		if d := h.device(victim.DeviceID); d.RevokedAt != nil {
			t.Fatal("nats permitted a cross-device publish")
		}
	})
}
