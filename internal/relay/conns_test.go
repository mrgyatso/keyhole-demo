package relay

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func TestRelayReachesDeviceThroughConns(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")
	h.createClient("beta")
	resp, k := h.enrollDevice(h.mintToken("acme", adminapi.MintTokenRequest{}).Secret, "m-1")
	a := h.connectAgent(resp, k)
	if _, err := a.Subscribe(proto.RPCWildcard(resp.DeviceID), func(m *nats.Msg) {
		var req proto.Request
		_ = json.Unmarshal(m.Data, &req)
		result, _ := json.Marshal(proto.PingResult{DeviceID: resp.DeviceID, Hostname: "SRV-m-1", OS: "windows"})
		out, _ := json.Marshal(proto.Response{V: proto.Version, ID: req.ID, OK: true, Result: result})
		_ = m.Respond(out)
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}

	var conns model.Conns = h.conns
	nc, err := conns.Conn("acme")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(proto.Request{V: proto.Version, ID: "req_1", Op: proto.OpPing})
	msg, err := nc.Request(proto.RPCSubject(resp.DeviceID, proto.OpPing), req, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var out proto.Response
	if err := json.Unmarshal(msg.Data, &out); err != nil || !out.OK || out.ID != "req_1" {
		t.Fatalf("ping response %+v %v", out, err)
	}

	betaConn, err := conns.Conn("beta")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := betaConn.Request(proto.RPCSubject(resp.DeviceID, proto.OpPing), req, 300*time.Millisecond); err == nil {
		t.Fatal("beta's connection reached acme's device")
	}
	if _, err := conns.Conn("nope"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("unknown client: %v", err)
	}
}

func TestDeviceEventsRecorded(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")
	h.createClient("beta")
	resp, k := h.enrollDevice(h.mintToken("acme", adminapi.MintTokenRequest{}).Secret, "m-1")
	a := h.connectAgent(resp, k)

	hello, _ := json.Marshal(proto.Hello{
		DeviceID: resp.DeviceID, Hostname: "SRV-RENAMED", OS: "linux", OSVersion: "10.0.26200",
		Arch: "amd64", AgentVersion: "v0.2.0", Time: time.Now(),
	})
	if err := a.Publish(proto.EventSubject(resp.DeviceID, proto.EvtHello), hello); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the hello to be recorded", func() bool {
		d := h.device(resp.DeviceID)
		return d.Hostname == "SRV-RENAMED" && d.LastSeen != nil
	})
	d := h.device(resp.DeviceID)
	if d.AgentVersion != "v0.2.0" || d.OSVersion != "10.0.26200" || d.OS != "windows" {
		t.Fatalf("device after hello %+v (the OS is fixed at enrollment)", d)
	}
	first := *d.LastSeen
	time.Sleep(10 * time.Millisecond)
	if err := a.Publish(proto.EventSubject(resp.DeviceID, proto.EvtHeartbeat), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the heartbeat to be recorded", func() bool {
		return h.device(resp.DeviceID).LastSeen.After(first)
	})
	var info adminapi.ClientInfo
	h.must(adminapi.RouteGetClient, []string{"acme"}, nil, &info)
	if info.Devices != 1 || info.Online != 1 {
		t.Fatalf("client info %+v", info)
	}

	// Events that name acme's device but arrive on beta's connection, or
	// name unknown devices, change nothing.
	before := h.device(resp.DeviceID)
	evil, _ := json.Marshal(proto.Hello{Hostname: "EVIL"})
	for _, m := range []*nats.Msg{
		{Subject: proto.EventSubject(resp.DeviceID, proto.EvtHello), Data: evil},
		{Subject: proto.EventSubject(resp.DeviceID, proto.EvtHeartbeat)},
	} {
		h.conns.handleEvent("beta", m)
	}
	for _, m := range []*nats.Msg{
		{Subject: proto.EventSubject("dev_unknown", proto.EvtHeartbeat)},
		{Subject: "kh.d.x"},
		{Subject: proto.EventSubject(resp.DeviceID, "other")},
		{Subject: proto.EventSubject(resp.DeviceID, proto.EvtHello), Data: []byte("{not json")},
	} {
		h.conns.handleEvent("acme", m)
	}
	after := h.device(resp.DeviceID)
	if after.Hostname != before.Hostname || !after.LastSeen.Equal(*before.LastSeen) {
		t.Fatalf("foreign or malformed events changed the device: %+v", after)
	}
}

func TestRevokeDeviceCutsItOff(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")
	resp, k := h.enrollDevice(h.mintToken("acme", adminapi.MintTokenRequest{}).Secret, "m-1")
	a := h.connectAgent(resp, k)

	var d model.Device
	h.must(adminapi.RouteRevokeDevice, []string{resp.DeviceID}, nil, &d)
	if d.RevokedAt == nil {
		t.Fatal("revoke did not report the device revoked")
	}
	a.waitClosed(t)
	if again, err := dialAgent(h.nats.ClientURL(), resp.UserJWT, k.seed); err == nil {
		again.Close()
		t.Fatal("a revoked device reconnected")
	}
	keys, err := h.st.AccountKeys(bg, "acme")
	if err != nil {
		t.Fatal(err)
	}
	ac, err := jwt.DecodeAccountClaims(keys.AccountJWT)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ac.Revocations[k.pub]; !ok {
		t.Fatal("the stored account JWT does not revoke the device key")
	}
	h.must(adminapi.RouteRevokeDevice, []string{resp.DeviceID}, nil, nil) // idempotent
	if r := h.call(adminapi.RouteRevokeDevice, []string{"dev_nope"}, nil); r.status != 404 {
		t.Fatalf("unknown device: %d", r.status)
	}
}

func TestReconcile(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")

	t.Run("pushes revocations the store has but NATS lacks", func(t *testing.T) {
		resp, k := h.enrollDevice(h.mintToken("acme", adminapi.MintTokenRequest{}).Secret, "m-1")
		a := h.connectAgent(resp, k)
		// As if the push after a revocation had failed.
		if _, err := h.st.RevokeDevice(bg, resp.DeviceID, time.Now()); err != nil {
			t.Fatal(err)
		}
		h.srv.reconcile(bg)
		a.waitClosed(t)
	})

	t.Run("replaces a lost client connection", func(t *testing.T) {
		nc, err := h.conns.Conn("acme")
		if err != nil {
			t.Fatal(err)
		}
		nc.Close()
		eventually(t, "the closed connection to be dropped", func() bool { return !h.conns.has("acme") })
		h.srv.reconcile(bg)
		eventually(t, "a new connection", func() bool {
			nc, err := h.conns.Conn("acme")
			return err == nil && nc.IsConnected()
		})
	})
}
