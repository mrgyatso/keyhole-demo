package relay

import (
	"bytes"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

func TestAdminRequiresToken(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")
	for _, route := range adminRoutes() {
		method, pattern := adminapi.Split(route)
		url := h.priv.URL + adminapi.Fill(pattern, "acme")
		for name, auth := range map[string]string{
			"missing":      "",
			"wrong":        "Bearer " + model.NewSecret(model.SecretAdmin),
			"wrong scheme": "Basic " + h.adminToken,
			"stored hash":  "Bearer " + model.HashSecret(h.adminToken),
			"empty":        "Bearer ",
		} {
			hdr := http.Header{}
			if auth != "" {
				hdr.Set("Authorization", auth)
			}
			r := h.do(method, url, nil, hdr)
			if r.status != http.StatusUnauthorized || r.errCode() != proto.ErrUnauthorized || r.header.Get("WWW-Authenticate") == "" {
				t.Errorf("%s %s with %s token: %d", method, pattern, name, r.status)
			}
		}
	}
	if r := h.call(adminapi.RouteListClients, nil, nil); r.status != http.StatusOK {
		t.Fatalf("the admin token was refused: %d", r.status)
	}
}

func TestCreateClient(t *testing.T) {
	h := newHarness(t)
	info := h.createClient("acme")
	if info.Slug != "acme" || info.Name != "ACME" || !strings.HasPrefix(info.AccountKey, "A") || info.Disabled || info.Devices != 0 {
		t.Fatalf("client info %+v", info)
	}
	eventually(t, "the relay's connection in acme's account", func() bool {
		nc, err := h.conns.Conn("acme")
		return err == nil && nc.IsConnected()
	})
	var pol model.ClientPolicy
	h.must(adminapi.RouteGetPolicy, []string{"acme"}, nil, &pol)
	if !reflect.DeepEqual(pol, policy.DefaultClientPolicy()) {
		t.Fatal("a new client does not start from the default policy")
	}

	if r := h.call(adminapi.RouteCreateClient, nil, adminapi.CreateClientRequest{Slug: "acme"}); r.status != http.StatusConflict {
		t.Fatalf("duplicate: %d", r.status)
	}
	for _, req := range []adminapi.CreateClientRequest{
		{Slug: "Bad Slug"}, {Slug: "-acme"}, {Slug: "x"}, {Slug: "okay", Name: strings.Repeat("n", 200)},
	} {
		if r := h.call(adminapi.RouteCreateClient, nil, req); r.status != http.StatusBadRequest {
			t.Errorf("%+v: %d", req, r.status)
		}
	}
	var beta adminapi.ClientInfo
	h.must(adminapi.RouteCreateClient, nil, adminapi.CreateClientRequest{Slug: "beta"}, &beta)
	if beta.Name != "beta" {
		t.Fatalf("empty name should default to the slug, got %q", beta.Name)
	}
	var list []adminapi.ClientInfo
	h.must(adminapi.RouteListClients, nil, nil, &list)
	if len(list) != 2 || list[0].Slug != "acme" || list[1].Slug != "beta" {
		t.Fatalf("list %+v", list)
	}
	if r := h.call(adminapi.RouteGetClient, []string{"nope"}, nil); r.status != http.StatusNotFound {
		t.Fatalf("unknown client: %d", r.status)
	}
}

func TestKillSwitch(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")
	var info adminapi.ClientInfo
	h.must(adminapi.RouteDisableClient, []string{"acme"}, adminapi.DisableRequest{Reason: "suspected compromise"}, &info)
	if !info.Disabled {
		t.Fatal("disable did not report the client disabled")
	}
	// The gateway reads the kill switch through Directory.Client.
	if c, err := h.st.Client(bg, "acme"); err != nil || !c.Disabled {
		t.Fatalf("directory still shows the client enabled: %v", err)
	}
	h.must(adminapi.RouteDisableClient, []string{"acme"}, nil, &info) // the body is optional
	h.must(adminapi.RouteEnableClient, []string{"acme"}, nil, &info)
	if info.Disabled {
		t.Fatal("enable did not clear the kill switch")
	}
	if c, _ := h.st.Client(bg, "acme"); c.Disabled {
		t.Fatal("directory still shows the client disabled")
	}
	if r := h.call(adminapi.RouteDisableClient, []string{"nope"}, nil); r.status != http.StatusNotFound {
		t.Fatalf("unknown client: %d", r.status)
	}
	var reasons []string
	for _, e := range h.entries("acme") {
		if e.Tool == toolClientDisable {
			reasons = append(reasons, string(e.Args))
		}
	}
	if len(reasons) != 2 || !strings.Contains(reasons[0], "suspected compromise") {
		t.Fatalf("disable entries %v", reasons)
	}
}

func TestTechnicianACLAdministration(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")
	req := adminapi.TechnicianACLRequest{Technician: "idp|alice", Client: "acme"}
	h.must(adminapi.RouteGrantTechnicianClient, nil, req, nil)
	allowed, err := h.st.TechnicianCanAccess(bg, req.Technician, req.Client)
	if err != nil || !allowed {
		t.Fatalf("granted ACL = %v, %v", allowed, err)
	}
	r := h.call(adminapi.RouteListTechnicianClients, nil, nil)
	if r.status != http.StatusBadRequest {
		t.Fatalf("missing technician query = %d", r.status)
	}
	r = h.do(http.MethodGet, h.priv.URL+"/v1/admin/technician-acls?technician=idp%7Calice", nil, h.adminHeader())
	if r.status != http.StatusOK || !strings.Contains(string(r.body), `"slug":"acme"`) {
		t.Fatalf("listed ACLs = %d %s", r.status, r.body)
	}
	h.must(adminapi.RouteRevokeTechnicianClient, nil, req, nil)
	allowed, err = h.st.TechnicianCanAccess(bg, req.Technician, req.Client)
	if err != nil || allowed {
		t.Fatalf("revoked ACL = %v, %v", allowed, err)
	}
	entries := h.entries("acme")
	if entries[len(entries)-2].Tool != toolACLGrant || entries[len(entries)-1].Tool != toolACLRevoke {
		t.Fatalf("ACL audit entries: %+v", entries)
	}
}

// TestMutationsAreAudited checks that every admin mutation and every
// enrollment lands in the client's chain, attributed to the actor, and that
// no entry carries a secret.
func TestMutationsAreAudited(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")
	h.must(adminapi.RouteDisableClient, []string{"acme"}, adminapi.DisableRequest{Reason: "incident"}, nil)
	h.must(adminapi.RouteEnableClient, []string{"acme"}, nil, nil)
	var pol model.ClientPolicy
	h.must(adminapi.RouteGetPolicy, []string{"acme"}, nil, &pol)
	pol.MaxMatches = 100
	h.must(adminapi.RoutePutPolicy, []string{"acme"}, pol, nil)
	tok1 := h.mintToken("acme", adminapi.MintTokenRequest{Note: "first"})
	h.must(adminapi.RouteRevokeToken, []string{tok1.Token.ID}, nil, nil)
	tok2 := h.mintToken("acme", adminapi.MintTokenRequest{})
	dev, _ := h.enrollDevice(tok2.Secret, "m-1")
	h.must(adminapi.RouteRevokeDevice, []string{dev.DeviceID}, nil, nil)
	var ses adminapi.MintSessionResponse
	h.must(adminapi.RouteMintSession, []string{"acme"}, adminapi.MintSessionRequest{Tech: "bob"}, &ses)
	h.must(adminapi.RouteRevokeSession, []string{ses.Session.ID}, nil, nil)

	want := []string{
		toolClientCreate, toolClientDisable, toolClientEnable, toolPolicySet,
		toolTokenMint, toolTokenRevoke, toolTokenMint, toolEnroll, toolDeviceRevoke,
		toolSessionMint, toolSessionRevoke,
	}
	entries := h.entries("acme")
	var got []string
	for _, e := range entries {
		got = append(got, e.Tool)
		wantKind, wantTech := audit.KindAdmin, "alice"
		if e.Tool == toolEnroll {
			wantKind, wantTech = audit.KindEnroll, ""
		}
		if e.Kind != wantKind || e.Tech != wantTech || e.Result != audit.ResultOK || e.Client != "acme" {
			t.Errorf("%s entry: kind %q tech %q result %q", e.Tool, e.Kind, e.Tech, e.Result)
		}
		for _, secret := range []string{tok1.Secret, tok2.Secret, ses.Bearer, h.adminToken} {
			if strings.Contains(string(e.Args), secret) {
				t.Errorf("%s entry carries a secret", e.Tool)
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("audited actions\n got %v\nwant %v", got, want)
	}
	if last := entries[len(entries)-3]; last.DeviceID != dev.DeviceID || last.DeviceKey == "" {
		t.Fatalf("device.revoke entry does not identify the device: %+v", last)
	}
	if v, _ := h.audit.Verify(bg, "acme"); !v.OK || v.Entries != uint64(len(want)) {
		t.Fatalf("chain %+v", v)
	}
}

// TestAuditFailure: a secret whose minting is not on record is never handed
// out, and a failed audit is reported even when the change stands.
func TestAuditFailure(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")
	acl := adminapi.TechnicianACLRequest{Technician: "idp|alice", Client: "acme"}
	h.must(adminapi.RouteGrantTechnicianClient, nil, acl, nil)
	tok := h.mintToken("acme", adminapi.MintTokenRequest{})
	h.audit.fail.Store(true)

	r := h.call(adminapi.RouteGrantTechnicianClient, nil, acl)
	if r.status != http.StatusInternalServerError || r.errCode() != proto.ErrAuditFailed {
		t.Fatalf("duplicate ACL grant with audit down: %d %s", r.status, r.body)
	}
	if allowed, _ := h.st.TechnicianCanAccess(bg, acl.Technician, acl.Client); !allowed {
		t.Fatal("an audit failure withdrew a pre-existing ACL")
	}

	r = h.call(adminapi.RouteMintToken, []string{"acme"}, nil)
	if r.status != http.StatusInternalServerError || r.errCode() != proto.ErrAuditFailed || bytes.Contains(r.body, []byte("khe_")) {
		t.Fatalf("token mint with audit down: %d %s", r.status, r.body)
	}
	toks, _ := h.st.Tokens(bg, "acme")
	if len(toks) != 2 || toks[1].RevokedAt == nil {
		t.Fatal("the unaudited token was left usable")
	}

	r = h.call(adminapi.RouteMintSession, []string{"acme"}, adminapi.MintSessionRequest{Tech: "bob"})
	if r.status != http.StatusInternalServerError || r.errCode() != proto.ErrAuditFailed || bytes.Contains(r.body, []byte("khs_")) {
		t.Fatalf("session mint with audit down: %d %s", r.status, r.body)
	}
	sessions, _ := h.st.Sessions(bg, "acme")
	if len(sessions) != 1 || sessions[0].RevokedAt == nil {
		t.Fatal("the unaudited session was left usable")
	}

	er := h.enroll(enrollRequest(tok.Secret, newDeviceKey(t), "m-1"), nil)
	if er.status != http.StatusInternalServerError || er.errCode() != proto.ErrAuditFailed || bytes.Contains(er.body, []byte("user_jwt")) {
		t.Fatalf("enroll with audit down: %d %s", er.status, er.body)
	}
	devices, _ := h.st.Devices(bg, "acme")
	if len(devices) != 1 || devices[0].RevokedAt == nil {
		t.Fatal("the unaudited device was left live")
	}

	r = h.call(adminapi.RouteDisableClient, []string{"acme"}, nil)
	if r.status != http.StatusInternalServerError || r.errCode() != proto.ErrAuditFailed {
		t.Fatalf("disable with audit down: %d", r.status)
	}
	if c, _ := h.st.Client(bg, "acme"); !c.Disabled {
		t.Fatal("the kill switch must work even when the audit store is down")
	}
}

func TestTokenAndSessionMint(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")

	r := h.call(adminapi.RouteMintToken, []string{"acme"}, nil) // empty body: defaults
	if r.status != http.StatusOK {
		t.Fatalf("mint: %d %s", r.status, r.body)
	}
	var tok adminapi.MintTokenResponse
	if err := jsonUnmarshal(r.body, &tok); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok.Secret, "khe_acme_") || tok.Token.ExpiresAt.Sub(tok.Token.CreatedAt) != 90*24*time.Hour || tok.Token.MaxUses != 0 {
		t.Fatalf("minted %+v", tok.Token)
	}
	if bytes.Contains(r.body, []byte(model.HashSecret(tok.Secret))) {
		t.Fatal("the response carries the token hash")
	}
	for _, req := range []adminapi.MintTokenRequest{{TTLDays: -1}, {TTLDays: 4000}, {MaxUses: -1}, {Note: "a\x00b"}} {
		if r := h.call(adminapi.RouteMintToken, []string{"acme"}, req); r.status != http.StatusBadRequest {
			t.Errorf("%+v: %d", req, r.status)
		}
	}
	if r := h.call(adminapi.RouteMintToken, []string{"nope"}, nil); r.status != http.StatusNotFound {
		t.Fatalf("unknown client: %d", r.status)
	}

	var ses adminapi.MintSessionResponse
	h.must(adminapi.RouteMintSession, []string{"acme"}, adminapi.MintSessionRequest{Tech: "bob", Note: "ticket 123"}, &ses)
	if !strings.HasPrefix(ses.Bearer, model.SecretSession+"_") || ses.MCPURL != "http://100.64.0.1:7802/mcp" {
		t.Fatalf("session %+v", ses)
	}
	wantCmd := `claude mcp add --transport http keyhole-acme http://100.64.0.1:7802/mcp --header "Authorization: Bearer ` + ses.Bearer + `"`
	if ses.ClaudeAddCommand != wantCmd {
		t.Fatalf("claude command\n got %s\nwant %s", ses.ClaudeAddCommand, wantCmd)
	}
	if ses.Session.ExpiresAt.Sub(ses.Session.CreatedAt) != 720*time.Minute || ses.Session.Tech != "bob" {
		t.Fatalf("session %+v", ses.Session)
	}
	got, err := h.st.SessionByToken(bg, ses.Bearer)
	if err != nil || got.ID != ses.Session.ID || got.Client != "acme" || got.Valid(time.Now()) != nil {
		t.Fatalf("the gateway cannot resolve the bearer: %+v %v", got, err)
	}
	for _, req := range []adminapi.MintSessionRequest{{}, {Tech: "  "}, {Tech: "bob", TTLMinutes: 20000}, {Tech: "bob", TTLMinutes: -5}} {
		if r := h.call(adminapi.RouteMintSession, []string{"acme"}, req); r.status != http.StatusBadRequest {
			t.Errorf("%+v: %d", req, r.status)
		}
	}
	if r := h.call(adminapi.RouteMintSession, []string{"nope"}, adminapi.MintSessionRequest{Tech: "bob"}); r.status != http.StatusNotFound {
		t.Fatalf("unknown client: %d", r.status)
	}
	var list []model.Session
	h.must(adminapi.RouteListSessions, []string{"acme"}, nil, &list)
	if len(list) != 1 {
		t.Fatalf("sessions %+v", list)
	}
	var revoked model.Session
	h.must(adminapi.RouteRevokeSession, []string{ses.Session.ID}, nil, &revoked)
	if got, _ := h.st.SessionByToken(bg, ses.Bearer); !errors.Is(got.Valid(time.Now()), model.ErrRevoked) {
		t.Fatal("a revoked session is still valid")
	}
	if r := h.call(adminapi.RouteRevokeSession, []string{"ses_nope"}, nil); r.status != http.StatusNotFound {
		t.Fatalf("unknown session: %d", r.status)
	}
}

func TestPolicyPut(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")
	var p model.ClientPolicy
	h.must(adminapi.RouteGetPolicy, []string{"acme"}, nil, &p)
	p.Allow["linux"] = append(p.Allow["linux"], proto.AllowRule{ID: "app", Path: "/opt/app/logs", Files: []string{"*.log"}})
	p.Version = 42
	var stored model.ClientPolicy
	h.must(adminapi.RoutePutPolicy, []string{"acme"}, p, &stored)
	if stored.Version != 2 {
		t.Fatalf("version %d, want 2 whatever the body says", stored.Version)
	}
	h.must(adminapi.RouteGetPolicy, []string{"acme"}, nil, &p)
	if p.Version != 2 || p.Allow["linux"][len(p.Allow["linux"])-1].ID != "app" {
		t.Fatalf("stored policy %+v", p)
	}
	bad := p
	bad.Allow = map[string][]proto.AllowRule{"windows": {{ID: "share", Path: `\\fileserver\share`}}}
	if r := h.call(adminapi.RoutePutPolicy, []string{"acme"}, bad); r.status != http.StatusBadRequest || r.errCode() != proto.ErrBadRequest {
		t.Fatalf("UNC rule accepted: %d", r.status)
	}
	if r := h.call(adminapi.RoutePutPolicy, []string{"nope"}, p); r.status != http.StatusNotFound {
		t.Fatalf("unknown client: %d", r.status)
	}
	entries := h.entries("acme")
	if last := entries[len(entries)-1]; last.Tool != toolPolicySet || !strings.Contains(string(last.Args), "/opt/app/logs") {
		t.Fatalf("policy entry %+v", last)
	}
}

// TestSecretsNeverLogged is security invariant #7 for the relay's own log.
func TestSecretsNeverLogged(t *testing.T) {
	h := newHarness(t)
	h.createClient("acme")
	tok := h.mintToken("acme", adminapi.MintTokenRequest{})
	_, k := h.enrollDevice(tok.Secret, "m-1")
	refused := model.NewEnrollSecret("acme")
	h.enroll(enrollRequest(refused, newDeviceKey(t), "m-2"), nil)
	var ses adminapi.MintSessionResponse
	h.must(adminapi.RouteMintSession, []string{"acme"}, adminapi.MintSessionRequest{Tech: "bob"}, &ses)
	wrongAdmin := model.NewSecret(model.SecretAdmin)
	h.do(http.MethodGet, h.priv.URL+"/v1/admin/clients", nil, http.Header{"Authorization": {"Bearer " + wrongAdmin}})
	h.audit.fail.Store(true) // error paths log too
	h.call(adminapi.RouteMintToken, []string{"acme"}, nil)
	h.call(adminapi.RouteMintSession, []string{"acme"}, adminapi.MintSessionRequest{Tech: "bob"})
	h.enroll(enrollRequest(tok.Secret, newDeviceKey(t), "m-3"), nil)
	h.audit.fail.Store(false)
	keys, err := h.st.AccountKeys(bg, "acme")
	if err != nil {
		t.Fatal(err)
	}

	logs := h.logs.String()
	for _, want := range []string{"device enrolled", "enrollment refused", "session minted", "audit append failed"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("expected %q in the log; the test would be vacuous", want)
		}
	}
	for name, secret := range map[string]string{
		"enrollment token":         tok.Secret,
		"refused enrollment token": refused,
		"session bearer":           ses.Bearer,
		"admin token":              h.adminToken,
		"wrong admin token":        wrongAdmin,
		"device seed":              k.seed,
		"account signing seed":     keys.SigningSeed,
		"relay user seed":          keys.RelaySeed,
		"operator signing seed":    h.op.SigningSeed,
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log contains the %s", name)
		}
	}
}
