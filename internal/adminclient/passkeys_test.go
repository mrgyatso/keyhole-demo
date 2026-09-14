package adminclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/adminclient"
	"github.com/mrgyatso/keyhole/internal/adminclient/adminfake"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

func TestPasskeyRoutes(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()

	link := try(c.MintPasskeyLink(ctx, "idp|alice")).must(t)
	if !strings.HasPrefix(link.URL, adminfake.DefaultCompanionURL+"/enroll#khp_") || link.Technician != "idp|alice" || link.ExpiresAt.IsZero() {
		t.Fatalf("link %+v", link)
	}
	now := time.Now().UTC()
	f.AddPasskey(model.Passkey{CredentialID: "Y3JlZC0x", Technician: "idp|alice", Name: "Laptop", Algorithm: -7, CreatedAt: now})
	f.AddPasskey(model.Passkey{CredentialID: "Y3JlZC0y", Technician: "idp|bob", Name: "Phone", Algorithm: -7, CreatedAt: now})
	if list := try(c.Passkeys(ctx, "idp|alice")).must(t); len(list) != 1 || list[0].Name != "Laptop" {
		t.Fatalf("passkeys: %+v", list)
	}
	if p := try(c.RevokePasskey(ctx, "Y3JlZC0x")).must(t); p.RevokedAt == nil || p.Technician != "idp|alice" {
		t.Fatalf("revoke: %+v", p)
	}
	if p, _ := f.Passkey("Y3JlZC0x"); p.RevokedAt == nil {
		t.Fatal("passkey not revoked")
	}

	reqs := f.Requests()
	want := []string{
		route(adminapi.RouteMintPasskeyLink),
		route(adminapi.RouteListPasskeys),
		route(adminapi.RouteRevokePasskey, "Y3JlZC0x"),
	}
	if len(reqs) != len(want) {
		t.Fatalf("got %d requests, want %d", len(reqs), len(want))
	}
	for i, r := range reqs {
		if got := r.Method + " " + r.Path; got != want[i] || r.Auth != "Bearer "+token {
			t.Errorf("request %d = %s (auth %q), want %s", i, got, r.Auth, want[i])
		}
	}
	var mint adminapi.PasskeyLinkRequest
	if err := json.Unmarshal(reqs[0].Body, &mint); err != nil || mint.Technician != "idp|alice" {
		t.Errorf("mint body %s: %v", reqs[0].Body, err)
	}
	if q := reqs[1].Query.Get("technician"); q != "idp|alice" {
		t.Errorf("list query technician = %q", q)
	}

	if _, err := c.RevokePasskey(ctx, "bm9uZQ"); adminclient.ErrorCode(err) != proto.ErrNotFound {
		t.Fatalf("revoke unknown: %v", err)
	}
	f.SetCompanionURL("")
	_, err := c.MintPasskeyLink(ctx, "idp|alice")
	var ae *adminclient.Error
	if !errors.As(err, &ae) || ae.Status != http.StatusServiceUnavailable || ae.Code != "unavailable" {
		t.Fatalf("mint without a companion: %v", err)
	}
	if n := len(f.PasskeyLinks()); n != 1 {
		t.Fatalf("%d links minted, want 1", n)
	}
}
