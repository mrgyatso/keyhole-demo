package relay

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/companion"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

const companionOrigin = "https://companion.keyhole.test"

// storedApprovalRows counts, by purging them, the passkey links and other
// technician-approval rows a fresh store holds.
func (h *harness) storedApprovalRows() int64 {
	h.t.Helper()
	n, err := h.st.PurgeApprovals(bg, time.Now().Add(24*time.Hour))
	if err != nil {
		h.t.Fatal(err)
	}
	return n
}

func TestPasskeyAdminRequiresToken(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.CompanionURL = companionOrigin })
	for _, route := range []string{adminapi.RouteMintPasskeyLink, adminapi.RouteListPasskeys, adminapi.RouteRevokePasskey} {
		method, pattern := adminapi.Split(route)
		url := h.priv.URL + adminapi.Fill(pattern, "Y3JlZA") + "?technician=alice"
		for name, hdr := range map[string]http.Header{
			"missing": {},
			"wrong":   {"Authorization": {"Bearer " + model.NewSecret(model.SecretAdmin)}},
		} {
			r := h.do(method, url, adminapi.PasskeyLinkRequest{Technician: "alice"}, hdr)
			if r.status != http.StatusUnauthorized || r.errCode() != proto.ErrUnauthorized {
				t.Errorf("%s with a %s token: %d", route, name, r.status)
			}
		}
	}
	if n := h.storedApprovalRows(); n != 0 {
		t.Fatalf("unauthenticated requests stored %d rows", n)
	}
}

func TestPasskeyLinkNeedsTheCompanion(t *testing.T) {
	h := newHarness(t)
	r := h.call(adminapi.RouteMintPasskeyLink, nil, adminapi.PasskeyLinkRequest{Technician: "idp|alice"})
	if r.status != http.StatusServiceUnavailable || r.errCode() != codeUnavailable || !strings.Contains(string(r.body), "technician approval is off") {
		t.Fatalf("mint without a companion: %d %s", r.status, r.body)
	}
	if n := h.storedApprovalRows(); n != 0 {
		t.Fatalf("a link was stored without a companion to enroll at: %d rows", n)
	}
}

func TestPasskeyLinkMintListRevoke(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.CompanionURL = companionOrigin + "/" })
	before := time.Now().UTC()
	var link adminapi.PasskeyLinkResponse
	h.must(adminapi.RouteMintPasskeyLink, nil, adminapi.PasskeyLinkRequest{Technician: " idp|alice "}, &link)
	prefix := companionOrigin + companion.EnrollPath + "#" + model.SecretPasskeyLink + "_"
	if !strings.HasPrefix(link.URL, prefix) || link.Technician != "idp|alice" || !strings.HasPrefix(link.ID, model.PrefixPasskeyLink+"_") {
		t.Fatalf("link %+v", link)
	}
	if ttl := link.ExpiresAt.Sub(before); ttl < model.PasskeyLinkTTL-time.Minute || ttl > model.PasskeyLinkTTL+time.Minute {
		t.Fatalf("link lifetime %s", ttl)
	}

	// Only the hash is stored, and it resolves the secret in the fragment.
	secret := link.URL[strings.Index(link.URL, "#")+1:]
	stored, err := h.st.PasskeyLinkByToken(bg, secret, time.Now())
	if err != nil || stored.ID != link.ID || stored.Technician != "idp|alice" {
		t.Fatalf("stored link %+v, %v", stored, err)
	}
	if stored.Hash != model.HashSecret(secret) {
		t.Fatal("the stored link is not the hash of its secret")
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "passkey link minted") {
		t.Fatal("the mint was not logged; the next check would be vacuous")
	}
	if strings.Contains(logs, secret) {
		t.Fatal("the log contains the link secret")
	}

	for _, bad := range []adminapi.PasskeyLinkRequest{{}, {Technician: "  "}, {Technician: "alice\nbob"},
		{Technician: strings.Repeat("a", maxActorLen+1)}} {
		if r := h.call(adminapi.RouteMintPasskeyLink, nil, bad); r.status != http.StatusBadRequest {
			t.Errorf("mint for %q: %d", bad.Technician, r.status)
		}
	}

	// The companion enrolls the passkey; the admin API lists and revokes it.
	p := model.Passkey{CredentialID: "Y3JlZC0x", Technician: "idp|alice", PublicKey: []byte("spki"), Algorithm: -7, Name: "Laptop"}
	if err := h.st.UsePasskeyLink(bg, link.ID, p, time.Now()); err != nil {
		t.Fatal(err)
	}
	r := h.do(http.MethodGet, h.priv.URL+"/v1/admin/passkeys?technician=idp%7Calice", nil, h.adminHeader())
	var list []model.Passkey
	if r.status != http.StatusOK || json.Unmarshal(r.body, &list) != nil || len(list) != 1 || list[0].Name != "Laptop" || list[0].RevokedAt != nil {
		t.Fatalf("list: %d %s", r.status, r.body)
	}
	if strings.Contains(string(r.body), "public_key") {
		t.Fatal("the list returns public keys")
	}
	r = h.do(http.MethodGet, h.priv.URL+"/v1/admin/passkeys?technician=nobody", nil, h.adminHeader())
	if r.status != http.StatusOK || strings.TrimSpace(string(r.body)) != "[]" {
		t.Fatalf("empty list: %d %s", r.status, r.body)
	}
	if r := h.call(adminapi.RouteListPasskeys, nil, nil); r.status != http.StatusBadRequest {
		t.Fatalf("list without a technician: %d", r.status)
	}

	var revoked model.Passkey
	h.must(adminapi.RouteRevokePasskey, []string{p.CredentialID}, nil, &revoked)
	if revoked.RevokedAt == nil || revoked.Technician != "idp|alice" {
		t.Fatalf("revoke returned %+v", revoked)
	}
	if got, _ := h.st.Passkey(bg, p.CredentialID); got.Live() == nil {
		t.Fatal("the passkey is still live")
	}
	if r := h.call(adminapi.RouteRevokePasskey, []string{"bm9uZQ"}, nil); r.status != http.StatusNotFound {
		t.Fatalf("revoke unknown: %d", r.status)
	}
}
