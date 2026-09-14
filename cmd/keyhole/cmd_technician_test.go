package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/adminclient/adminfake"
	"github.com/mrgyatso/keyhole/internal/model"
)

func TestTechnicianPasskeyLink(t *testing.T) {
	h := newHarness(t)
	out := h.ok("technician", "passkey-link", "idp|alice")
	url := secretIn(out, adminfake.DefaultCompanionURL+"/enroll#khp_")
	if url == "" || !strings.Contains(out, "one-time secret") || !strings.Contains(out, "shown once") {
		t.Fatalf("passkey-link output:\n%s", out)
	}
	reqs := h.admin.Requests()
	var req adminapi.PasskeyLinkRequest
	if err := json.Unmarshal(reqs[len(reqs)-1].Body, &req); err != nil || req.Technician != "idp|alice" {
		t.Fatalf("request %s: %v", reqs[len(reqs)-1].Body, err)
	}
	var resp adminapi.PasskeyLinkResponse
	if err := json.Unmarshal([]byte(h.ok("technician", "passkey-link", "idp|alice", "--json")), &resp); err != nil ||
		!strings.Contains(resp.URL, "#khp_") || resp.URL == url {
		t.Fatalf("--json: %+v, %v", resp, err)
	}

	// A relay without a companion refuses, and the CLI says why.
	h.admin.SetCompanionURL("")
	_, errOut, code := h.run("", false, "technician", "passkey-link", "idp|alice")
	if code != exitError || !strings.Contains(errOut, "technician approval is off") {
		t.Fatalf("without a companion: exit %d, %q", code, errOut)
	}
}

func TestTechnicianPasskeysAndRevoke(t *testing.T) {
	h := newHarness(t)
	if out := h.ok("technician", "passkeys", "idp|alice"); !strings.Contains(out, "keyhole technician passkey-link idp|alice") {
		t.Fatalf("empty list: %s", out)
	}
	last := h.now.Add(-time.Hour)
	h.admin.AddPasskey(model.Passkey{CredentialID: "Y3JlZC0x", Technician: "idp|alice", Name: "MacBook Touch ID",
		Algorithm: -7, CreatedAt: h.now.Add(-48 * time.Hour), LastUsedAt: &last})
	out := h.ok("technician", "passkeys", "idp|alice")
	for _, want := range []string{"Y3JlZC0x", "MacBook Touch ID", "active", "ago"} {
		if !strings.Contains(out, want) {
			t.Fatalf("passkeys table lacks %q:\n%s", want, out)
		}
	}

	// Revoking asks first, and refuses without a terminal.
	_, errOut, code := h.run("", false, "technician", "passkey-revoke", "Y3JlZC0x")
	if code != exitError || !strings.Contains(errOut, "--yes") || h.requests("POST", "/revoke") != 0 {
		t.Fatalf("revoke without --yes: exit %d, %q", code, errOut)
	}
	if out := h.ok("technician", "passkey-revoke", "Y3JlZC0x", "--yes"); !strings.Contains(out, "Revoked passkey Y3JlZC0x") {
		t.Fatalf("revoke output: %s", out)
	}
	if p, _ := h.admin.Passkey("Y3JlZC0x"); p.RevokedAt == nil {
		t.Fatal("passkey not revoked")
	}
	if out := h.ok("technician", "passkeys", "idp|alice"); !strings.Contains(out, "revoked") {
		t.Fatalf("list after revoke: %s", out)
	}

	// A pasted secret or enrollment link is refused before anything is sent,
	// and never echoed.
	sent := len(h.admin.Requests())
	const body = "abcdefghijklmnopqrstuvwxyz234567"
	for _, arg := range []string{"khp_" + body, adminfake.DefaultCompanionURL + "/enroll#khp_" + body, "khc_" + body, "khs_" + body} {
		_, errOut, code := h.run("", false, "technician", "passkey-revoke", arg, "--yes")
		if code != exitUsage || strings.Contains(errOut, body) || !strings.Contains(errOut, "that is a secret") {
			t.Errorf("%s: exit %d, %q", arg[:4], code, errOut)
		}
	}
	if _, _, code := h.run("", false, "technician", "passkey-revoke", "not/base64url", "--yes"); code != exitUsage {
		t.Fatalf("bad credential ID: exit %d", code)
	}
	if n := len(h.admin.Requests()); n != sent {
		t.Fatalf("refused arguments sent %d requests", n-sent)
	}
}
