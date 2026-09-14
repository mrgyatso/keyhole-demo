package e2e_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/companion"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/passkey/passkeytest"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// companionBrowser is a technician's browser on the companion: a cookie jar
// for the sign-in, and a software passkey that signs what the page asks.
type companionBrowser struct {
	t      *testing.T
	origin string
	client *http.Client
	key    *passkeytest.Authenticator
}

// post sends what the companion's own page sends: JSON, with its Origin. It
// decodes an OK answer into out and returns the status.
func (b *companionBrowser) post(path string, body, out any) int {
	b.t.Helper()
	raw, err := json.Marshal(body)
	check(b.t, err)
	req, err := http.NewRequest(http.MethodPost, b.origin+path, bytes.NewReader(raw))
	check(b.t, err)
	req.Header.Set("Origin", b.origin)
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	check(b.t, err)
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		b.t.Logf("POST %s: %d %s", path, resp.StatusCode, data)
	} else if out != nil {
		check(b.t, json.Unmarshal(data, out))
	}
	return resp.StatusCode
}

// begun is what a passkey ceremony's begin answers, as far as the page reads
// it.
type begun struct {
	Technician string `json:"technician"`
	Options    struct {
		Challenge string `json:"challenge"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"options"`
}

func (g begun) challenge(t *testing.T) []byte {
	t.Helper()
	c, err := base64.RawURLEncoding.DecodeString(g.Options.Challenge)
	check(t, err)
	return c
}

// enrollFinish is the body the enrollment page sends once the passkey exists.
type enrollFinish struct {
	Token             string `json:"token"`
	CredentialID      string `json:"credential_id"`
	PublicKey         []byte `json:"public_key"`
	Algorithm         int    `json:"algorithm"`
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Name              string `json:"name"`
}

// approve approves a card on the browser's sign-in, as the page does on
// Approve: no passkey prompt, an empty body. It returns approve's status.
func (b *companionBrowser) approve(kind, id string) int {
	b.t.Helper()
	return b.post("/api/"+kind+"/"+id+"/approve", struct{}{}, nil)
}

// TestCompanionApprovesThroughTheRealGate drives the companion as a
// technician's browser would, with a software passkey, against the real
// gateway and endpoint: enrollment through a one-time link, sign-in, the
// unlock card, reads, the change card, and signing out.
func TestCompanionApprovesThroughTheRealGate(t *testing.T) {
	e := setupApproval(t, false)
	var h http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	comp, err := companion.New(companion.Config{Store: e.st, Directory: e.st, Gate: e.gw, Origin: srv.URL})
	check(t, err)
	h = comp.Handler()
	jar, err := cookiejar.New(nil)
	check(t, err)
	b := &companionBrowser{t: t, origin: srv.URL, client: &http.Client{Jar: jar}, key: passkeytest.New(t, "127.0.0.1", srv.URL)}

	// A one-time link, as `keyhole technician passkey-link` mints, enrolls
	// the passkey and signs the technician in.
	secret, now := model.NewSecret(model.SecretPasskeyLink), time.Now().UTC()
	check(t, e.st.CreatePasskeyLink(e.ctx, model.PasskeyLink{ID: model.NewID(model.PrefixPasskeyLink), Technician: approvalTech,
		Hash: model.HashSecret(secret), CreatedAt: now, ExpiresAt: now.Add(model.PasskeyLinkTTL)}))
	var g begun
	if code := b.post("/api/enroll/begin", map[string]string{"token": secret}, &g); code != http.StatusOK || g.Technician != approvalTech {
		t.Fatalf("enroll begin: %d %+v", code, g)
	}
	handle, err := base64.RawURLEncoding.DecodeString(g.Options.User.ID)
	check(t, err)
	b.key.UserHandle = handle // a discoverable passkey returns its user.id with every assertion
	att := b.key.Create(g.challenge(t))
	if code := b.post("/api/enroll/finish", enrollFinish{Token: secret, CredentialID: att.CredentialID, PublicKey: att.PublicKey,
		Algorithm: att.Algorithm, AuthenticatorData: att.AuthenticatorData, ClientDataJSON: att.ClientDataJSON, Name: "e2e key"}, nil); code != http.StatusOK {
		t.Fatalf("enroll finish: %d", code)
	}

	// The model asks for access; the technician unlocks the client on its card.
	first := e.requestAccess("ticket 77: vendor errors")
	if first.State != model.AccessAwaitingUnlock {
		t.Fatalf("first request: %s", first.State)
	}
	if code := b.approve("unlocks", first.Unlock); code != http.StatusOK {
		t.Fatalf("approving the unlock on its card: %d", code)
	}
	e.access(first.ID, model.AccessApproved, model.AccessActive)
	if text, bad := e.read(first.ID, e.file); bad || !strings.Contains(text, "retries=3") {
		t.Fatalf("read under the unlock: %s", text)
	}

	// The model prepares and submits a change; the technician approves its
	// card, and only then is the file written.
	second := e.requestAccess("ticket 77: fix the retry setting", proto.OpReadFile, proto.OpPrepareFileChange, proto.OpApplyFileChange)
	second = e.access(second.ID, model.AccessApproved, model.AccessActive)
	planID, digest := e.prepare(second.ID, cfg1)
	if text, bad := e.call(proto.OpApplyFileChange, map[string]any{"device": e.deviceID, "access_id": second.ID,
		"plan_id": planID, "plan_digest": digest}); bad {
		t.Fatalf("apply_file_change: %s", text)
	}
	ca := e.submitted(second.ID, planID, proto.OpApplyFileChange)
	if onDisk(t, e.file) != cfg0 {
		t.Fatal("the change was written before its card was approved")
	}
	if code := b.approve("changes", ca.ID); code != http.StatusOK {
		t.Fatalf("approving the change on its card: %d", code)
	}
	got, err := e.st.ChangeApproval(e.ctx, ca.ID)
	check(t, err)
	if got.State != model.ChangeApplied || onDisk(t, e.file) != cfg1 {
		t.Fatalf("after the card's approval: %s (%s %s), file %q", got.State, got.ErrorCode, got.Reason, onDisk(t, e.file))
	}

	// Signing out locks the client, and every grant made under it ends.
	if code := b.post("/api/logout", struct{}{}, nil); code != http.StatusOK {
		t.Fatalf("sign-out: %d", code)
	}
	e.access(first.ID, model.AccessTerminated)
	e.access(second.ID, model.AccessTerminated)
}
