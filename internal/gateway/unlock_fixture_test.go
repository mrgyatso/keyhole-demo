package gateway

import (
	"cmp"
	"context"
	"encoding/json"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/store"
)

// The technician identity of the unlock tests, the passkeys enrolled for it
// and for another technician, and the companion's origin.
const (
	unlockBearer    = "oidc_unlock_alice"
	unlockSession   = "idp_unlock_alice"
	unlockTech      = "tech_alice"
	unlockCred      = "cred-alice"
	unlockOldCred   = "cred-alice-old" // enrolled, then revoked
	unlockOtherTech = "tech_bob"
	unlockOtherCred = "cred-bob"
	unlockCompanion = "https://companion.test"
)

// unlockApprovals is the relay's store for technician approval, except that
// access requests live in the fixture's fake directory, as the gateway's
// Access store does there; so the requests made under an unlock are read from
// there too. In the relay both are the same store.
type unlockApprovals struct {
	*store.Store
	dir *fakeDir
}

func (s unlockApprovals) AccessForUnlock(_ context.Context, id string) ([]model.AccessRequest, error) {
	s.dir.mu.Lock()
	defer s.dir.mu.Unlock()
	var out []model.AccessRequest
	for _, a := range s.dir.access {
		if a.Unlock == id {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, func(a, b model.AccessRequest) int {
		return cmp.Or(a.RequestedAt.Compare(b.RequestedAt), strings.Compare(a.ID, b.ID))
	})
	return out, nil
}

// unlockFixture is the gateway fixture with technician approval on. A real
// store holds unlocks and passkeys, and g is a second gateway over the same
// stores, through which tests call the gate methods the companion calls.
type unlockFixture struct {
	*fixture
	st *store.Store
	g  *Gateway
}

func newUnlockFixture(t *testing.T, tweak ...func(*Config)) *unlockFixture {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "keyhole.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for _, slug := range []string{"acme", "globex"} {
		keys := store.AccountKeys{AccountKey: "A-" + slug, AccountSeed: "SA-" + slug, SigningSeed: "SS-" + slug,
			AccountJWT: "jwt-" + slug, RelayJWT: "relay-jwt-" + slug, RelaySeed: "SU-" + slug}
		if err := st.CreateClient(ctx, model.Client{Slug: slug, Name: slug, CreatedAt: time.Now(), Policy: policy.DefaultClientPolicy()}, keys); err != nil {
			t.Fatal(err)
		}
	}
	var cfg *Config
	f := newFixture(t, append([]func(*Config){func(c *Config) {
		c.Approvals = unlockApprovals{Store: st, dir: c.Directory.(*fakeDir)}
		c.CompanionURL = unlockCompanion + "/"
		c.Authenticator = fakeAuthenticator{sessions: map[string]model.TechnicianSession{
			unlockBearer: {ID: unlockSession, Technician: unlockTech, Name: "Alice", MFA: true, ExpiresAt: time.Now().Add(time.Hour)},
		}}
		cfg = c
	}}, tweak...)...)
	g, err := New(*cfg)
	if err != nil {
		t.Fatal(err)
	}
	u := &unlockFixture{fixture: f, st: st, g: g}
	u.enroll(t, unlockTech, unlockCred)
	u.enroll(t, unlockTech, unlockOldCred)
	u.enroll(t, unlockOtherTech, unlockOtherCred)
	if err := st.RevokePasskey(ctx, unlockOldCred, time.Now()); err != nil {
		t.Fatal(err)
	}
	return u
}

// enroll stores a passkey for tech through a one-time link, as the companion's
// enrollment does. Its key is never used: the companion verifies signatures.
func (u *unlockFixture) enroll(t *testing.T, tech, cred string) {
	t.Helper()
	ctx, now := context.Background(), time.Now().UTC()
	link := model.PasskeyLink{ID: model.NewID(model.PrefixPasskeyLink), Technician: tech, Hash: model.HashSecret(cred + "-link"),
		CreatedAt: now, ExpiresAt: now.Add(model.PasskeyLinkTTL)}
	if err := u.st.CreatePasskeyLink(ctx, link); err != nil {
		t.Fatal(err)
	}
	if err := u.st.UsePasskeyLink(ctx, link.ID, model.Passkey{CredentialID: cred, Technician: tech, PublicKey: []byte{1}, Algorithm: -7}, now); err != nil {
		t.Fatal(err)
	}
}

// unlockEndpoint makes agent behave as a managed endpoint running the
// technician consent adapter, together with the relay recording its decision:
// a request that carries the technician's unlock and does not ask the person
// at the machine is approved as asked, after delay.
func unlockEndpoint(f *fixture, agent *fakeAgent, delay time.Duration) {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	agent.during = func(req proto.Request) {
		if req.Op != proto.OpRequestAccess {
			return
		}
		var cr proto.ConsentRequest
		if json.Unmarshal(req.Args, &cr) != nil || cr.Approval == nil || cr.EndpointConsent {
			return
		}
		approve := func() {
			f.dir.update(func(d *fakeDir) {
				a, ok := d.access[cr.AccessID]
				if !ok || a.State != model.AccessAwaiting {
					return
				}
				issued := cr.ExpiresAt.Add(-cr.Duration)
				a.State, a.DecidedAt, a.Approver = model.AccessApproved, &issued, cr.Approval.ApproverLabel()
				a.GrantID, a.Nonce = "grt_"+cr.AccessID, "nonce_"+cr.AccessID
				a.EffectiveScope, a.EffectiveOperations = slices.Clone(cr.Paths), slices.Clone(cr.Operations)
				d.access[cr.AccessID] = a
			})
		}
		if delay == 0 {
			approve()
			return
		}
		go func() {
			time.Sleep(delay)
			approve()
		}()
	}
}

// unlockAsk is a request_access call for SRV01 in acme, with extra fields.
func unlockAsk(extra map[string]any) map[string]any {
	m := map[string]any{"client": "acme", "device": "SRV01", "purpose": "ticket 42"}
	maps.Copy(m, extra)
	return m
}

// request calls request_access and decodes its answer.
func (u *unlockFixture) request(t *testing.T, cs *mcp.ClientSession, args map[string]any) accessAnswer {
	t.Helper()
	text, isErr := call(t, cs, proto.OpRequestAccess, args)
	if isErr {
		t.Fatalf("request_access %v: %s", args, text)
	}
	var a accessAnswer
	if err := json.Unmarshal([]byte(text), &a); err != nil {
		t.Fatalf("request_access answer %q: %v", text, err)
	}
	return a
}

func (u *unlockFixture) unlockRow(t *testing.T, id string) model.Unlock {
	t.Helper()
	got, err := u.st.Unlock(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (u *unlockFixture) accessRow(t *testing.T, id string) model.AccessRequest {
	t.Helper()
	a, err := u.dir.Access(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// setUnlock changes a stored unlock, as time passing or another writer would.
func (u *unlockFixture) setUnlock(t *testing.T, id string, change func(*model.Unlock)) model.Unlock {
	t.Helper()
	got, err := u.st.UpdateUnlockTx(context.Background(), id, func(r *model.Unlock) error {
		change(r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// begin does what the companion's begin does: it rotates the unlock's nonce
// and offers its expiry, as of began.
func (u *unlockFixture) begin(t *testing.T, id string, began time.Time) model.Unlock {
	t.Helper()
	return u.setUnlock(t, id, func(r *model.Unlock) {
		expires := began.Add(r.Duration)
		r.Nonce, r.ExpiresAt = model.NewID("nonce"), &expires
	})
}

// unlockSigned is the approval the companion hands the gate once it has
// verified the technician's assertion over row as it stands.
func unlockSigned(row model.Unlock, cred string, at time.Time) proto.TechnicianApproval {
	a := row.Approval()
	a.Credential, a.ApprovedAt = cred, at
	a.Assertion = &proto.PasskeyAssertion{CredentialID: cred, AuthenticatorData: []byte("authenticator"),
		ClientDataJSON: []byte(`{"type":"webauthn.get"}`), Signature: []byte("signature")}
	return a
}

// approve approves unlock id as the technician, with her passkey, the way the
// companion does: begin now, then hand the gate the verified approval.
func (u *unlockFixture) approve(t *testing.T, id string) model.Unlock {
	t.Helper()
	row := u.begin(t, id, u.now)
	got, err := u.g.ApproveUnlock(context.Background(), id, unlockSigned(row, unlockCred, u.now))
	if err != nil {
		t.Fatalf("ApproveUnlock: %v", err)
	}
	return got
}

// pendingUnlock stores an unlock of client awaiting approval, requested at
// requested, without any MCP call.
func (u *unlockFixture) pendingUnlock(t *testing.T, client string, requested time.Time) model.Unlock {
	t.Helper()
	unl := model.Unlock{ID: model.NewID(model.PrefixUnlock), Technician: unlockTech, Client: client, Session: unlockSession,
		Purpose: "ticket 42", State: model.UnlockAwaiting, Duration: time.Hour, IdleTimeout: model.DefaultUnlockIdle,
		RequestedAt: requested, Deadline: requested.Add(model.UnlockApprovalWindow)}
	if err := u.st.CreateUnlock(context.Background(), unl); err != nil {
		t.Fatal(err)
	}
	return unl
}

// waitingRow stores a request for device waiting for unl.
func (u *unlockFixture) waitingRow(t *testing.T, unl model.Unlock, device string) model.AccessRequest {
	t.Helper()
	deadline := unl.Deadline
	a := model.AccessRequest{ID: model.NewID(model.PrefixAccess), Client: unl.Client, Device: device, Technician: unl.Technician,
		Session: unl.Session, Purpose: unl.Purpose, State: model.AccessAwaitingUnlock, RequestedScope: []string{`C:\Windows\Logs`},
		RequestedOperations: slices.Clone(readOperations), RequestedAt: unl.RequestedAt, ExpiresAt: unl.RequestedAt.Add(time.Hour),
		IdleTimeout: model.DefaultUnlockIdle, PolicyVersion: 1, ConsentDeadline: &deadline, Unlock: unl.ID}
	if err := u.dir.CreateAccess(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	return a
}

// unlockForwards returns every access request forwarded to agent.
func unlockForwards(t *testing.T, agent *fakeAgent) []proto.ConsentRequest {
	t.Helper()
	var out []proto.ConsentRequest
	for _, r := range agent.requests() {
		if r.Op != proto.OpRequestAccess {
			continue
		}
		var cr proto.ConsentRequest
		if err := json.Unmarshal(r.Args, &cr); err != nil {
			t.Fatal(err)
		}
		out = append(out, cr)
	}
	return out
}

// unlockForward returns the forward of access request id to agent.
func unlockForward(t *testing.T, agent *fakeAgent, id string) proto.ConsentRequest {
	t.Helper()
	for _, cr := range unlockForwards(t, agent) {
		if cr.AccessID == id {
			return cr
		}
	}
	t.Fatalf("access request %s was never forwarded", id)
	return proto.ConsentRequest{}
}

// unlockRevocations returns every end_access agent was sent.
func unlockRevocations(t *testing.T, agent *fakeAgent) []proto.EndAccessArgs {
	t.Helper()
	var out []proto.EndAccessArgs
	for _, r := range agent.requests() {
		if r.Op != proto.OpEndAccess {
			continue
		}
		var e proto.EndAccessArgs
		if err := json.Unmarshal(r.Args, &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

// unlockEntries returns client's consent entries recorded under tool.
func (u *unlockFixture) unlockEntries(t *testing.T, client, tool string) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	for _, e := range u.entries(t, client) {
		if e.Kind == audit.KindConsent && e.Tool == tool {
			out = append(out, e)
		}
	}
	return out
}
