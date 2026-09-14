package store_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/store"
)

var ctx = context.Background()

func openStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keyhole.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, path
}

func addClient(t *testing.T, st *store.Store, slug string) model.Client {
	t.Helper()
	c := model.Client{Slug: slug, Name: strings.ToUpper(slug), CreatedAt: time.Now(), Policy: policy.DefaultClientPolicy()}
	keys := store.AccountKeys{
		AccountKey: "A-" + slug, AccountSeed: "SA-" + slug, SigningSeed: "SS-" + slug,
		AccountJWT: "jwt-" + slug, RelayJWT: "relay-jwt-" + slug, RelaySeed: "SU-" + slug,
	}
	if err := st.CreateClient(ctx, c, keys); err != nil {
		t.Fatal(err)
	}
	got, err := st.Client(ctx, slug)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// addToken stores a token and returns its secret.
func addToken(t *testing.T, st *store.Store, client string, mutate func(*model.EnrollToken)) string {
	t.Helper()
	secret := model.NewEnrollSecret(client)
	now := time.Now()
	tok := model.EnrollToken{
		ID: model.NewID(model.PrefixToken), Client: client, Hash: model.HashSecret(secret),
		CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}
	if mutate != nil {
		mutate(&tok)
	}
	if err := st.CreateToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	return secret
}

func newDevice(key, machine string) model.Device {
	return model.Device{
		ID: model.NewID(model.PrefixDevice), PublicKey: key, Hostname: "HOST-" + machine, MachineID: machine,
		OS: "windows", OSVersion: "10.0.26100", Arch: "amd64", AgentVersion: "v0.1.0",
	}
}

func TestOpenMigratesOnceAndIsPrivate(t *testing.T) {
	st, path := openStore(t)
	addClient(t, st, "acme")
	st.Close()
	st2, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	if _, err := st2.Client(ctx, "acme"); err != nil {
		t.Fatalf("data lost on reopen: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("database mode %o, want 600", perm)
	}
}

func TestClients(t *testing.T) {
	st, _ := openStore(t)
	acme := addClient(t, st, "acme")
	addClient(t, st, "beta")
	if acme.AccountKey != "A-acme" || acme.Name != "ACME" || acme.Policy.Version != 1 || acme.CreatedAt.Location() != time.UTC {
		t.Fatalf("stored client: %+v", acme)
	}
	err := st.CreateClient(ctx, model.Client{Slug: "acme", CreatedAt: time.Now()}, store.AccountKeys{AccountKey: "A-other"})
	if !errors.Is(err, model.ErrConflict) {
		t.Fatalf("duplicate slug: %v", err)
	}
	err = st.CreateClient(ctx, model.Client{Slug: "gamma", CreatedAt: time.Now()}, store.AccountKeys{AccountKey: "A-acme"})
	if !errors.Is(err, model.ErrConflict) {
		t.Fatalf("duplicate account: %v", err)
	}
	if err := st.CreateClient(ctx, model.Client{Slug: "Bad Slug"}, store.AccountKeys{}); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("bad slug: %v", err)
	}
	if _, err := st.Client(ctx, "nope"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("unknown client: %v", err)
	}
	all, err := st.Clients(ctx)
	if err != nil || len(all) != 2 || all[0].Slug != "acme" || all[1].Slug != "beta" {
		t.Fatalf("Clients = %v, %v", all, err)
	}

	keys, err := st.AccountKeys(ctx, "acme")
	if err != nil || keys.SigningSeed != "SS-acme" || keys.RelaySeed != "SU-acme" {
		t.Fatalf("AccountKeys = %+v, %v", keys, err)
	}
	if err := st.SetAccountJWT(ctx, "acme", "jwt-2"); err != nil {
		t.Fatal(err)
	}
	if keys, _ := st.AccountKeys(ctx, "acme"); keys.AccountJWT != "jwt-2" {
		t.Fatalf("account jwt not replaced: %q", keys.AccountJWT)
	}
	if err := st.SetAccountJWT(ctx, "nope", "x"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("SetAccountJWT unknown: %v", err)
	}

	c, err := st.SetDisabled(ctx, "acme", true, "incident 42", time.Now())
	if err != nil || !c.Disabled {
		t.Fatalf("disable: %+v %v", c, err)
	}
	if c, _ := st.Client(ctx, "acme"); !c.Disabled {
		t.Fatal("kill switch not persisted")
	}
	if c, err := st.SetDisabled(ctx, "acme", false, "", time.Now()); err != nil || c.Disabled {
		t.Fatalf("enable: %+v %v", c, err)
	}
	if _, err := st.SetDisabled(ctx, "nope", true, "", time.Now()); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("disable unknown: %v", err)
	}
}

func TestTechnicianClientACL(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	addClient(t, st, "globex")
	now := time.Now()
	enrollment, err := st.EnrollDevice(ctx, store.EnrollParams{Secret: addToken(t, st, "acme", nil), Device: newDevice("U-IDP", "m-idp"), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.GrantTechnicianClient(ctx, "tech_alice", "acme", now); err != nil {
		t.Fatal(err)
	}
	access := model.AccessRequest{ID: "acc_idp", Client: "acme", Device: enrollment.Device.ID, Technician: "tech_alice",
		Session: "idp_external_session", Purpose: "test", State: model.AccessRequested, RequestedAt: now,
		ExpiresAt: now.Add(time.Hour), PolicyVersion: 1}
	if err := st.CreateAccess(ctx, access); err != nil {
		t.Fatalf("access with external identity-provider session: %v", err)
	}
	if err := st.GrantTechnicianClient(ctx, "tech_alice", "acme", now); err != nil {
		t.Fatalf("idempotent grant: %v", err)
	}
	allowed, err := st.TechnicianCanAccess(ctx, "tech_alice", "acme")
	if err != nil || !allowed {
		t.Fatalf("allowed = %v, %v", allowed, err)
	}
	allowed, err = st.TechnicianCanAccess(ctx, "tech_alice", "globex")
	if err != nil || allowed {
		t.Fatalf("ungranted client allowed = %v, %v", allowed, err)
	}
	clients, err := st.ClientsForTechnician(ctx, "tech_alice")
	if err != nil || len(clients) != 1 || clients[0].Slug != "acme" {
		t.Fatalf("ClientsForTechnician = %+v, %v", clients, err)
	}
	if err := st.RevokeTechnicianClient(ctx, "tech_alice", "acme"); err != nil {
		t.Fatal(err)
	}
	if allowed, err = st.TechnicianCanAccess(ctx, "tech_alice", "acme"); err != nil || allowed {
		t.Fatalf("revoked allowed = %v, %v", allowed, err)
	}
}

func TestSetPolicyBumpsVersion(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	p := policy.DefaultClientPolicy()
	p.Version = 99
	p.MaxMatches = 7
	got, err := st.SetPolicy(ctx, "acme", p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || got.MaxMatches != 7 {
		t.Fatalf("SetPolicy returned version %d, max matches %d", got.Version, got.MaxMatches)
	}
	stored, err := st.Policy(ctx, "acme")
	if err != nil || stored.Version != 2 || stored.MaxMatches != 7 || len(stored.Allow["windows"]) == 0 {
		t.Fatalf("stored policy %+v, %v", stored, err)
	}
	if _, err := st.SetPolicy(ctx, "nope", p); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("SetPolicy unknown: %v", err)
	}
}

func TestTokens(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	addToken(t, st, "acme", func(tok *model.EnrollToken) { tok.ID, tok.Note, tok.MaxUses = "tok_a", "rollout", 5 })
	if err := st.CreateToken(ctx, model.EnrollToken{ID: "tok_x", Client: "nope", Hash: "h"}); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("token for unknown client: %v", err)
	}
	if err := st.CreateToken(ctx, model.EnrollToken{ID: "tok_y", Client: "acme"}); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("token without hash: %v", err)
	}
	toks, err := st.Tokens(ctx, "acme")
	if err != nil || len(toks) != 1 || toks[0].Note != "rollout" || toks[0].MaxUses != 5 || toks[0].Hash == "" {
		t.Fatalf("Tokens = %+v, %v", toks, err)
	}
	first := time.Now().Add(-time.Minute)
	tok, err := st.RevokeToken(ctx, "tok_a", first)
	if err != nil || tok.RevokedAt == nil {
		t.Fatalf("revoke: %+v %v", tok, err)
	}
	tok, err = st.RevokeToken(ctx, "tok_a", time.Now())
	if err != nil || !tok.RevokedAt.Equal(first.UTC().Truncate(time.Nanosecond)) {
		t.Fatalf("second revoke moved revoked_at: %v %v", tok.RevokedAt, err)
	}
	if _, err := st.RevokeToken(ctx, "tok_nope", time.Now()); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("revoke unknown: %v", err)
	}
}

func TestEnrollDevice(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	addClient(t, st, "beta")
	now := time.Now()
	secret := addToken(t, st, "acme", nil)

	enr, err := st.EnrollDevice(ctx, store.EnrollParams{Secret: secret, Org: "acme", Device: newDevice("UKEY1", "m-1"), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if enr.Device.Client != "acme" || enr.Token.Uses != 1 || enr.Device.EnrollTokenID != enr.Token.ID || len(enr.Replaced) != 0 {
		t.Fatalf("enrollment %+v", enr)
	}
	stored, err := st.Device(ctx, enr.Device.ID)
	if err != nil || stored.PublicKey != "UKEY1" || stored.OS != "windows" || stored.RevokedAt != nil {
		t.Fatalf("stored device %+v, %v", stored, err)
	}

	t.Run("same machine re-enrolls and replaces the old device", func(t *testing.T) {
		again, err := st.EnrollDevice(ctx, store.EnrollParams{Secret: secret, Device: newDevice("UKEY2", "m-1"), Now: now})
		if err != nil {
			t.Fatal(err)
		}
		if len(again.Replaced) != 1 || again.Replaced[0].ID != enr.Device.ID || again.Replaced[0].RevokedAt == nil {
			t.Fatalf("replaced %+v", again.Replaced)
		}
		if old, _ := st.Device(ctx, enr.Device.ID); old.RevokedAt == nil {
			t.Fatal("old device still live")
		}
		devs, _ := st.Devices(ctx, "acme")
		if len(devs) != 2 {
			t.Fatalf("want both devices listed, got %d", len(devs))
		}
	})

	t.Run("same machine id in another client is not replaced", func(t *testing.T) {
		betaSecret := addToken(t, st, "beta", nil)
		other, err := st.EnrollDevice(ctx, store.EnrollParams{Secret: betaSecret, Device: newDevice("UKEY3", "m-1"), Now: now})
		if err != nil {
			t.Fatal(err)
		}
		if len(other.Replaced) != 0 {
			t.Fatalf("replaced across clients: %+v", other.Replaced)
		}
	})

	t.Run("a key is never enrolled twice", func(t *testing.T) {
		_, err := st.EnrollDevice(ctx, store.EnrollParams{Secret: secret, Device: newDevice("UKEY1", "m-9"), Now: now})
		if !errors.Is(err, model.ErrConflict) {
			t.Fatalf("reused key: %v", err)
		}
	})

	t.Run("token and org failures consume nothing", func(t *testing.T) {
		expired := addToken(t, st, "acme", func(tok *model.EnrollToken) { tok.ExpiresAt = now.Add(-time.Minute) })
		revoked := addToken(t, st, "acme", func(tok *model.EnrollToken) { tok.ID = "tok_revoked" })
		if _, err := st.RevokeToken(ctx, "tok_revoked", now); err != nil {
			t.Fatal(err)
		}
		used := addToken(t, st, "acme", func(tok *model.EnrollToken) { tok.ID, tok.MaxUses = "tok_once", 1 })
		if _, err := st.EnrollDevice(ctx, store.EnrollParams{Secret: used, Device: newDevice("UKEY4", ""), Now: now}); err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			secret, org string
			want        error
		}{
			{"khe_acme_unknown", "", model.ErrNotFound},
			{expired, "", model.ErrExpired},
			{revoked, "", model.ErrRevoked},
			{used, "", model.ErrExhausted},
			{secret, "beta", store.ErrOrgMismatch},
		}
		for _, c := range cases {
			_, err := st.EnrollDevice(ctx, store.EnrollParams{Secret: c.secret, Org: c.org, Device: newDevice("UKEY5", "m-5"), Now: now})
			if !errors.Is(err, c.want) {
				t.Errorf("want %v, got %v", c.want, err)
			}
			if err != nil && strings.Contains(err.Error(), c.secret) {
				t.Errorf("error leaks the token secret: %v", err)
			}
		}
		if tok, _ := st.Token(ctx, enr.Token.ID); tok.Uses != 2 {
			t.Fatalf("org mismatch consumed a use: uses=%d", tok.Uses)
		}
	})
}

// TestEnrollDeviceHonoursMaxUnderConcurrency checks that consuming a token
// is atomic: concurrent enrollments never exceed MaxUses.
func TestEnrollDeviceHonoursMaxUnderConcurrency(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	secret := addToken(t, st, "acme", func(tok *model.EnrollToken) { tok.ID, tok.MaxUses = "tok_3", 3 })
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		ok, spent int
	)
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := st.EnrollDevice(ctx, store.EnrollParams{
				Secret: secret, Device: newDevice("UKEY-"+string(rune('a'+i)), ""), Now: time.Now(),
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, model.ErrExhausted):
				spent++
			default:
				t.Errorf("enroll: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 3 || spent != 9 {
		t.Fatalf("%d enrolled, %d refused; want 3 and 9", ok, spent)
	}
	if tok, _ := st.Token(ctx, "tok_3"); tok.Uses != 3 {
		t.Fatalf("uses = %d", tok.Uses)
	}
}

func TestSessions(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	bearer := model.NewSecret(model.SecretSession)
	now := time.Now()
	ses := model.Session{
		ID: "ses_1", Client: "acme", Tech: "zach", Hash: model.HashSecret(bearer),
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := st.CreateSession(ctx, ses); err != nil {
		t.Fatal(err)
	}
	got, err := st.SessionByToken(ctx, bearer)
	if err != nil || got.ID != "ses_1" || got.Tech != "zach" || got.Valid(now) != nil {
		t.Fatalf("SessionByToken = %+v, %v", got, err)
	}
	unknown := model.NewSecret(model.SecretSession)
	_, err = st.SessionByToken(ctx, unknown)
	if !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("unknown bearer: %v", err)
	}
	if strings.Contains(err.Error(), unknown) {
		t.Fatal("error leaks the bearer")
	}
	if list, err := st.Sessions(ctx, "acme"); err != nil || len(list) != 1 {
		t.Fatalf("Sessions = %v, %v", list, err)
	}
	revoked, err := st.RevokeSession(ctx, "ses_1", now)
	if err != nil || !errors.Is(revoked.Valid(now), model.ErrRevoked) {
		t.Fatalf("revoke: %+v %v", revoked, err)
	}
	if err := st.CreateSession(ctx, model.Session{ID: "ses_2", Client: "nope", Tech: "x", Hash: "h"}); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("session for unknown client: %v", err)
	}
}

func TestDeviceEvents(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	addClient(t, st, "beta")
	enr, err := st.EnrollDevice(ctx, store.EnrollParams{Secret: addToken(t, st, "acme", nil), Device: newDevice("UKEY1", "m-1"), Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	id := enr.Device.ID
	seen := time.Now().Add(time.Minute)
	if err := st.TouchDevice(ctx, "acme", id, seen); err != nil {
		t.Fatal(err)
	}
	if d, _ := st.Device(ctx, id); d.LastSeen == nil || !d.LastSeen.Equal(seen.UTC()) {
		t.Fatalf("last seen %v", d.LastSeen)
	}
	if err := st.TouchDevice(ctx, "beta", id, seen); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("another client touched acme's device: %v", err)
	}
	if err := st.TouchDevice(ctx, "acme", "dev_nope", seen); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("unknown device: %v", err)
	}

	info := store.DeviceInfo{Hostname: "SRV-02", OSVersion: "10.0.26200", AgentVersion: "v0.2.0"}
	if err := st.UpdateDeviceInfo(ctx, "acme", id, info, seen); err != nil {
		t.Fatal(err)
	}
	d, _ := st.Device(ctx, id)
	if d.Hostname != "SRV-02" || d.OSVersion != "10.0.26200" || d.AgentVersion != "v0.2.0" || d.Arch != "amd64" || d.OS != "windows" {
		t.Fatalf("device after hello: %+v", d)
	}
	if err := st.UpdateDeviceInfo(ctx, "beta", id, info, seen); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("another client updated acme's device: %v", err)
	}

	if _, err := st.RevokeDevice(ctx, id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchDevice(ctx, "acme", id, seen); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("revoked device touched: %v", err)
	}
	if _, err := st.RevokeDevice(ctx, "dev_nope", time.Now()); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("revoke unknown: %v", err)
	}
}

func TestAdminTokenAndKV(t *testing.T) {
	st, _ := openStore(t)
	if _, err := st.AdminTokenHash(ctx); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("unset admin token: %v", err)
	}
	for _, h := range []string{"h1", "h2"} {
		if err := st.SetAdminTokenHash(ctx, h, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if h, err := st.AdminTokenHash(ctx); err != nil || h != "h2" {
		t.Fatalf("admin token hash %q, %v", h, err)
	}
	if _, err := st.KV(ctx, "k"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("unset kv: %v", err)
	}
	for _, v := range []string{"v1", "v2"} {
		if err := st.SetKV(ctx, "k", v); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := st.KV(ctx, "k"); err != nil || v != "v2" {
		t.Fatalf("kv %q, %v", v, err)
	}
}

// TestSecretsNeverStored is part of invariant #7: after tokens, sessions and
// the admin token pass through the store, no secret is in the database files.
func TestSecretsNeverStored(t *testing.T) {
	st, path := openStore(t)
	addClient(t, st, "acme")
	enroll := addToken(t, st, "acme", nil)
	if _, err := st.EnrollDevice(ctx, store.EnrollParams{Secret: enroll, Device: newDevice("UKEY1", "m-1"), Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	bearer := model.NewSecret(model.SecretSession)
	now := time.Now()
	if err := st.CreateSession(ctx, model.Session{ID: "ses_1", Client: "acme", Tech: "t", Hash: model.HashSecret(bearer), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SessionByToken(ctx, bearer); err != nil {
		t.Fatal(err)
	}
	admin := model.NewSecret(model.SecretAdmin)
	if err := st.SetAdminTokenHash(ctx, model.HashSecret(admin), now); err != nil {
		t.Fatal(err)
	}
	st.Close()
	for _, f := range []string{path, path + "-wal"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, secret := range []string{enroll, bearer, admin} {
			if strings.Contains(string(b), secret) {
				t.Fatalf("%s holds a plaintext secret", filepath.Base(f))
			}
		}
	}
}
