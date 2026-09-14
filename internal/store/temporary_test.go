package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/store"
)

// ephemeral makes addToken mint a valid temporary-install token.
func ephemeral(ttl time.Duration) func(*model.EnrollToken) {
	return func(t *model.EnrollToken) {
		t.Ephemeral, t.MaxUses, t.DeviceTTL = true, 1, ttl
		t.Technician, t.Note = "alice@msp", "ticket 4471"
	}
}

func TestEphemeralTokenMustBeSingleUseAndBounded(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	base := model.EnrollToken{
		Client: "acme", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour),
		Ephemeral: true, MaxUses: 1, DeviceTTL: time.Hour,
	}
	for name, mutate := range map[string]func(*model.EnrollToken){
		"unlimited uses": func(tok *model.EnrollToken) { tok.MaxUses = 0 },
		"two uses":       func(tok *model.EnrollToken) { tok.MaxUses = 2 },
		"no device ttl":  func(tok *model.EnrollToken) { tok.DeviceTTL = 0 },
		"device ttl too long": func(tok *model.EnrollToken) {
			tok.DeviceTTL = model.MaxDeviceTTL + time.Minute
		},
	} {
		t.Run(name, func(t *testing.T) {
			tok := base
			tok.ID, tok.Hash = model.NewID(model.PrefixToken), model.HashSecret(model.NewEnrollSecret("acme"))
			mutate(&tok)
			if err := st.CreateToken(ctx, tok); !errors.Is(err, model.ErrInvalid) {
				t.Fatalf("stored an unsound ephemeral token: %v", err)
			}
		})
	}
}

func TestEphemeralTokenEnrollsExactlyOneExpiringDevice(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	secret := addToken(t, st, "acme", ephemeral(30*time.Minute))
	now := time.Now().UTC().Truncate(time.Second)

	enr, err := st.EnrollDevice(ctx, store.EnrollParams{Secret: secret, Device: newDevice("U-one", "m-1"), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if !enr.Device.Ephemeral || enr.Device.ExpiresAt == nil {
		t.Fatalf("device is not temporary: %+v", enr.Device)
	}
	if want := now.Add(30 * time.Minute); !enr.Device.ExpiresAt.Equal(want) {
		t.Fatalf("expires at %s, want %s", enr.Device.ExpiresAt, want)
	}
	// The deadline survives a round trip through SQLite.
	stored, err := st.Device(ctx, enr.Device.ID)
	if err != nil || !stored.Ephemeral || stored.ExpiresAt == nil || !stored.ExpiresAt.Equal(*enr.Device.ExpiresAt) {
		t.Fatalf("stored device %+v (%v)", stored, err)
	}
	if stored.Expired(now) || !stored.Expired(now.Add(31*time.Minute)) {
		t.Fatal("Expired does not follow the deadline")
	}

	// One use, and no second machine can ride the same token.
	_, err = st.EnrollDevice(ctx, store.EnrollParams{Secret: secret, Device: newDevice("U-two", "m-2"), Now: now})
	if !errors.Is(err, model.ErrExhausted) {
		t.Fatalf("second enrollment with a one-use token: %v", err)
	}
}

func TestManagedEnrollmentStaysUnexpiring(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	secret := addToken(t, st, "acme", nil)
	enr, err := st.EnrollDevice(ctx, store.EnrollParams{Secret: secret, Device: newDevice("U-managed", "m-9"), Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if enr.Device.Ephemeral || enr.Device.ExpiresAt != nil {
		t.Fatalf("managed device carries a deadline: %+v", enr.Device)
	}
	if enr.Device.Expired(time.Now().Add(10 * 365 * 24 * time.Hour)) {
		t.Fatal("a managed device expired")
	}
}

func TestExpireEphemeralDevicesRevokesOnlyWhatIsDue(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	addClient(t, st, "beta")
	now := time.Now().UTC()

	due, err := st.EnrollDevice(ctx, store.EnrollParams{
		Secret: addToken(t, st, "acme", ephemeral(time.Minute)),
		Device: newDevice("U-due", "m-due"), Now: now.Add(-2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	live, err := st.EnrollDevice(ctx, store.EnrollParams{
		Secret: addToken(t, st, "beta", ephemeral(time.Hour)),
		Device: newDevice("U-live", "m-live"), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	managed, err := st.EnrollDevice(ctx, store.EnrollParams{
		Secret: addToken(t, st, "acme", nil),
		Device: newDevice("U-managed", "m-managed"), Now: now.Add(-72 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	expired, err := st.ExpireEphemeralDevices(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].ID != due.Device.ID || expired[0].RevokedAt == nil {
		t.Fatalf("expired %+v", expired)
	}
	if expired[0].Client != "acme" {
		t.Fatalf("expired device reported client %q", expired[0].Client)
	}
	for _, id := range []string{live.Device.ID, managed.Device.ID} {
		d, err := st.Device(ctx, id)
		if err != nil || d.RevokedAt != nil {
			t.Fatalf("device %s was revoked early: %+v (%v)", id, d, err)
		}
	}

	// Running again is a no-op: a revoked device is not expired twice, so the
	// relay does not re-audit or re-push on every reconcile.
	again, err := st.ExpireEphemeralDevices(ctx, now)
	if err != nil || len(again) != 0 {
		t.Fatalf("second sweep returned %d devices (%v)", len(again), err)
	}
}

func TestSelfRevokeCannotReachAnotherClient(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	addClient(t, st, "beta")
	acme, err := st.EnrollDevice(ctx, store.EnrollParams{
		Secret: addToken(t, st, "acme", ephemeral(time.Hour)),
		Device: newDevice("U-acme", "m-acme"), Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := st.RevokeDeviceOwned(ctx, "beta", acme.Device.ID, time.Now()); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("another client's revocation landed: %v", err)
	}
	if d, err := st.Device(ctx, acme.Device.ID); err != nil || d.RevokedAt != nil {
		t.Fatalf("device revoked by the wrong client: %+v (%v)", d, err)
	}

	at := time.Now().UTC()
	d, err := st.RevokeDeviceOwned(ctx, "acme", acme.Device.ID, at)
	if err != nil || d.RevokedAt == nil {
		t.Fatalf("own revocation failed: %+v (%v)", d, err)
	}
	// Revoking again finds nothing live, so a repeated event is not a second
	// revocation with a later time.
	if _, err := st.RevokeDeviceOwned(ctx, "acme", acme.Device.ID, time.Now().Add(time.Hour)); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("second revocation accepted: %v", err)
	}
	if again, err := st.Device(ctx, acme.Device.ID); err != nil || !again.RevokedAt.Equal(*d.RevokedAt) {
		t.Fatalf("revocation time moved: %+v (%v)", again, err)
	}
}

func TestTokenBySecretFindsEphemeralTerms(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	secret := addToken(t, st, "acme", ephemeral(45*time.Minute))

	tok, err := st.TokenBySecret(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !tok.Ephemeral || tok.DeviceTTL != 45*time.Minute || tok.Technician != "alice@msp" || tok.Note != "ticket 4471" {
		t.Fatalf("token %+v", tok)
	}
	if _, err := st.TokenBySecret(ctx, model.NewEnrollSecret("acme")); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("unknown secret resolved: %v", err)
	}
}

// A temporary install never displaces a managed enrollment. The machine ID is
// self-reported, so otherwise anyone holding an ephemeral token could revoke
// any managed device of the client whose machine ID they name.
func TestEphemeralEnrollmentLeavesManagedDevicesAlone(t *testing.T) {
	st, _ := openStore(t)
	addClient(t, st, "acme")
	now := time.Now()
	managed, err := st.EnrollDevice(ctx, store.EnrollParams{
		Secret: addToken(t, st, "acme", nil), Device: newDevice("U-managed", "m-shared"), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	temp, err := st.EnrollDevice(ctx, store.EnrollParams{
		Secret: addToken(t, st, "acme", ephemeral(time.Hour)), Device: newDevice("U-temp", "m-shared"), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(temp.Replaced) != 0 {
		t.Fatalf("a temporary enrollment replaced %+v", temp.Replaced)
	}
	if d, err := st.Device(ctx, managed.Device.ID); err != nil || d.RevokedAt != nil {
		t.Fatalf("a temporary enrollment revoked the managed device: %+v (%v)", d, err)
	}

	// A second temporary install on that machine still replaces the first.
	again, err := st.EnrollDevice(ctx, store.EnrollParams{
		Secret: addToken(t, st, "acme", ephemeral(time.Hour)), Device: newDevice("U-temp2", "m-shared"), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Replaced) != 1 || again.Replaced[0].ID != temp.Device.ID {
		t.Fatalf("a second temporary enrollment replaced %+v", again.Replaced)
	}

	// And a managed enrollment replaces everything live on the machine, as before.
	reinstall, err := st.EnrollDevice(ctx, store.EnrollParams{
		Secret: addToken(t, st, "acme", nil), Device: newDevice("U-managed2", "m-shared"), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(reinstall.Replaced) != 2 {
		t.Fatalf("a managed re-enrollment replaced %+v", reinstall.Replaced)
	}
}
