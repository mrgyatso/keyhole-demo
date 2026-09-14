package gateway

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/store"
)

func TestCheckApprovalBindsTheRowAndTheTechniciansPasskey(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "keyhole.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Now().UTC()
	for tech, cred := range map[string]string{"alice": "cred-alice", "bob": "cred-bob"} {
		link := model.PasskeyLink{ID: model.NewID(model.PrefixPasskeyLink), Technician: tech,
			Hash: model.HashSecret(cred + "-secret"), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := st.CreatePasskeyLink(ctx, link); err != nil {
			t.Fatal(err)
		}
		if err := st.UsePasskeyLink(ctx, link.ID, model.Passkey{CredentialID: cred, Technician: tech,
			PublicKey: []byte{1}, Algorithm: -7}, now); err != nil {
			t.Fatal(err)
		}
	}
	g := &Gateway{approvals: st}
	want := proto.TechnicianApproval{Kind: proto.ApprovalUnlock, ID: "unl_1", Technician: "alice", Client: "acme",
		Nonce: "n", ExpiresAt: now.Add(time.Hour)}
	signed := want
	signed.Credential, signed.ApprovedAt = "cred-alice", now
	if err := g.checkApproval(ctx, "alice", want, signed); err != nil {
		t.Fatalf("a valid approval was refused: %v", err)
	}
	for name, c := range map[string]struct {
		change func(*proto.TechnicianApproval)
		want   error
	}{
		"another nonce":             {func(a *proto.TechnicianApproval) { a.Nonce = "m" }, model.ErrInvalid},
		"another expiry":            {func(a *proto.TechnicianApproval) { a.ExpiresAt = a.ExpiresAt.Add(time.Second) }, model.ErrInvalid},
		"another kind":              {func(a *proto.TechnicianApproval) { a.Kind = proto.ApprovalChange }, model.ErrInvalid},
		"unsigned":                  {func(a *proto.TechnicianApproval) { a.Credential, a.ApprovedAt = "", time.Time{} }, model.ErrInvalid},
		"another technician's key":  {func(a *proto.TechnicianApproval) { a.Credential = "cred-bob" }, model.ErrInvalid},
		"a passkey nobody enrolled": {func(a *proto.TechnicianApproval) { a.Credential = "cred-nobody" }, model.ErrInvalid},
	} {
		a := signed
		c.change(&a)
		if err := g.checkApproval(ctx, "alice", want, a); !errors.Is(err, c.want) {
			t.Errorf("%s: checkApproval = %v, want %v", name, err, c.want)
		}
	}
	if err := st.RevokePasskey(ctx, "cred-alice", now); err != nil {
		t.Fatal(err)
	}
	if err := g.checkApproval(ctx, "alice", want, signed); !errors.Is(err, model.ErrRevoked) {
		t.Fatalf("a revoked passkey still approves: %v", err)
	}
}
