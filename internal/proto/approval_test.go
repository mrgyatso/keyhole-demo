package proto

import (
	"strings"
	"testing"
	"time"
)

func sampleApproval() TechnicianApproval {
	return TechnicianApproval{Kind: ApprovalChange, ID: "chg_1", Technician: "tech", Client: "acme", Purpose: "p",
		Device: "dev_1", AccessID: "acc_1", GrantID: "grt", Op: OpApplyFileChange, PlanID: "plan_1", PlanDigest: "d",
		RollbackID: "rb_1", Nonce: "n", ExpiresAt: time.Date(2026, 9, 11, 22, 0, 0, 5, time.UTC)}
}

func TestChallengeBindsEverySignedField(t *testing.T) {
	base := sampleApproval()
	if got := base.Challenge(); len(got) != 32 {
		t.Fatalf("challenge is %d bytes, want 32", len(got))
	}
	for name, change := range map[string]func(*TechnicianApproval){
		"kind":        func(a *TechnicianApproval) { a.Kind = ApprovalUnlock },
		"id":          func(a *TechnicianApproval) { a.ID = "chg_2" },
		"technician":  func(a *TechnicianApproval) { a.Technician = "other" },
		"client":      func(a *TechnicianApproval) { a.Client = "globex" },
		"purpose":     func(a *TechnicianApproval) { a.Purpose = "q" },
		"device":      func(a *TechnicianApproval) { a.Device = "dev_2" },
		"access_id":   func(a *TechnicianApproval) { a.AccessID = "acc_2" },
		"grant_id":    func(a *TechnicianApproval) { a.GrantID = "grt2" },
		"op":          func(a *TechnicianApproval) { a.Op = OpRollbackFileChange },
		"plan_id":     func(a *TechnicianApproval) { a.PlanID = "plan_2" },
		"plan_digest": func(a *TechnicianApproval) { a.PlanDigest = "e" },
		"rollback_id": func(a *TechnicianApproval) { a.RollbackID = "rb_2" },
		"nonce":       func(a *TechnicianApproval) { a.Nonce = "m" },
		"expires_at":  func(a *TechnicianApproval) { a.ExpiresAt = a.ExpiresAt.Add(time.Nanosecond) },
	} {
		a := base
		change(&a)
		if a.SameSigned(base) {
			t.Errorf("changing %s leaves the challenge unchanged", name)
		}
	}
}

func TestChallengeIgnoresTheSignatureAndTheTimeZone(t *testing.T) {
	base := sampleApproval()
	signed := base
	signed.Credential, signed.ApprovedAt = "cred", time.Now()
	signed.Assertion = &PasskeyAssertion{CredentialID: "cred", Signature: []byte{1}}
	if !signed.SameSigned(base) {
		t.Error("the signature fields changed the challenge")
	}
	zoned := base
	zoned.ExpiresAt = base.ExpiresAt.In(time.FixedZone("UTC+1", 3600))
	if !zoned.SameSigned(base) {
		t.Error("the same instant in another zone changed the challenge")
	}
}

func TestChallengeLengthPrefixesKeepFieldsApart(t *testing.T) {
	// Without length prefixes a purpose that spells out the next field could
	// pass for an approval with a different nonce.
	a := TechnicianApproval{Purpose: "x\ndevice=0:\naccess_id=0:", Nonce: "n"}
	b := TechnicianApproval{Purpose: "x", Nonce: "n"}
	if a.SameSigned(b) {
		t.Fatal("two different approvals share a challenge")
	}
}

func TestSignedAndApproverLabel(t *testing.T) {
	a := sampleApproval()
	if a.Signed() {
		t.Fatal("an approval without a credential reports itself signed")
	}
	a.Credential, a.ApprovedAt = "AbCdEfGhIjKlMnOp", time.Now()
	if !a.Signed() {
		t.Fatal("a signed approval reports itself unsigned")
	}
	if got := a.ApproverLabel(); got != "technician tech (passkey AbCdEfGhIjKl)" {
		t.Fatalf("label = %q", got)
	}
	if strings.Contains(a.ApproverLabel(), "MnOp") {
		t.Fatal("the label carries the whole credential ID")
	}
}
