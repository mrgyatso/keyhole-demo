package store_test

import (
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
)

// A request that waited for a technician unlock is forwarded with whatever
// of its lifetime is left, and the gateway shortens its idle timeout to fit.
// The endpoint mints the grant with the forwarded value and the relay compares
// it with the stored one, so the store must keep what the gateway wrote.
func TestUpdateAccessKeepsAShortenedIdleTimeout(t *testing.T) {
	st, a, now := approvalFixture(t)
	if _, err := st.UpdateAccessTx(ctx, a.ID, func(r *model.AccessRequest) error {
		r.State, r.IdleTimeout, r.ExpiresAt = model.AccessAwaiting, 3*time.Minute, now.Add(3*time.Minute)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := st.Access(ctx, a.ID)
	if err != nil || got.IdleTimeout != 3*time.Minute || got.State != model.AccessAwaiting {
		t.Fatalf("Access = %+v, %v", got, err)
	}
	got.IdleTimeout = time.Minute
	if err := st.UpdateAccess(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.Access(ctx, a.ID); again.IdleTimeout != time.Minute {
		t.Fatalf("UpdateAccess dropped the idle timeout: %v", again.IdleTimeout)
	}
}
