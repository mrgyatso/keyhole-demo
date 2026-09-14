package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// revokeTimeout bounds the whole self-revocation, connection included. A
// temporary install must not hang on teardown because the relay is
// unreachable: the relay revokes it on its own schedule anyway.
const revokeTimeout = 20 * time.Second

// SelfRevoke gives up this device's own credential at the relay by publishing
// proto.Revoke on the device's event subject. The device credential is the
// authentication: NATS lets a device publish only its own subjects, so the
// relay trusts the subject and treats the payload as a cross-check.
//
// It is best effort by design. The endpoint saying "I am done" ends the
// session sooner; the endpoint failing to say it does not extend the session,
// because the relay expires the device by itself.
func SelfRevoke(ctx context.Context, e *Enrollment, credsFile, reason string) error {
	switch {
	case e == nil || e.DeviceID == "" || len(e.NATSURLs) == 0:
		return fmt.Errorf("agent: self-revoke: %w", ErrNotEnrolled)
	case credsFile == "":
		return fmt.Errorf("agent: self-revoke: no credentials file")
	}
	ctx, cancel := context.WithTimeout(ctx, revokeTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()

	nc, err := nats.Connect(strings.Join(e.NATSURLs, ","),
		nats.UserCredentials(credsFile),
		nats.Name("keyhole-agent revoke "+e.DeviceID),
		// One attempt inside the deadline: this runs during teardown, and the
		// relay is the authority on expiry regardless of what happens here.
		nats.MaxReconnects(0),
		nats.RetryOnFailedConnect(false),
		nats.Timeout(time.Until(deadline)),
	)
	if err != nil {
		return fmt.Errorf("agent: self-revoke: connect: %w", err)
	}
	defer nc.Close()

	b, err := json.Marshal(proto.Revoke{DeviceID: e.DeviceID, Reason: reason, Time: time.Now().UTC()})
	if err != nil {
		return err
	}
	if err := nc.Publish(proto.EventSubject(e.DeviceID, proto.EvtRevoke), b); err != nil {
		return fmt.Errorf("agent: self-revoke: publish: %w", err)
	}
	// Flush, not fire-and-forget: the connection closes moments later, and an
	// unflushed revocation would be lost.
	if err := nc.FlushWithContext(ctx); err != nil {
		return fmt.Errorf("agent: self-revoke: flush: %w", err)
	}
	return nil
}
