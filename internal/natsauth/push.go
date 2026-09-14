package natsauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nats-io/nats.go"
)

// ClaimsUpdateSubject is where the full resolver accepts account JWTs from
// the SYS account.
const ClaimsUpdateSubject = "$SYS.REQ.CLAIMS.UPDATE"

// DefaultPushTimeout bounds Push when ctx has no deadline.
const DefaultPushTimeout = 5 * time.Second

// claimsUpdateReply mirrors nats-server's ServerAPIClaimUpdateResponse.
type claimsUpdateReply struct {
	Data *struct {
		Account string `json:"account"`
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"data"`
	Error *struct {
		Account     string `json:"account"`
		Code        int    `json:"code"`
		Description string `json:"description"`
	} `json:"error"`
}

// Push hands an account JWT to nats-server's full resolver over a SYS-account
// connection, and returns an error unless the server confirms it stored it.
// Connected users of the account pick up the new claims at once, so a push
// that adds a revocation disconnects the revoked users.
func Push(ctx context.Context, sys *nats.Conn, accountJWT string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultPushTimeout)
		defer cancel()
	}
	msg, err := sys.RequestWithContext(ctx, ClaimsUpdateSubject, []byte(accountJWT))
	if err != nil {
		return fmt.Errorf("natsauth: push account jwt: %w", err)
	}
	var reply claimsUpdateReply
	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return fmt.Errorf("natsauth: push account jwt: bad reply: %w", err)
	}
	switch {
	case reply.Error != nil:
		return fmt.Errorf("natsauth: push account jwt: %s (code %d)", reply.Error.Description, reply.Error.Code)
	case reply.Data == nil || reply.Data.Code != http.StatusOK:
		return errors.New("natsauth: push account jwt: server did not confirm the update")
	}
	return nil
}
