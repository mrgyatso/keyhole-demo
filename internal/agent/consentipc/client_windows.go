//go:build windows

package consentipc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
)

// DialTimeout bounds one attempt to reach the service.
const DialTimeout = 10 * time.Second

// Client is the consent application's connection to the service. It sends
// what the endpoint user chose and receives requests, state changes and
// activity. It carries no authority of its own: the service decides what
// this process is allowed to ask for from the pipe connection itself.
type Client struct {
	conn net.Conn
	r    *bufio.Reader
	mu   sync.Mutex
}

// Dial connects to the service's consent pipe.
func Dial(ctx context.Context) (*Client, error) { return DialPipe(ctx, PipeName) }

// DialPipe connects to the consent pipe called name. Only tests use a pipe
// other than PipeName.
func DialPipe(ctx context.Context, name string) (*Client, error) {
	dctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	conn, err := winio.DialPipeContext(dctx, name)
	if err != nil {
		return nil, fmt.Errorf("consentipc: connect to the Keyhole service: %w", err)
	}
	c := &Client{conn: conn, r: NewReader(conn)}
	if err := c.Send(Envelope{Type: TypeHello, Hello: &Hello{Version: ProtocolVersion}}); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Send writes one message to the service.
func (c *Client) Send(e Envelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return WriteEnvelope(c.conn, e)
}

// Receive reads the next message. It returns io.EOF when the service closes
// the connection, which the window treats as "the service is gone".
func (c *Client) Receive() (Envelope, error) {
	e, err := ReadEnvelope(c.r)
	if errors.Is(err, net.ErrClosed) {
		err = io.EOF
	}
	return e, err
}

// Close disconnects. The service treats it as the window having gone: live
// grants pause until a window is back.
func (c *Client) Close() error { return c.conn.Close() }

// Decide answers one request. Select lists the indexes of the request's
// paths the user left ticked; nil means all of them.
func (c *Client) Decide(accessID, decision string, sel []int, reason string) error {
	return c.Send(Envelope{Type: TypeDecide, Decide: &Decision{AccessID: accessID, Decision: decision, Select: sel, Reason: reason}})
}

// Control pauses, resumes or ends a live grant.
func (c *Client) Control(accessID, action string) error {
	return c.Send(Envelope{Type: TypeControl, Control: &Control{AccessID: accessID, Action: action}})
}

// DecidePlan answers a staged file-change review. The service verifies the
// pipe peer's elevation and matches the digest to an outstanding review.
func (c *Client) DecidePlan(accessID, digest, decision string) error {
	return c.Send(Envelope{Type: TypePlanDecide, PlanDecide: &PlanDecision{AccessID: accessID, Digest: digest, Decision: decision}})
}
