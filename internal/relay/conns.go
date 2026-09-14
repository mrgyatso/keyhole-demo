package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/natsauth"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/store"
)

// maxEventBytes caps the device events the relay will parse.
const maxEventBytes = 64 << 10

var _ model.Conns = (*ConnManager)(nil)

// ConnManager keeps one NATS connection per client, authenticated as the
// relay user of that client's account, and reconnecting forever. It
// implements model.Conns. Each connection also listens to its devices'
// hello and heartbeat events and records them in the store.
type ConnManager struct {
	url   string
	st    *store.Store
	log   *slog.Logger
	opts  []nats.Option
	audit audit.Store // endpoint consent transitions; nil records them unaudited

	// onSelfRevoke is called after an endpoint revoked its own device
	// credential (Slice 4), so the Server can audit it and push the
	// revocation into the account JWT. Set once, before Connect.
	onSelfRevoke func(model.Device, string)

	mu     sync.Mutex
	conns  map[string]*nats.Conn
	closed bool
}

// OnSelfRevoke registers the callback for endpoint self-revocation events.
func (m *ConnManager) OnSelfRevoke(fn func(model.Device, string)) { m.onSelfRevoke = fn }

// WithAudit records endpoint-initiated consent transitions in the client's
// audit chain. The relay wires it at startup; without it the transitions are
// still durable, which is what the store tests need.
func (m *ConnManager) WithAudit(a audit.Store) *ConnManager {
	m.audit = a
	return m
}

// NewConnManager returns a manager that dials url (e.g.
// nats://127.0.0.1:4222). opts are added to every connection it makes.
func NewConnManager(url string, st *store.Store, log *slog.Logger, opts ...nats.Option) *ConnManager {
	if log == nil {
		log = slog.Default()
	}
	return &ConnManager{url: url, st: st, log: log, opts: opts, conns: map[string]*nats.Conn{}}
}

// Conn returns the connection inside client's account, or an error wrapping
// model.ErrNotFound. The connection may be reconnecting; requests on it fail
// until it is back.
func (m *ConnManager) Conn(client string) (*nats.Conn, error) {
	m.mu.Lock()
	nc := m.conns[client]
	m.mu.Unlock()
	if nc == nil {
		return nil, fmt.Errorf("relay: no nats connection for client %q: %w", client, model.ErrNotFound)
	}
	return nc, nil
}

func (m *ConnManager) has(client string) bool {
	_, err := m.Conn(client)
	return err == nil
}

// Connect opens client's connection with the relay user's credentials and
// subscribes to its devices' events. If NATS is unreachable the connection
// keeps retrying in the background. A client that already has a connection
// keeps it.
func (m *ConnManager) Connect(client string, creds natsauth.UserCreds) error {
	m.mu.Lock()
	closed, exists := m.closed, m.conns[client] != nil
	m.mu.Unlock()
	if closed {
		return errors.New("relay: connection manager is closed")
	}
	if exists {
		return nil
	}
	nc, err := m.dial("client/"+client, creds, nats.ClosedHandler(func(nc *nats.Conn) { m.forget(client, nc) }))
	if err != nil {
		return err
	}
	if _, err := nc.Subscribe(proto.AllEventsWildcard, func(msg *nats.Msg) { m.handleEvent(client, msg) }); err != nil {
		nc.Close()
		return fmt.Errorf("relay: subscribe to %s events: %w", client, err)
	}
	m.mu.Lock()
	if m.closed || m.conns[client] != nil {
		m.mu.Unlock()
		nc.Close()
		return nil
	}
	m.conns[client] = nc
	m.mu.Unlock()
	return nil
}

// Close closes every client connection.
func (m *ConnManager) Close() {
	m.mu.Lock()
	m.closed = true
	conns := m.conns
	m.conns = map[string]*nats.Conn{}
	m.mu.Unlock()
	for _, nc := range conns {
		nc.Close()
	}
}

// forget drops a connection that closed for good, so the next reconcile
// dials a fresh one.
func (m *ConnManager) forget(client string, nc *nats.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conns[client] == nc {
		delete(m.conns, client)
		if !m.closed {
			m.log.Warn("nats connection closed", "client", client, "err", nc.LastError())
		}
	}
}

func (m *ConnManager) dial(name string, creds natsauth.UserCreds, extra ...nats.Option) (*nats.Conn, error) {
	opts := []nats.Option{
		creds.Option(),
		nats.Name("keyhole-relay/" + name),
		nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(true),
		nats.ReconnectWait(2 * time.Second),
		nats.IgnoreAuthErrorAbort(), // an account the resolver lost comes back on the next push
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				m.log.Warn("nats disconnected", "conn", name, "err", err)
			}
		}),
		nats.ReconnectHandler(func(*nats.Conn) { m.log.Info("nats reconnected", "conn", name) }),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			m.log.Warn("nats error", "conn", name, "err", err)
		}),
	}
	opts = append(append(opts, m.opts...), extra...)
	nc, err := nats.Connect(m.url, opts...)
	if err != nil {
		return nil, fmt.Errorf("relay: nats connect %s: %w", name, err)
	}
	return nc, nil
}

// handleEvent records a device event. The subject names the device, and
// NATS permissions let a device publish only its own subjects, so the
// subject is authoritative; the store ignores devices that are unknown,
// revoked or another client's.
func (m *ConnManager) handleEvent(client string, msg *nats.Msg) {
	tok := strings.Split(msg.Subject, ".")
	if len(tok) != 5 || tok[3] != "evt" {
		return
	}
	id, evt := tok[2], tok[4]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now()
	var err error
	switch evt {
	case proto.EvtConsent:
		m.handleConsent(client, id, msg.Data)
		return
	case proto.EvtHeartbeat:
		err = m.st.TouchDevice(ctx, client, id, now)
	case proto.EvtHello:
		var h proto.Hello
		if len(msg.Data) > maxEventBytes {
			m.log.Warn("oversized hello ignored", "client", client, "device", id, "bytes", len(msg.Data))
			return
		}
		if err := json.Unmarshal(msg.Data, &h); err != nil {
			m.log.Warn("malformed hello ignored", "client", client, "device", id, "err", err)
			return
		}
		err = m.st.UpdateDeviceInfo(ctx, client, id, store.DeviceInfo{
			Hostname:     clip(h.Hostname),
			OSVersion:    clip(h.OSVersion),
			Arch:         clip(h.Arch),
			AgentVersion: clip(h.AgentVersion),
		}, now)
		if err == nil {
			m.log.Info("device hello", "client", client, "device", id, "hostname", clip(h.Hostname), "agent_version", clip(h.AgentVersion))
		}
	case proto.EvtRevoke:
		var rev proto.Revoke
		if len(msg.Data) > maxEventBytes || json.Unmarshal(msg.Data, &rev) != nil {
			m.log.Warn("malformed revoke ignored", "client", client, "device", id)
			return
		}
		err = m.selfRevoke(ctx, client, id, rev)
	default:
		return
	}
	switch {
	case errors.Is(err, model.ErrNotFound):
		m.log.Debug("event from an unknown or revoked device ignored", "client", client, "device", id, "event", evt)
	case err != nil:
		m.log.Warn("record device event", "client", client, "device", id, "event", evt, "err", err)
	}
}

// clip bounds a self-reported string before it is stored.
func clip(s string) string {
	const max = 255
	if len(s) <= max {
		return s
	}
	return strings.ToValidUTF8(s[:max], "")
}
