// Package relay is Keyhole's control plane. It keeps one NATS connection in
// each client's account (the relay's only route to that client's devices),
// keeps nats-server's account JWTs in step with the store over the SYS
// account, serves enrollment and agent downloads on the public listener, and
// serves the admin API and the MCP endpoint on the private listener.
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/natsauth"
	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/store"
)

// ReportWriter renders an audit report in one format (csv, pdf). entries
// are the client's entries in [meta.From, meta.To), in chain order; v is the
// verification of the client's whole chain.
type ReportWriter func(w io.Writer, meta ReportMeta, entries []audit.Entry, v audit.VerifyResult) error

// ReportMeta describes the report being rendered.
type ReportMeta struct {
	Client      string
	ClientName  string
	From, To    time.Time // zero for an open bound
	GeneratedAt time.Time
}

// DefaultEnrollPerMinute is the default per-IP enrollment rate limit.
const DefaultEnrollPerMinute = 30

// reconcileInterval is how often NATS is brought back in step with the
// store (pending pushes, lost connections).
const reconcileInterval = 30 * time.Second

// Config wires a Server. Store, Conns, Operator, SysCreds and Audit are
// required.
type Config struct {
	Store    *store.Store
	Conns    *ConnManager       // shared with the MCP gateway and the audit store
	Operator *natsauth.Operator // signs client account JWTs
	SysCreds natsauth.UserCreds // SYS-account user that pushes account JWTs
	Audit    audit.Store

	// AgentNATSURLs go to enrolling agents, e.g. wss://keyhole.example.invalid/nats.
	AgentNATSURLs []string
	// MCPURL is the MCP endpoint techs add to Claude Code, e.g.
	// http://relay.example.invalid:7802/mcp.
	MCPURL string
	// DownloadDir is served read-only at /dl/ on the public listener.
	// Empty serves nothing.
	DownloadDir string
	// MCP serves /mcp on the private listener. Nil answers 503.
	MCP http.Handler
	// CompanionURL is the companion's origin (Slice 6). The admin API builds
	// one-time passkey enrollment links with it; empty when technician
	// approval is off.
	CompanionURL string
	// Reports renders audit exports by format name ("csv", "pdf"). jsonl is
	// built in.
	Reports map[string]ReportWriter
	// EnrollPerMinute limits enrollment attempts per client IP (with the same
	// burst). Zero means DefaultEnrollPerMinute.
	EnrollPerMinute int
	// Now is the clock the reconcile loop judges temporary-device deadlines
	// by. Nil means time.Now; tests move it instead of waiting out a session.
	Now    func() time.Time
	Logger *slog.Logger
}

// Server is the relay control plane. Create it with New, then Start it.
type Server struct {
	cfg     Config
	st      *store.Store
	conns   *ConnManager
	op      *natsauth.Operator
	audit   audit.Store
	log     *slog.Logger
	limiter *rateLimiter
	now     func() time.Time

	acctMu sync.Mutex        // serialises account JWT changes, so no revocation is lost
	pushed map[string]string // client -> the account JWT the resolver last accepted

	sys       *nats.Conn
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// New checks cfg and returns an unstarted Server.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("relay: Config.Store is required")
	case cfg.Conns == nil:
		return nil, errors.New("relay: Config.Conns is required")
	case cfg.Operator == nil:
		return nil, errors.New("relay: Config.Operator is required")
	case cfg.Audit == nil:
		return nil, errors.New("relay: Config.Audit is required")
	case cfg.SysCreds.JWT == "" || cfg.SysCreds.Seed == "":
		return nil, errors.New("relay: Config.SysCreds is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	rate := cfg.EnrollPerMinute
	if rate <= 0 {
		rate = DefaultEnrollPerMinute
	}
	// Endpoint consent arrives as a device event, so the connection manager
	// audits the transitions it records.
	cfg.Conns.WithAudit(cfg.Audit)
	return &Server{
		cfg:     cfg,
		st:      cfg.Store,
		conns:   cfg.Conns,
		op:      cfg.Operator,
		audit:   cfg.Audit,
		log:     cfg.Logger,
		limiter: newRateLimiter(rate),
		now:     cfg.Now,
		pushed:  map[string]string{},
	}, nil
}

// Start connects to NATS as the SYS user, pushes every client's account JWT
// and connects to every client account, then keeps NATS in step with the
// store in the background until Close. NATS being down is not fatal:
// connections retry forever, and pending pushes go out once it is back.
func (s *Server) Start(ctx context.Context) error {
	if s.stop != nil {
		return errors.New("relay: already started")
	}
	sys, err := s.conns.dial("sys", s.cfg.SysCreds)
	if err != nil {
		return err
	}
	s.sys = sys
	s.conns.OnSelfRevoke(s.onDeviceSelfRevoked)
	s.stop, s.done = make(chan struct{}), make(chan struct{})
	s.reconcile(ctx)
	go s.loop()
	return nil
}

// Close stops the background work and closes the SYS connection. The
// ConnManager, store and audit store belong to the caller.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		if s.stop != nil {
			close(s.stop)
			<-s.done
		}
		if s.sys != nil {
			s.sys.Close()
		}
	})
}

func (s *Server) loop() {
	defer close(s.done)
	t := time.NewTicker(reconcileInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), reconcileInterval)
			s.reconcile(ctx)
			cancel()
		}
	}
}

// reconcile brings NATS in step with the store: each client's account JWT
// revokes every revoked device and has been accepted by the resolver, and
// each client has a connection.
func (s *Server) reconcile(ctx context.Context) {
	// Expire temporary devices first, so this same pass pushes their
	// revocations into the affected accounts.
	s.expireTemporaryDevices(ctx)
	clients, err := s.st.Clients(ctx)
	if err != nil {
		s.log.Error("reconcile: list clients", "err", err)
		return
	}
	for _, c := range clients {
		if err := s.syncAccount(ctx, c.Slug); err != nil {
			s.log.Warn("reconcile: account not yet in step with nats", "client", c.Slug, "err", err)
		}
		if err := s.connect(ctx, c.Slug); err != nil {
			s.log.Warn("reconcile: connect client account", "client", c.Slug, "err", err)
		}
	}
}

func (s *Server) connect(ctx context.Context, slug string) error {
	if s.conns.has(slug) {
		return nil
	}
	keys, err := s.st.AccountKeys(ctx, slug)
	if err != nil {
		return err
	}
	return s.conns.Connect(slug, natsauth.UserCreds{JWT: keys.RelayJWT, Seed: keys.RelaySeed})
}

// errNATS marks failures to reach nats-server; admin calls answer 502.
var errNATS = errors.New("nats unavailable")

// syncAccount re-signs a client's account JWT if a revoked device's key is
// missing from its revocations, and pushes it unless the resolver has
// already accepted this exact JWT. The store is the source of truth, so a
// push that fails now is retried by the next reconcile.
func (s *Server) syncAccount(ctx context.Context, slug string) error {
	s.acctMu.Lock()
	defer s.acctMu.Unlock()
	keys, err := s.st.AccountKeys(ctx, slug)
	if err != nil {
		return err
	}
	devices, err := s.st.Devices(ctx, slug)
	if err != nil {
		return err
	}
	revoked := map[string]time.Time{}
	for _, d := range devices {
		if d.RevokedAt != nil {
			revoked[d.PublicKey] = *d.RevokedAt
		}
	}
	tok, changed, err := s.op.Revoke(keys.AccountJWT, revoked)
	if err != nil {
		return fmt.Errorf("relay: re-sign account of %s: %w", slug, err)
	}
	if changed {
		if err := s.st.SetAccountJWT(ctx, slug, tok); err != nil {
			return err
		}
	}
	if s.pushed[slug] == tok {
		return nil
	}
	if err := s.push(ctx, tok); err != nil {
		return err
	}
	s.pushed[slug] = tok
	return nil
}

func (s *Server) push(ctx context.Context, accountJWT string) error {
	if s.sys == nil || !s.sys.IsConnected() {
		return fmt.Errorf("relay: push account jwt: %w: not connected", errNATS)
	}
	ctx, cancel := context.WithTimeout(ctx, natsauth.DefaultPushTimeout)
	defer cancel()
	if err := natsauth.Push(ctx, s.sys, accountJWT); err != nil {
		return fmt.Errorf("relay: %w: %w", errNATS, err)
	}
	return nil
}

// provisionClient creates a client's NATS account, has the resolver accept
// it, records the client with the default policy, and connects to the new
// account. Nothing is recorded unless NATS accepted the account.
func (s *Server) provisionClient(ctx context.Context, slug, name string) (model.Client, error) {
	if _, err := s.st.Client(ctx, slug); err == nil {
		return model.Client{}, fmt.Errorf("relay: client %q: %w", slug, model.ErrConflict)
	} else if !errors.Is(err, model.ErrNotFound) {
		return model.Client{}, err
	}
	acct, err := s.op.NewAccount(slug)
	if err != nil {
		return model.Client{}, err
	}
	c := model.Client{
		Slug:       slug,
		Name:       name,
		AccountKey: acct.PublicKey,
		CreatedAt:  time.Now().UTC(),
		Policy:     policy.DefaultClientPolicy(),
	}
	keys := store.AccountKeys{
		AccountKey:  acct.PublicKey,
		AccountSeed: acct.Seed,
		SigningSeed: acct.SigningSeed,
		AccountJWT:  acct.JWT,
		RelayJWT:    acct.Relay.JWT,
		RelaySeed:   acct.Relay.Seed,
	}
	s.acctMu.Lock()
	err = s.push(ctx, acct.JWT)
	if err == nil {
		err = s.st.CreateClient(ctx, c, keys)
	}
	if err == nil {
		s.pushed[slug] = acct.JWT
	}
	s.acctMu.Unlock()
	if err != nil {
		return model.Client{}, err
	}
	if err := s.conns.Connect(slug, acct.Relay); err != nil {
		s.log.Warn("connect new client account; retrying in the background", "client", slug, "err", err)
	}
	return s.st.Client(ctx, slug)
}
