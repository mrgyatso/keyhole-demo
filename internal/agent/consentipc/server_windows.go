//go:build windows

package consentipc

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
)

// RequireSignedUIEnv switches on Authenticode verification of the consent
// application. It is off until Keyhole has a signing certificate; the
// acceptance procedure in the Slice 3 handoff says how to test it with a
// self-signed one.
const RequireSignedUIEnv = "KEYHOLE_REQUIRE_SIGNED_CONSENT_UI"

// writeTimeout bounds one message to a consent application. A window that
// cannot keep up is disconnected, which pauses the grants it was watching
// rather than letting the service block on it.
const writeTimeout = 5 * time.Second

// Server is the service's named-pipe transport for local consent. It
// verifies every peer, hands the verified identity to the Hub, and never
// lets a message decide who sent it.
type Server struct {
	hub              *Hub
	log              *slog.Logger
	image            string
	pipe             string
	hello            Hello
	requireSignature bool
}

// ServerOptions configures a Server.
type ServerOptions struct {
	Logger *slog.Logger
	// Image is the installed consent application. A peer running any other
	// executable is refused. It defaults to keyhole-consent.exe beside this
	// process, which on an installed endpoint is the ACL-protected program
	// directory.
	Image            string
	Hello            Hello
	RequireSignature bool
	// Pipe is the pipe to serve. It defaults to PipeName; tests use their
	// own so they never collide with an installed service.
	Pipe string
	// Sessions and Launch replace how the service lists interactive sessions
	// and starts the consent application in one. They default to the
	// Terminal Services calls; tests set them so that a test never starts a
	// program in anyone's session.
	Sessions func() []string
	Launch   func(session string) error
}

// NewServer returns an unstarted Server and the ConsentAdapter the runner
// uses.
func NewServer(o ServerOptions) (*Server, error) {
	image := o.Image
	if image == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("consentipc: locate the service executable: %w", err)
		}
		image = filepath.Join(filepath.Dir(exe), ConsentExecutable)
	}
	log := cmp.Or(o.Logger, slog.New(slog.DiscardHandler))
	s := &Server{log: log, image: image, pipe: cmp.Or(o.Pipe, PipeName), hello: o.Hello,
		requireSignature: o.RequireSignature || os.Getenv(RequireSignedUIEnv) == "1"}
	s.hello.Version = ProtocolVersion
	sessions, launch := o.Sessions, o.Launch
	if sessions == nil {
		sessions = interactiveSessions
	}
	if launch == nil {
		launch = func(session string) error { return launchInSession(session, image) }
	}
	s.hub = NewHub(HubOptions{Logger: log, Sessions: sessions, Launch: launch})
	return s, nil
}

// ConsentExecutable is the consent application's file name. The service
// expects it beside its own executable.
const ConsentExecutable = "keyhole-consent.exe"

// Adapter is what the runner uses as its ConsentAdapter.
func (s *Server) Adapter() *Hub { return s.hub }

// Serve listens on the consent pipe until ctx is done. The pipe's ACL lets
// only SYSTEM, Administrators and interactive users open it; every
// connection is then checked again against the installed executable.
func (s *Server) Serve(ctx context.Context) error {
	l, err := winio.ListenPipe(s.pipe, &winio.PipeConfig{
		SecurityDescriptor: PipeSDDL,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
	if err != nil {
		return fmt.Errorf("consentipc: listen on %s: %w", s.pipe, err)
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	s.log.Info("consent pipe listening", "pipe", s.pipe, "image", s.image, "require_signature", s.requireSignature)
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, winio.ErrPipeListenerClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Warn("consent pipe accept failed", "err", err)
			continue
		}
		go s.handle(ctx, conn)
	}
}

// handle verifies one consent application and serves it until it goes away.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	p, err := inspect(conn, s.image, s.requireSignature)
	if err != nil {
		s.log.Warn("refused a consent pipe client", "err", err)
		return
	}
	out := make(chan Envelope, 32)
	var once sync.Once
	stop := func() { once.Do(func() { close(out) }) }
	defer stop()
	v := &View{Session: p.session, User: p.user, Elevated: p.elevated, Send: func(e Envelope) {
		defer func() { _ = recover() }() // the writer may have closed out
		select {
		case out <- e:
		default:
			s.log.Warn("consent application is not keeping up; disconnecting", "session", p.session)
			_ = conn.Close()
		}
	}}
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for e := range out {
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := WriteEnvelope(conn, e); err != nil {
				s.log.Warn("consent application write failed", "session", p.session, "err", err)
				_ = conn.Close()
				return
			}
		}
	}()
	v.Send(Envelope{Type: TypeHello, Hello: &s.hello})
	s.hub.AddView(v)
	// AddView has already resumed any grant that was paused only because no
	// window was watching it; a grant the user paused stays paused.
	s.log.Info("consent application attached", "session", p.session, "user", p.user,
		"elevated", p.elevated, "pid", p.pid)

	r := NewReader(conn)
	for ctx.Err() == nil {
		e, err := ReadEnvelope(r)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
				s.log.Warn("consent application read failed", "session", p.session, "err", err)
			}
			break
		}
		s.dispatch(v, p, e)
	}
	stop()
	<-writerDone
	// A window that exited while its session is still signed in only pauses
	// what it was watching; a session that has gone ends the grants the user
	// in it approved.
	s.hub.RemoveView(v, !sessionHasUser(p.session))
}

func (s *Server) dispatch(v *View, p peer, e Envelope) {
	switch e.Type {
	case TypeHello:
		if e.Hello != nil && e.Hello.Version != ProtocolVersion {
			s.log.Warn("consent application speaks another protocol version",
				"session", p.session, "version", e.Hello.Version, "want", ProtocolVersion)
		}
	case TypeDecide:
		if e.Decide == nil {
			return
		}
		if err := s.hub.Decide(v, *e.Decide); err != nil {
			s.log.Warn("refused a consent decision", "session", p.session, "user", p.user,
				"access", e.Decide.AccessID, "decision", e.Decide.Decision, "err", err)
			return
		}
		s.log.Info("endpoint user answered", "session", p.session, "user", p.user,
			"access", e.Decide.AccessID, "decision", e.Decide.Decision, "elevated", p.elevated)
	case TypePlanDecide:
		if e.PlanDecide == nil {
			return
		}
		if err := s.hub.DecidePlan(v, *e.PlanDecide); err != nil {
			s.log.Warn("refused a plan decision", "session", p.session, "user", p.user,
				"access", e.PlanDecide.AccessID, "err", err)
			return
		}
		s.log.Info("endpoint user reviewed a change", "session", p.session, "user", p.user,
			"access", e.PlanDecide.AccessID, "decision", e.PlanDecide.Decision, "elevated", p.elevated)
	case TypeControl:
		if e.Control == nil {
			return
		}
		if err := s.hub.Control(v, *e.Control); err != nil {
			s.log.Warn("refused a consent control", "session", p.session, "user", p.user,
				"access", e.Control.AccessID, "action", e.Control.Action, "err", err)
			return
		}
		s.log.Info("endpoint user controlled a grant", "session", p.session, "user", p.user,
			"access", e.Control.AccessID, "action", e.Control.Action)
	default:
		s.log.Warn("unknown consent message", "session", p.session, "type", e.Type)
	}
}
