// Package companion is the Keyhole companion (Slice 6): the web app in which
// a technician signs in with a passkey, then unlocks a client and approves
// changes on that sign-in, with no prompt per decision. The relay
// serves it on a listener of its own, never beside MCP or administration, and
// in deployment only over HTTPS, because WebAuthn needs a secure context.
//
// The companion verifies passkeys and holds the technician's sign-in. The
// effects of a decision (activating an unlock, releasing a change) belong to
// the gateway, which the companion reaches through model.ApprovalGate.
package companion

import (
	"cmp"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/passkey"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// EnrollPath is where a one-time passkey enrollment link points.
const EnrollPath = "/enroll"

// EnrollURL is the one-time enrollment link for secret on the companion at
// origin. The secret travels in the fragment, which browsers never send to a
// server, so it cannot end up in an access log or a Referer header.
func EnrollURL(origin, secret string) string {
	return strings.TrimRight(origin, "/") + EnrollPath + "#" + secret
}

// Config wires the companion.
type Config struct {
	Store     model.ApprovalStore
	Directory model.Directory // client and device names for the cards
	Gate      model.ApprovalGate
	// Origin is the companion's own origin, e.g. https://library.example.ts.net.
	// Passkeys are accepted from it alone. http is allowed only for localhost.
	Origin string
	// RPID is the WebAuthn relying party ID; the default is Origin's host
	// name. Passkeys are bound to it, so changing it means enrolling them
	// again.
	RPID   string
	Logger *slog.Logger     // default discards
	Now    func() time.Time // default time.Now
}

const (
	bodyLimit     = 64 << 10        // the largest request body; a passkey registration is a few KiB
	maxCeremonies = 256             // passkey ceremonies in flight, per kind
	gateTimeout   = 2 * time.Minute // how long a decision's effects may take, a change's release included
	// ceremonyHint is the browser's prompt timeout, inside the server's so a
	// prompt the browser still shows is one the server will still accept.
	ceremonyHint = model.CeremonyTimeout - 15*time.Second
)

// securityPolicy lets the pages load their own scripts, styles and API and
// nothing else: no inline code, no other origin, no framing.
const securityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// Error codes the companion adds to those in proto.
const (
	codeConflict    = "conflict"
	codeExpired     = "expired"
	codeForbidden   = "forbidden"
	codeUnsupported = "unsupported_media_type"
)

//go:embed static
var assets embed.FS

// Server is the companion.
type Server struct {
	store   model.ApprovalStore
	dir     model.Directory
	gate    model.ApprovalGate
	origin  string
	rpID    string
	rp      passkey.RP
	secure  bool // the origin is https, so the sign-in cookie is Secure
	log     *slog.Logger
	now     func() time.Time
	logins  *ceremonies // sign-ins, keyed by a random ceremony ID
	enrolls *ceremonies // enrollments, keyed by link ID
	handler http.Handler
}

// New checks cfg and builds the companion.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.Directory == nil || cfg.Gate == nil {
		return nil, errors.New("companion: Store, Directory and Gate are required")
	}
	origin, host, err := checkOrigin(cfg.Origin)
	if err != nil {
		return nil, err
	}
	rpID := cmp.Or(cfg.RPID, host)
	if rpID != host && !strings.HasSuffix(host, "."+rpID) {
		return nil, fmt.Errorf("companion: relying party ID %q does not cover the origin's host %q", rpID, host)
	}
	s := &Server{store: cfg.Store, dir: cfg.Directory, gate: cfg.Gate, origin: origin, rpID: rpID,
		rp: passkey.RP{ID: rpID, Origin: origin}, secure: strings.HasPrefix(origin, "https://"),
		log: cmp.Or(cfg.Logger, slog.New(slog.DiscardHandler)), now: cfg.Now,
		logins: newCeremonies(maxCeremonies), enrolls: newCeremonies(maxCeremonies)}
	if s.now == nil {
		s.now = time.Now
	}
	s.handler = s.routes()
	return s, nil
}

// checkOrigin accepts scheme://host[:port] and nothing after it: https, or
// http for localhost, since passkeys need a secure context.
func checkOrigin(raw string) (origin, host string, err error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("companion: origin %q must be scheme://host[:port] with nothing after it", raw)
	}
	host = u.Hostname()
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1"):
	default:
		return "", "", fmt.Errorf("companion: origin %q must use https (http only for localhost): passkeys need a secure context", raw)
	}
	return u.Scheme + "://" + u.Host, host, nil
}

// Handler serves the companion. The relay mounts it on the companion's own
// listener only.
func (s *Server) Handler() http.Handler { return s.handler }

// routes is the companion: its pages, their assets, and the JSON API they
// call, all behind harden.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	for _, p := range []string{"GET /{$}", "GET /u/{id}", "GET /c/{id}"} {
		mux.HandleFunc(p, page("index.html"))
	}
	mux.HandleFunc("GET "+EnrollPath, page("enroll.html"))
	mux.Handle("GET /static/", staticFiles())

	mux.HandleFunc("POST /api/enroll/begin", s.handleEnrollBegin)
	mux.HandleFunc("POST /api/enroll/finish", s.handleEnrollFinish)
	mux.HandleFunc("POST /api/login/begin", s.handleLoginBegin)
	mux.HandleFunc("POST /api/login/finish", s.handleLoginFinish)
	for pattern, h := range map[string]func(http.ResponseWriter, *http.Request, model.CompanionSession){
		"POST /api/logout":               s.handleLogout,
		"GET /api/state":                 s.handleState,
		"GET /api/unlocks/{id}/receipt":  s.handleReceipt,
		"POST /api/unlocks/{id}/approve": s.handleUnlockApprove,
		"POST /api/unlocks/{id}/deny":    s.handleUnlockDeny,
		"POST /api/unlocks/{id}/lock":    s.handleUnlockLock,
		"POST /api/changes/{id}/approve": s.handleChangeApprove,
		"POST /api/changes/{id}/deny":    s.handleChangeDeny,
	} {
		mux.HandleFunc(pattern, s.signedIn(h))
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, proto.ErrNotFound, "no such companion API")
	})
	return s.harden(mux)
}

// harden sets the security headers on every response, and admits a request
// that changes anything only from the companion's own page. Its Origin must be
// the companion's, which the browser sets and no other page can forge, and its
// body JSON, which a cross-site form cannot send. The sign-in cookie is
// SameSite=Strict on top of both.
func (s *Server) harden(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", securityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("Origin") != s.origin {
				writeError(w, http.StatusForbidden, codeForbidden, "requests must come from the Keyhole companion's own page")
				return
			}
			if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, codeUnsupported, "request bodies must be application/json")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)
		}
		next.ServeHTTP(w, r)
	})
}

// page serves one of the embedded HTML pages. The app answers at /, and at
// /u/{id} and /c/{id} so that a link to a card opens the app on it.
func page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		b, err := assets.ReadFile("static/" + name)
		if err != nil {
			http.Error(w, "page missing from the build", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(b)
	}
}

// staticFiles serves the pages' scripts and styles. Directories are not
// listed, and the HTML pages are served at their own paths only.
func staticFiles() http.Handler {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err) // the embedded directory exists by construction
	}
	files := http.StripPrefix("/static/", http.FileServerFS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/static/")
		if name == "" || strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".html") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError answers with a proto.HTTPError body. msg is shown to the
// technician.
func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, proto.HTTPError{Error: proto.Error{Code: code, Message: msg}})
}

// decode reads the request's JSON body into v, answering the request itself
// when it cannot. An empty body is accepted only when optional.
func decode(w http.ResponseWriter, r *http.Request, v any, optional bool) bool {
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(v)
	switch {
	case err == nil:
		var extra json.RawMessage
		if err = dec.Decode(&extra); err == io.EOF {
			return true
		} else if err == nil {
			err = errors.New("unexpected data after the JSON value")
		}
	case err == io.EOF && optional:
		return true
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeError(w, http.StatusRequestEntityTooLarge, proto.ErrBadRequest,
			fmt.Sprintf("the request body is larger than %d bytes", bodyLimit))
		return false
	}
	writeError(w, http.StatusBadRequest, proto.ErrBadRequest, "malformed JSON body: "+err.Error())
	return false
}

// fail answers with the HTTP status for an error from the store or the gate.
// Not found says nothing more, so a card that is someone else's reads exactly
// like one that does not exist.
func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, model.ErrNotFound):
		writeError(w, http.StatusNotFound, proto.ErrNotFound, "Not found. It may have been removed, or not be yours.")
	case errors.Is(err, model.ErrConflict), errors.Is(err, model.ErrPending):
		writeError(w, http.StatusConflict, codeConflict, "It changed before your answer arrived: "+err.Error())
	case errors.Is(err, model.ErrExpired), errors.Is(err, model.ErrExhausted):
		writeError(w, http.StatusGone, codeExpired, "It has expired: "+err.Error())
	case errors.Is(err, model.ErrInvalid):
		writeError(w, http.StatusBadRequest, proto.ErrBadRequest, "Keyhole refused it: "+err.Error())
	case errors.Is(err, model.ErrRevoked):
		writeError(w, http.StatusForbidden, codeForbidden, "Refused: "+err.Error())
	default:
		s.log.Error("companion request failed", "err", err)
		writeError(w, http.StatusInternalServerError, proto.ErrInternal, "Keyhole hit an internal error. Try again in a moment.")
	}
}

// gateContext is what a decision's effects run under. It outlives the
// request: a technician who closes the page while a change is being released
// must not cut the release off halfway, so only the deadline bounds it.
func (s *Server) gateContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), gateTimeout)
}
