package relay

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/nats-io/nkeys"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/natsauth"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/store"
)

const (
	enrollBodyLimit = 16 << 10
	maxEnrollField  = 256
)

// supportedOS are the GOOS values a client policy has rules for.
var supportedOS = map[string]bool{"windows": true, "linux": true, "darwin": true}

// PublicHandler serves the internet-facing listener, reached through the
// Cloudflare tunnel: enrollment, agent downloads and health. MCP and admin
// routes are not registered here at all; they exist only on PrivateHandler.
func (s *Server) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+proto.EnrollPath, s.handleEnroll)
	mux.HandleFunc("POST "+proto.TempOfferPath, s.handleTempOffer)
	mux.HandleFunc("GET /dl/", s.handleDownload)
	mux.HandleFunc(adminapi.RouteHealth, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return s.logRequests("public", mux)
}

// handleEnroll implements "Enrollment" in docs/ARCHITECTURE.md.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.limiter.allow(ip) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, codeRateLimited, "too many enrollment attempts; retry later")
		return
	}
	var req proto.EnrollRequest
	if !decodeBody(w, r, enrollBodyLimit, &req) {
		return
	}
	if err := validateEnroll(&req); err != nil {
		writeError(w, http.StatusBadRequest, proto.ErrBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	enr, err := s.st.EnrollDevice(ctx, store.EnrollParams{
		Secret: req.Token,
		Org:    req.Org,
		Device: model.Device{
			ID:           model.NewID(model.PrefixDevice),
			PublicKey:    req.PublicKey,
			Hostname:     req.Hostname,
			MachineID:    req.MachineID,
			OS:           req.OS,
			OSVersion:    req.OSVersion,
			Arch:         req.Arch,
			AgentVersion: req.AgentVersion,
		},
		Now: time.Now(),
	})
	switch {
	case err == nil:
	case errors.Is(err, model.ErrNotFound), errors.Is(err, model.ErrExpired),
		errors.Is(err, model.ErrRevoked), errors.Is(err, model.ErrExhausted):
		// One answer for every token failure, so this is no oracle.
		s.log.Info("enrollment refused", "ip", ip, "err", err)
		writeError(w, http.StatusUnauthorized, proto.ErrInvalidToken, "the enrollment token is not valid")
		return
	case errors.Is(err, store.ErrOrgMismatch):
		s.log.Info("enrollment refused", "ip", ip, "org", req.Org, "err", err)
		writeError(w, http.StatusForbidden, proto.ErrOrgMismatch, "the enrollment token belongs to a different client")
		return
	case errors.Is(err, model.ErrConflict):
		writeError(w, http.StatusConflict, proto.ErrBadRequest, "this public key is already enrolled; generate a new key")
		return
	default:
		s.log.Error("enrollment failed", "ip", ip, "err", err)
		writeError(w, http.StatusInternalServerError, proto.ErrInternal, "enrollment failed")
		return
	}

	resp, err := s.completeEnrollment(ctx, enr, ip)
	if len(enr.Replaced) > 0 || err != nil {
		if serr := s.syncAccount(ctx, enr.Device.Client); serr != nil {
			s.log.Warn("enroll: revocation not yet pushed to nats; will retry", "client", enr.Device.Client, "err", serr)
		}
	}
	if err != nil {
		code := proto.ErrInternal
		if errors.Is(err, errAudit) {
			code = proto.ErrAuditFailed
		}
		writeError(w, http.StatusInternalServerError, code, "enrollment failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// completeEnrollment signs the device's credential and audits the
// enrollment. If either fails, the new device is revoked and no credential
// is handed out.
func (s *Server) completeEnrollment(ctx context.Context, enr store.Enrollment, ip string) (proto.EnrollResponse, error) {
	d := enr.Device
	keys, err := s.st.AccountKeys(ctx, d.Client)
	var userJWT string
	if err == nil {
		userJWT, err = natsauth.DeviceJWT(keys.AccountKey, keys.SigningSeed, d.ID, d.PublicKey)
	}
	replaced := make([]string, 0, len(enr.Replaced))
	for _, old := range enr.Replaced {
		replaced = append(replaced, old.ID)
	}
	if err == nil {
		err = s.appendAudit(ctx, &audit.Entry{
			Kind:         audit.KindEnroll,
			Client:       d.Client,
			DeviceID:     d.ID,
			DeviceKey:    d.PublicKey,
			Hostname:     d.Hostname,
			AgentVersion: d.AgentVersion,
			Tool:         toolEnroll,
			Result:       audit.ResultOK,
		}, map[string]any{
			"token_id":         enr.Token.ID,
			"machine_id":       d.MachineID,
			"os":               d.OS,
			"os_version":       d.OSVersion,
			"arch":             d.Arch,
			"remote_ip":        ip,
			"replaced_devices": replaced,
		})
	}
	if err != nil {
		s.log.Error("enrollment withdrawn", "client", d.Client, "device", d.ID, "err", err)
		if _, rerr := s.st.RevokeDevice(ctx, d.ID, time.Now()); rerr != nil {
			s.log.Error("withdraw enrolled device", "device", d.ID, "err", rerr)
		}
		return proto.EnrollResponse{}, err
	}
	s.log.Info("device enrolled", "client", d.Client, "device", d.ID, "hostname", d.Hostname,
		"token", enr.Token.ID, "replaced", replaced, "ip", ip)
	return proto.EnrollResponse{
		DeviceID: d.ID,
		Client:   d.Client,
		UserJWT:  userJWT,
		NATSURLs: append([]string(nil), s.cfg.AgentNATSURLs...),
	}, nil
}

func validateEnroll(req *proto.EnrollRequest) error {
	fields := []struct{ name, val string }{
		{"token", req.Token}, {"org", req.Org}, {"hostname", req.Hostname}, {"machine_id", req.MachineID},
		{"os", req.OS}, {"os_version", req.OSVersion}, {"arch", req.Arch}, {"agent_version", req.AgentVersion},
	}
	for _, f := range fields {
		if len(f.val) > maxEnrollField {
			return fmt.Errorf("%s is longer than %d bytes", f.name, maxEnrollField)
		}
		if strings.ContainsFunc(f.val, unicode.IsControl) {
			return fmt.Errorf("%s contains control characters", f.name)
		}
	}
	switch {
	case req.Token == "":
		return errors.New("token is required")
	case !nkeys.IsValidPublicUserKey(req.PublicKey):
		return errors.New("public_key must be a NATS user public key")
	case req.Hostname == "":
		return errors.New("hostname is required")
	case !supportedOS[req.OS]:
		return errors.New("os must be windows, linux or darwin")
	case req.Org != "" && !model.ValidSlug(req.Org):
		return errors.New("org is not a client slug")
	}
	return nil
}

// handleDownload serves regular files from DownloadDir. There are no
// directory listings, no dotfiles, and nothing outside the directory
// (os.OpenInRoot refuses escaping paths and symlinks).
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/dl/")
	if s.cfg.DownloadDir == "" || !servable(name) {
		http.NotFound(w, r)
		return
	}
	f, err := os.OpenInRoot(s.cfg.DownloadDir, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Agents are updated in place. Serving an edge-cached executable risks
	// enrolling a device with an older build after a security or reliability fix.
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

func servable(name string) bool {
	if name == "" || !fs.ValidPath(name) {
		return false
	}
	for seg := range strings.SplitSeq(name, "/") {
		if strings.HasPrefix(seg, ".") {
			return false
		}
	}
	return true
}

// clientIP is the peer address, or Cloudflare's CF-Connecting-IP when the
// peer is loopback (cloudflared runs on the same host). The header is never
// trusted from anyone else.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if peer, err := netip.ParseAddr(host); err == nil && peer.IsLoopback() {
		if cf, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); err == nil {
			return cf.String()
		}
	}
	return host
}

// rateLimiter is a per-key token bucket: burst tokens, refilled at perMinute.
type rateLimiter struct {
	mu        sync.Mutex
	perMinute float64
	burst     float64
	buckets   map[string]*bucket
	lastSweep time.Time
	now       func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMinute int) *rateLimiter {
	return &rateLimiter{
		perMinute: float64(perMinute),
		burst:     float64(perMinute),
		buckets:   map[string]*bucket{},
		now:       time.Now,
	}
}

func (l *rateLimiter) allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// A bucket idle long enough to be full again is the same as no bucket.
	full := time.Duration(l.burst / l.perMinute * float64(time.Minute))
	if now.Sub(l.lastSweep) > time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.last) >= full {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Minutes()*l.perMinute)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
