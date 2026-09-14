package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/mrgyatso/keyhole/internal/agent/hostinfo"
	"github.com/mrgyatso/keyhole/internal/agent/mirror"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/version"
)

// Executor runs one file op; fstools implements it. It fills Result and
// Meta and returns a Response for every request, errors included, and it
// honours ctx.
type Executor interface {
	Execute(ctx context.Context, req *proto.Request) *proto.Response
}

// Mirror receives the local audit copy of each request and of lifecycle
// events. *mirror.Mirror implements it; it must not block.
type Mirror interface {
	Call(mirror.Call)
	Lifecycle(event, detail string)
}

// Defaults for RunnerOptions.
const (
	DefaultMaxInFlight   = 4
	DefaultMaxOpDuration = 2 * time.Minute
	DefaultShutdownGrace = 20 * time.Second
	DefaultReconnectWait = 2 * time.Second
	maxReconnectWait     = time.Minute
	pingInterval         = 20 * time.Second // under Cloudflare's idle WebSocket timeout
	maxPingsOutstanding  = 3
)

// RunnerOptions configures a Runner.
type RunnerOptions struct {
	Enrollment *Enrollment // device ID and NATS URLs
	CredsFile  string      // device.creds; empty connects without credentials (tests only)
	Executor   Executor
	Mirror     Mirror        // nil: no local audit copy
	Host       hostinfo.Info // reported in hello and ping
	Logger     *slog.Logger  // nil: slog.Default()

	MaxInFlight   int           // file ops at once; more get ErrBusy. 0: DefaultMaxInFlight
	MaxOpDuration time.Duration // ceiling on one op whatever its deadline. 0: DefaultMaxOpDuration
	Heartbeat     time.Duration // 0: proto.HeartbeatInterval
	ShutdownGrace time.Duration // wait for in-flight ops on shutdown before cancelling them. 0: DefaultShutdownGrace
	ReconnectWait time.Duration // first reconnect delay, doubled per attempt up to a minute, plus jitter. 0: DefaultReconnectWait
	NATSOptions   []nats.Option // applied last; for tests
	Consent       ConsentAdapter
	GrantsFile    string        // live access IDs, so a restart can revoke what it was holding. "": no record
	ConsentWindow time.Duration // how long a request may wait for the user. 0: proto.ConsentTimeout
}

// Runner serves one device's RPC subject over NATS: it answers ping itself,
// hands file ops to the Executor with bounded concurrency, publishes hello
// and heartbeats, and mirrors every call locally.
type Runner struct {
	o         RunnerOptions
	log       *slog.Logger
	deviceID  string
	rpcPrefix string // kh.d.<device>.rpc.

	mu       sync.Mutex
	inFlight int
	closing  bool
	wg       sync.WaitGroup

	work       context.Context // parent of every op's context
	cancelWork context.CancelFunc
	grants     grantCache

	connMu sync.Mutex
	nc     *nats.Conn // the live connection, for events published outside a request
}

// publishEvent sends an event on the current connection, if there is one.
// Consent transitions happen minutes after the request that started them, so
// they cannot hold on to the connection the request arrived on.
func (r *Runner) publishEvent(evt string, v any) {
	r.connMu.Lock()
	nc := r.nc
	r.connMu.Unlock()
	if nc == nil {
		r.log.Warn("no relay connection for event", "event", evt)
		return
	}
	r.publish(nc, evt, v)
}

// NewRunner checks o and applies defaults.
func NewRunner(o RunnerOptions) (*Runner, error) {
	e := o.Enrollment
	switch {
	case e == nil || e.DeviceID == "":
		return nil, errors.New("agent: runner needs an enrollment with a device ID")
	case len(e.NATSURLs) == 0:
		return nil, errors.New("agent: enrollment has no NATS URLs")
	case o.Executor == nil:
		return nil, errors.New("agent: runner needs an executor")
	}
	for _, u := range e.NATSURLs {
		if err := checkNATSURL(u); err != nil {
			return nil, fmt.Errorf("agent: %w", err)
		}
	}
	if o.CredsFile != "" {
		if _, err := os.Stat(o.CredsFile); err != nil {
			return nil, fmt.Errorf("agent: credentials: %w", err)
		}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.MaxInFlight <= 0 {
		o.MaxInFlight = DefaultMaxInFlight
	}
	if o.MaxOpDuration <= 0 {
		o.MaxOpDuration = DefaultMaxOpDuration
	}
	if o.Heartbeat <= 0 {
		o.Heartbeat = proto.HeartbeatInterval
	}
	if o.ShutdownGrace <= 0 {
		o.ShutdownGrace = DefaultShutdownGrace
	}
	if o.ReconnectWait <= 0 {
		o.ReconnectWait = DefaultReconnectWait
	}
	if o.ConsentWindow <= 0 {
		o.ConsentWindow = proto.ConsentTimeout
	}
	work, cancel := context.WithCancel(context.Background())
	return &Runner{
		o:          o,
		log:        o.Logger.With("device_id", e.DeviceID),
		deviceID:   e.DeviceID,
		rpcPrefix:  proto.RPCSubject(e.DeviceID, ""),
		work:       work,
		cancelWork: cancel,
		grants:     grantCache{grants: map[string]liveGrant{}},
	}, nil
}

// Run connects to the relay and serves requests until ctx is cancelled,
// then stops taking requests, lets in-flight ones finish (cancelling them
// after ShutdownGrace) and disconnects. It keeps reconnecting on its own
// while the relay is unreachable, and returns nil after a clean shutdown.
// A Runner runs once.
func (r *Runner) Run(ctx context.Context) error {
	defer r.cancelWork()
	closed := make(chan struct{})
	nc, err := r.connect(closed)
	if err != nil {
		return err
	}
	defer nc.Close()
	r.connMu.Lock()
	r.nc = nc
	r.connMu.Unlock()
	sub, err := nc.Subscribe(proto.RPCWildcard(r.deviceID), func(m *nats.Msg) { r.onMsg(nc, m) })
	if err != nil {
		return fmt.Errorf("agent: subscribe: %w", err)
	}
	// Restarting cleared the live grant cache, so anything the previous run
	// was holding is already unusable. Tell the relay before serving.
	r.terminateStaleGrants()
	r.lifecycle(mirror.Start, "keyhole-agent "+version.Version)
	r.log.Info("agent started", "version", version.Version, "servers", strings.Join(r.o.Enrollment.NATSURLs, ","))

	hbCtx, stopHB := context.WithCancel(ctx)
	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		r.heartbeats(hbCtx, nc)
	}()

	var runErr error
	select {
	case <-ctx.Done():
	case <-closed:
		runErr = errors.New("agent: NATS connection closed unexpectedly")
	}
	stopHB()
	<-hbDone
	r.shutdown(nc, sub)
	r.lifecycle(mirror.Stop, "")
	r.log.Info("agent stopped")
	return runErr
}

func (r *Runner) connect(closed chan<- struct{}) (*nats.Conn, error) {
	name := "keyhole-agent " + version.Version + " " + r.deviceID
	if r.o.Host.Hostname != "" {
		name += " (" + r.o.Host.Hostname + ")"
	}
	opts := []nats.Option{
		nats.Name(name),
		nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(true),
		// A revoked or not-yet-valid credential must not end the service:
		// keep trying, with backoff, so an un-revoke or fix needs no visit.
		nats.IgnoreAuthErrorAbort(),
		nats.CustomReconnectDelay(r.reconnectDelay),
		nats.PingInterval(pingInterval),
		nats.MaxPingsOutstanding(maxPingsOutstanding),
		nats.Timeout(15 * time.Second),
		nats.ConnectHandler(func(nc *nats.Conn) { r.onConnect(nc, false) }),
		nats.ReconnectHandler(func(nc *nats.Conn) { r.onConnect(nc, true) }),
		nats.ReconnectErrHandler(func(_ *nats.Conn, err error) {
			r.log.Warn("relay connection attempt failed", "err", err)
		}),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			if nc.IsClosed() {
				return
			}
			r.log.Warn("disconnected from relay", "err", err)
			r.lifecycle(mirror.Disconnect, errString(err))
		}),
		nats.ClosedHandler(func(*nats.Conn) { close(closed) }),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			r.log.Warn("NATS error", "err", err)
		}),
	}
	if r.o.CredsFile != "" {
		opts = append(opts, nats.UserCredentials(r.o.CredsFile))
	}
	opts = append(opts, r.o.NATSOptions...)
	nc, err := nats.Connect(strings.Join(r.o.Enrollment.NATSURLs, ","), opts...)
	if err != nil {
		return nil, fmt.Errorf("agent: connect: %w", err)
	}
	return nc, nil
}

// reconnectDelay backs off exponentially with jitter, so a fleet does not
// reconnect in lockstep after a relay restart.
func (r *Runner) reconnectDelay(attempts int) time.Duration {
	d := r.o.ReconnectWait << min(max(attempts-1, 0), 6)
	d = min(d, maxReconnectWait)
	return d + rand.N(d/2+1)
}

func (r *Runner) onConnect(nc *nats.Conn, reconnected bool) {
	url := nc.ConnectedUrlRedacted()
	r.log.Info("connected to relay", "url", url, "reconnect", reconnected)
	r.lifecycle(mirror.Connect, url)
	hello := proto.Hello{
		DeviceID:     r.deviceID,
		Hostname:     r.o.Host.Hostname,
		OS:           r.o.Host.OS,
		OSVersion:    r.o.Host.OSVersion,
		Arch:         r.o.Host.Arch,
		AgentVersion: version.Version,
		Time:         time.Now().UTC(),
	}
	r.publish(nc, proto.EvtHello, hello)
}

func (r *Runner) heartbeats(ctx context.Context, nc *nats.Conn) {
	t := time.NewTicker(r.o.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if nc.IsConnected() {
				r.publish(nc, proto.EvtHeartbeat, proto.Heartbeat{DeviceID: r.deviceID, Time: time.Now().UTC()})
			}
		}
	}
}

func (r *Runner) publish(nc *nats.Conn, evt string, v any) {
	b, err := json.Marshal(v)
	if err == nil {
		err = nc.Publish(proto.EventSubject(r.deviceID, evt), b)
	}
	if err != nil {
		r.log.Warn("publish event failed", "event", evt, "err", err)
	}
}

func (r *Runner) onMsg(nc *nats.Conn, m *nats.Msg) {
	start := time.Now()
	if m.Reply == "" {
		r.log.Warn("request without a reply subject, dropped", "subject", m.Subject)
		return
	}
	req, perr := r.decode(m)
	if perr != nil {
		r.finish(nc, m, req, &proto.Response{Error: perr}, start)
		return
	}
	if req.Op == proto.OpPing {
		r.finish(nc, m, req, r.ping(), start)
		return
	}
	if req.Op == proto.OpRequestAccess {
		var cr proto.ConsentRequest
		if err := json.Unmarshal(req.Args, &cr); err != nil {
			r.finish(nc, m, req, &proto.Response{Error: &proto.Error{Code: proto.ErrBadRequest, Message: "malformed consent request"}}, start)
			return
		}
		r.finish(nc, m, req, r.consent(r.work, cr), start)
		return
	}
	if req.Op == proto.OpEndAccess {
		var a proto.EndAccessArgs
		if err := json.Unmarshal(req.Args, &a); err != nil {
			r.finish(nc, m, req, &proto.Response{Error: &proto.Error{Code: proto.ErrBadRequest, Message: "malformed end request"}}, start)
			return
		}
		r.finish(nc, m, req, r.endAccess(a), start)
		return
	}
	if err := r.authorize(req); err != nil {
		r.finish(nc, m, req, &proto.Response{Error: err}, start)
		return
	}
	if msg := r.acquire(); msg != "" {
		r.finish(nc, m, req, &proto.Response{Error: &proto.Error{Code: proto.ErrBusy, Message: msg}}, start)
		return
	}
	go func() {
		defer r.release()
		r.finish(nc, m, req, r.execute(req), start)
	}()
}

// decode parses and checks a request. On failure it returns what it could
// parse (for the reply's ID) and the error to send.
func (r *Runner) decode(m *nats.Msg) (*proto.Request, *proto.Error) {
	var req proto.Request
	if err := json.Unmarshal(m.Data, &req); err != nil {
		return &proto.Request{}, &proto.Error{Code: proto.ErrBadRequest, Message: "request is not valid JSON: " + err.Error()}
	}
	now := time.Now()
	switch op := strings.TrimPrefix(m.Subject, r.rpcPrefix); {
	case req.V != proto.Version:
		return &req, &proto.Error{Code: proto.ErrBadRequest,
			Message: fmt.Sprintf("protocol version %d is not supported; this agent speaks version %d", req.V, proto.Version)}
	case req.Op == "" || req.Op != op:
		return &req, &proto.Error{Code: proto.ErrBadRequest,
			Message: fmt.Sprintf("op %q does not match subject %q", req.Op, m.Subject)}
	case req.Deadline.IsZero():
		return &req, &proto.Error{Code: proto.ErrBadRequest, Message: "request has no deadline"}
	case !now.Before(req.Deadline):
		return &req, &proto.Error{Code: proto.ErrTimeout,
			Message: fmt.Sprintf("deadline %s had passed when the agent received the request at %s (check the clocks)",
				req.Deadline.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))}
	}
	return &req, nil
}

func (r *Runner) ping() *proto.Response {
	b, err := json.Marshal(proto.PingResult{
		DeviceID:     r.deviceID,
		Hostname:     r.o.Host.Hostname,
		OS:           r.o.Host.OS,
		Arch:         r.o.Host.Arch,
		AgentVersion: version.Version,
		Time:         time.Now().UTC(),
	})
	if err != nil {
		return &proto.Response{Error: &proto.Error{Code: proto.ErrInternal, Message: "encode ping result"}}
	}
	return &proto.Response{OK: true, Result: b}
}

// acquire takes an in-flight slot. It returns "" on success, or why not.
func (r *Runner) acquire() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.closing:
		return "agent is shutting down"
	case r.inFlight >= r.o.MaxInFlight:
		return fmt.Sprintf("agent is busy with %d requests; retry shortly", r.inFlight)
	}
	r.inFlight++
	r.wg.Add(1)
	return ""
}

func (r *Runner) release() {
	r.mu.Lock()
	r.inFlight--
	r.mu.Unlock()
	r.wg.Done()
}

func (r *Runner) execute(req *proto.Request) (resp *proto.Response) {
	deadline := req.Deadline
	if ceiling := time.Now().Add(r.o.MaxOpDuration); ceiling.Before(deadline) {
		deadline = ceiling
	}
	ctx, cancel := context.WithDeadline(r.work, deadline)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			r.log.Error("executor panicked", "op", req.Op, "request_id", req.ID, "panic", p, "stack", string(debug.Stack()))
			resp = &proto.Response{Error: &proto.Error{Code: proto.ErrInternal, Message: "agent failed while executing " + req.Op}}
		}
	}()
	resp = r.o.Executor.Execute(ctx, req)
	if resp == nil {
		resp = &proto.Response{Error: &proto.Error{Code: proto.ErrInternal, Message: "executor returned no response"}}
	}
	return resp
}

// finish completes resp, mirrors it and sends it.
func (r *Runner) finish(nc *nats.Conn, m *nats.Msg, req *proto.Request, resp *proto.Response, start time.Time) {
	data := seal(req, resp, start, nc.MaxPayload())
	r.record(req, resp)
	r.activity(req, resp)
	code := ""
	if resp.Error != nil {
		code = resp.Error.Code
	}
	r.log.Debug("request", "op", req.Op, "request_id", req.ID, "error", code,
		"bytes", resp.Meta.Bytes, "duration_ms", resp.Meta.DurationMS)
	if err := m.Respond(data); err != nil {
		r.log.Warn("reply failed", "op", req.Op, "request_id", req.ID, "err", err)
	}
}

// seal fills the envelope and Meta of resp and encodes it. Result is
// re-encoded first so that Meta.Bytes and Meta.SHA256 cover exactly the
// bytes that go on the wire (json.Marshal compacts and HTML-escapes an
// embedded RawMessage, so an executor's own encoding may differ). A
// response over maxPayload is replaced by a too_large error, and resp is
// updated to what was actually sent.
func seal(req *proto.Request, resp *proto.Response, start time.Time, maxPayload int64) []byte {
	resp.V, resp.ID = proto.Version, req.ID
	if resp.Error == nil && !resp.OK {
		resp.Error = &proto.Error{Code: proto.ErrInternal, Message: "executor reported failure without an error"}
	}
	if resp.Error == nil && len(resp.Result) > 0 {
		canon, err := json.Marshal(resp.Result)
		if err != nil {
			resp.Error = &proto.Error{Code: proto.ErrInternal, Message: "executor produced an invalid JSON result"}
		} else {
			resp.Result = canon
		}
	}
	resp.OK = resp.Error == nil
	if !resp.OK {
		resp.Result = nil
	}
	m := &resp.Meta
	if m.AgentTime.IsZero() {
		m.AgentTime = time.Now().UTC()
	}
	if m.AgentVersion == "" {
		m.AgentVersion = version.Version
	}
	if m.DurationMS == 0 {
		m.DurationMS = time.Since(start).Milliseconds()
	}
	m.Bytes, m.SHA256 = int64(len(resp.Result)), ""
	if len(resp.Result) > 0 {
		sum := sha256.Sum256(resp.Result)
		m.SHA256 = hex.EncodeToString(sum[:])
	} else {
		m.Redactions, m.RedactionRules = 0, nil
	}

	data, err := json.Marshal(resp)
	if err == nil && (maxPayload <= 0 || int64(len(data)) <= maxPayload) {
		return data
	}
	msg := "could not encode the response"
	if err == nil {
		msg = fmt.Sprintf("response is %d bytes, over the %d-byte message limit; read a smaller slice", len(data), maxPayload)
	}
	*resp = proto.Response{
		V:     proto.Version,
		ID:    req.ID,
		Error: &proto.Error{Code: proto.ErrTooLarge, Message: msg},
		Meta: proto.Meta{
			ResolvedPath: m.ResolvedPath,
			RuleID:       m.RuleID,
			AgentTime:    m.AgentTime,
			AgentVersion: m.AgentVersion,
			DurationMS:   m.DurationMS,
		},
	}
	if err != nil {
		resp.Error.Code = proto.ErrInternal
	}
	data, _ = json.Marshal(resp)
	return data
}

func (r *Runner) record(req *proto.Request, resp *proto.Response) {
	if r.o.Mirror == nil {
		return
	}
	var args struct {
		Path string `json:"path"`
	}
	_ = json.Unmarshal(req.Args, &args)
	c := mirror.Call{
		DeviceID:     r.deviceID,
		RequestID:    req.ID,
		Tech:         req.Caller.Tech,
		Session:      req.Caller.Session,
		Op:           req.Op,
		Path:         args.Path,
		ResolvedPath: resp.Meta.ResolvedPath,
		RuleID:       resp.Meta.RuleID,
		Bytes:        resp.Meta.Bytes,
		SHA256:       resp.Meta.SHA256,
		Redactions:   resp.Meta.Redactions,
	}
	if resp.Error != nil {
		c.ErrorCode = resp.Error.Code
	}
	r.o.Mirror.Call(c)
}

func (r *Runner) lifecycle(event, detail string) {
	if r.o.Mirror != nil {
		r.o.Mirror.Lifecycle(event, detail)
	}
}

// shutdown stops taking requests, waits for in-flight ones (cancelling them
// after the grace period) and flushes their replies.
func (r *Runner) shutdown(nc *nats.Conn, sub *nats.Subscription) {
	r.mu.Lock()
	r.closing = true
	inFlight := r.inFlight
	r.mu.Unlock()
	// Requests already delivered are still answered, with ErrBusy.
	if err := sub.Drain(); err != nil {
		_ = sub.Unsubscribe()
	}
	if inFlight > 0 {
		r.log.Info("waiting for in-flight requests", "count", inFlight)
	}
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(r.o.ShutdownGrace):
		r.log.Warn("cancelling in-flight requests after the shutdown grace period")
		r.cancelWork()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			r.log.Error("in-flight requests ignored cancellation; exiting without their replies")
		}
	}
	if err := nc.FlushTimeout(2 * time.Second); err != nil && !errors.Is(err, nats.ErrConnectionClosed) {
		r.log.Warn("flush on shutdown", "err", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
