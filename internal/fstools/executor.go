// Package fstools is the agent's read-only file toolkit. Every requested
// path goes through the same pipeline: a shape check, canonicalisation, the
// hard-deny list, the allow rules, a read-only open beneath an os.Root at
// the matched rule's directory, and the same policy again on the final path
// of the open handle. Nothing in this package opens a file for writing.
package fstools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"runtime/debug"
	"slices"
	"time"

	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Redactor replaces secrets in text. The agent passes a gitleaks-backed one.
type Redactor interface {
	Redact(text string) (out string, count int, rules []string)
}

// Options configure an Executor.
type Options struct {
	// Redactor is required when a request's Policy.Redact is set. Without
	// one such requests fail with proto.ErrInternal; unredacted text is
	// never returned.
	Redactor     Redactor
	AgentVersion string
	Now          func() time.Time // default time.Now
	Logger       *slog.Logger     // default slog.Default(); logs recovered panics, never file content

	// ChangeDir is the agent-private directory the structured remediation ops
	// stage plans, rollback copies and their journal in (normally
	// <data>/change). Without it those ops answer proto.ErrUnsupported and
	// this Executor cannot write anything at all.
	ChangeDir string
	// PlanApprover is the local consent application's plan review. When set,
	// prepare_file_change stages the plan, shows it the diff and returns at
	// once; apply_file_change refuses the plan until the person at the machine
	// approves that exact digest. The Windows consent UI implements it.
	PlanApprover ChangeApprover
}

// Executor runs file ops on the live filesystem. It is safe for concurrent
// use.
type Executor struct {
	redactor Redactor
	version  string
	now      func() time.Time
	log      *slog.Logger
	goos     string
	changes  *changeStore // nil without Options.ChangeDir: no op can write
}

// New returns an Executor for the host OS. A ChangeDir that cannot be created
// leaves the change ops unavailable; every read op still works, because a
// broken change store must not take the endpoint's diagnostics down with it.
func New(opts Options) *Executor {
	x := &Executor{redactor: opts.Redactor, version: opts.AgentVersion, now: opts.Now, log: opts.Logger, goos: runtime.GOOS}
	if x.now == nil {
		x.now = time.Now
	}
	if x.log == nil {
		x.log = slog.Default()
	}
	if opts.ChangeDir != "" {
		store, err := newChangeStore(opts.ChangeDir, opts.PlanApprover, x.log)
		if err != nil {
			x.log.Error("fstools: change store unavailable; structured remediation is off", "dir", opts.ChangeDir, "err", err)
		} else {
			x.changes = store
		}
	}
	return x
}

// Execute runs one file op. It never panics (a panic becomes
// proto.ErrInternal), always returns a Response with V, ID and
// Meta.AgentTime, AgentVersion and DurationMS set, abandons the work when
// ctx ends or req.Deadline passes, and answers any op it does not implement
// with proto.ErrUnsupported, ping included (the agent runtime answers ping).
// On success Result is the op's JSON result and Meta.Bytes and Meta.SHA256
// cover exactly those bytes.
func (x *Executor) Execute(ctx context.Context, req *proto.Request) (resp *proto.Response) {
	start := x.now()
	resp = &proto.Response{V: proto.Version}
	op := ""
	if req != nil {
		resp.ID, op = req.ID, req.Op
	}
	defer func() {
		if r := recover(); r != nil {
			x.log.Error("fstools: recovered from panic", "op", op, "request_id", resp.ID,
				"panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			finish(resp, nil, failf(proto.ErrInternal, "internal error in the agent"))
		}
		resp.Meta.AgentTime = start.UTC()
		resp.Meta.AgentVersion = x.version
		resp.Meta.DurationMS = x.now().Sub(start).Milliseconds()
	}()
	result, err := x.run(ctx, req, &resp.Meta)
	finish(resp, result, err)
	return resp
}

func (x *Executor) run(ctx context.Context, req *proto.Request, meta *proto.Meta) (any, error) {
	switch {
	case req == nil:
		return nil, failf(proto.ErrBadRequest, "empty request")
	case req.V != proto.Version:
		return nil, failf(proto.ErrBadRequest, "protocol version %d; this agent speaks version %d", req.V, proto.Version)
	case req.Policy.Redact && x.redactor == nil:
		return nil, failf(proto.ErrInternal, "policy requires redaction but this agent has no redactor; refusing rather than returning unredacted content")
	}
	handler, ok := handlers[req.Op]
	if !ok {
		return nil, failf(proto.ErrUnsupported, "op %q is not supported by this agent", req.Op)
	}
	if !req.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, req.Deadline)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := &call{ctx: ctx, x: x, goos: x.goos, pol: req.Policy, caps: capsOf(req.Policy), meta: meta,
		id: req.ID, op: req.Op, cap: req.Capability}
	return handler(c, req.Args)
}

// handlers maps each implemented op to its decoder and implementation.
var handlers = map[string]func(*call, json.RawMessage) (any, error){
	proto.OpListDir:     handle((*call).listDir),
	proto.OpStat:        handle((*call).stat),
	proto.OpReadFile:    handle((*call).readFile),
	proto.OpSearchFiles: handle((*call).searchFiles),
	proto.OpGrep:        handle((*call).grep),
	proto.OpHashFile:    handle((*call).hashFile),
	// Structured remediation (change*.go). Each of these refuses a request
	// with no capability, and the mutating ones run one at a time per device.
	proto.OpPrepareFileChange:  handle((*call).prepareFileChange),
	proto.OpApplyFileChange:    handle((*call).applyFileChange),
	proto.OpRollbackFileChange: handle((*call).rollbackFileChange),
	proto.OpServiceQuery:       handle((*call).serviceQuery),
	proto.OpServiceRestart:     handle((*call).serviceRestart),
	// Inventory (printer*.go): read-only, under a grant that names the op.
	proto.OpListPrinters: handle((*call).listPrinters),
}

func handle[A, R any](op func(*call, A) (R, error)) func(*call, json.RawMessage) (any, error) {
	return func(c *call, raw json.RawMessage) (any, error) {
		var a A
		if len(raw) == 0 {
			return nil, failf(proto.ErrBadRequest, "missing args")
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, failf(proto.ErrBadRequest, "malformed args: %v", err)
		}
		r, err := op(c, a)
		if err != nil {
			return nil, err
		}
		return r, nil
	}
}

// finish fills resp from an op's outcome. Result is marshalled once and
// Meta.Bytes and Meta.SHA256 are computed over those exact bytes. A failure
// carries no content, so it also reports no redactions.
func finish(resp *proto.Response, result any, err error) {
	if err == nil {
		var b []byte
		if b, err = json.Marshal(result); err == nil {
			sum := sha256.Sum256(b)
			resp.OK, resp.Error, resp.Result = true, nil, b
			resp.Meta.Bytes, resp.Meta.SHA256 = int64(len(b)), hex.EncodeToString(sum[:])
			slices.Sort(resp.Meta.RedactionRules)
			return
		}
		err = fmt.Errorf("encoding result: %w", err)
	}
	resp.OK, resp.Result, resp.Error = false, nil, protoError(err)
	resp.Meta.Bytes, resp.Meta.SHA256 = 0, ""
	resp.Meta.Redactions, resp.Meta.RedactionRules = 0, nil
}

// call is the state of one Execute.
type call struct {
	ctx   context.Context
	x     *Executor
	goos  string
	pol   proto.Policy
	caps  caps
	meta  *proto.Meta
	rules []proto.AllowRule // pol.Allow with symlinks resolved in each rule's literal prefix

	// id and op identify the request: the change ops journal by request ID,
	// which is what makes a mutating request idempotent. cap is the grant the
	// runner has already matched against its live grant cache; the change ops
	// refuse to write without one.
	id, op string
	cap    *proto.Capability
}

// caps are the Policy caps with unset (zero or negative) values replaced by
// the shipped defaults.
type caps struct {
	maxRead, maxFile    int64
	maxList, maxMatches int
}

func capsOf(p proto.Policy) caps {
	c := caps{p.MaxReadBytes, p.MaxFileBytes, p.MaxListEntries, p.MaxMatches}
	if c.maxRead <= 0 {
		c.maxRead = policy.DefaultMaxReadBytes
	}
	if c.maxFile <= 0 {
		c.maxFile = policy.DefaultMaxFileBytes
	}
	if c.maxList <= 0 {
		c.maxList = policy.DefaultMaxListEntries
	}
	if c.maxMatches <= 0 {
		c.maxMatches = policy.DefaultMaxMatches
	}
	return c
}

// clampLimit applies a request's own limit under a policy cap: 0 or more
// than the cap means the cap.
func clampLimit(n, cap int) int {
	if n <= 0 || n > cap {
		return cap
	}
	return n
}

// redact runs the Redactor over text when the policy asks for it. Callers
// record the counts with noteRedactions only for text they return.
func (c *call) redact(text string) (string, int, []string) {
	if !c.pol.Redact {
		return text, 0, nil
	}
	return c.x.redactor.Redact(text)
}

func (c *call) noteRedactions(n int, rules []string) {
	c.meta.Redactions += n
	for _, r := range rules {
		if !slices.Contains(c.meta.RedactionRules, r) {
			c.meta.RedactionRules = append(c.meta.RedactionRules, r)
		}
	}
}

// opError is a failure with a proto error code. Its message reaches the AI:
// it should help correct course, and never names an entry a listing hides.
type opError struct{ code, msg string }

func (e *opError) Error() string { return e.code + ": " + e.msg }

func failf(code, format string, args ...any) error {
	return &opError{code: code, msg: fmt.Sprintf(format, args...)}
}

func protoError(err error) *proto.Error {
	var oe *opError
	switch {
	case errors.As(err, &oe):
		return &proto.Error{Code: oe.code, Message: oe.msg}
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return &proto.Error{Code: proto.ErrTimeout, Message: "the request deadline passed before the op finished"}
	default:
		return &proto.Error{Code: proto.ErrInternal, Message: err.Error()}
	}
}
