package gateway

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nats-io/nats.go"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// callError is a call that did not produce content: the tool error Claude
// sees and the result the audit entry records.
type callError struct {
	result string // audit.ResultDenied or audit.ResultError
	code   string
	msg    string
}

func denied(code, msg string) *callError { return &callError{audit.ResultDenied, code, msg} }
func failed(code, msg string) *callError { return &callError{audit.ResultError, code, msg} }

// opCall is one tool call that runs an agent op on one device.
type opCall struct {
	tool     string // MCP tool name, which is also the agent op
	device   string // the device argument as Claude gave it
	accessID string
	args     any             // the op's proto args
	input    json.RawMessage // the tool arguments as sent, for the audit entry
	render   func(model.Device, *proto.Response) (*mcp.CallToolResult, error)
	// before and after are the structured remediation hooks: before runs once
	// the grant has been checked and can refuse the call (a mismatched change
	// plan) before anything reaches the machine; after runs on a successful
	// result and can record what the call produced. Both are audited like any
	// other outcome. They are nil for every read tool.
	before func(model.AccessRequest) *callError
	after  func(model.AccessRequest, *proto.Response) *callError
	// requestID fixes the request ID the endpoint sees. A released change
	// approval uses its own, so releasing it again is idempotent at the
	// endpoint; empty mints a fresh one.
	requestID string
}

// runOp is one device tool call, end to end. Whatever happens, it writes an
// audit entry, and it returns content only once that entry is durable.
func (g *Gateway) runOp(ctx context.Context, c caller, oc opCall) *mcp.CallToolResult {
	unlock := g.budgets.lock(c.session.ID)
	defer unlock()
	began := time.Now()
	e := g.entry(c, oc.tool, oc.input)
	if c.technician {
		e.Client = g.auditClient(ctx, c)
	}
	out, cerr := g.doOp(ctx, c, oc, &e)
	e.DurationMS = time.Since(began).Milliseconds()
	return g.finish(ctx, c, &e, out, cerr)
}

func (g *Gateway) doOp(ctx context.Context, c caller, oc opCall, e *audit.Entry) (*mcp.CallToolResult, *callError) {
	var activate *model.AccessRequest
	var access *model.AccessRequest
	unlocked := "" // the technician unlock the call runs under, if any
	clientSlug := ""
	if c.technician {
		if oc.accessID == "" {
			return nil, denied(proto.ErrGrantInvalid, "technician registrations require an approved access grant")
		}
		if g.access == nil {
			return nil, failed(proto.ErrInternal, "consented access store is unavailable")
		}
		a, err := g.access.Access(ctx, oc.accessID)
		if err != nil || a.Technician != c.session.Tech {
			return nil, denied(proto.ErrGrantInvalid, "access grant not found")
		}
		access, clientSlug = &a, a.Client
	} else if oc.accessID == "" && g.technicianApproval() {
		// Under technician approval every call on a machine runs under a grant
		// the technician's unlock made. A client-bound session without one
		// would read with no unlock at all; it can still list devices, and
		// request_access asks the technician for the unlock.
		return nil, denied(proto.ErrGrantInvalid, "every call on a machine needs an access grant from the technician's unlock of this client; call request_access, then pass its access_id")
	}
	client, cerr := g.admitClient(ctx, c, clientSlug)
	if cerr != nil {
		return nil, cerr
	}
	e.Client = client.Slug
	dev, cerr := g.resolveDevice(ctx, client.Slug, oc.device)
	if cerr != nil {
		return nil, cerr
	}
	e.DeviceID, e.DeviceKey, e.Hostname, e.AgentVersion = dev.ID, dev.PublicKey, dev.Hostname, dev.AgentVersion
	now := g.now()
	switch {
	case dev.RevokedAt != nil:
		return nil, denied(proto.ErrDeviceRevoked, fmt.Sprintf("%s was revoked on %s", deviceLabel(dev), dev.RevokedAt.UTC().Format(time.RFC3339)))
	// A temporary install is over at its deadline. The relay's reconcile loop
	// turns that into a real revocation within the minute; until then the
	// gateway must already refuse it, so a late sweep cannot extend a session.
	case dev.Expired(now):
		return nil, denied(proto.ErrDeviceRevoked, fmt.Sprintf("%s is a temporary installation whose session ended on %s",
			deviceLabel(dev), dev.ExpiresAt.UTC().Format(time.RFC3339)))
	case !dev.Online(now):
		return nil, failed(proto.ErrDeviceOffline, offlineMessage(dev))
	}
	budget := sessionBudget(client.Policy)
	if used := g.budgets.used(c.session.ID); used >= budget {
		return nil, denied(proto.ErrBudget, fmt.Sprintf("this session has already received %s, its whole read budget; the MSP can mint a new session", humanBytes(used)))
	}

	args, err := json.Marshal(oc.args)
	if err != nil {
		return nil, failed(proto.ErrInternal, "could not encode the request")
	}
	req := proto.Request{
		V:        proto.Version,
		ID:       cmp.Or(oc.requestID, model.NewID(model.PrefixRequest)),
		Op:       oc.tool,
		Args:     args,
		Policy:   client.Policy.For(dev.OS),
		Caller:   proto.Caller{Tech: c.session.Tech, Session: c.session.ID},
		Deadline: time.Now().Add(g.timeout),
	}
	e.RequestID = req.ID
	if oc.accessID != "" {
		if g.access == nil {
			return nil, failed(proto.ErrInternal, "consented access store is unavailable")
		}
		a := model.AccessRequest{}
		if access != nil {
			a = *access
		} else {
			var err error
			a, err = g.access.Access(ctx, oc.accessID)
			if err != nil {
				return nil, denied(proto.ErrGrantInvalid, "access grant does not belong to this client and device")
			}
		}
		if a.Client != client.Slug || a.Device != dev.ID {
			return nil, denied(proto.ErrGrantInvalid, "access grant does not belong to this client and device")
		}
		if a.Technician != c.session.Tech {
			return nil, denied(proto.ErrGrantInvalid, "access grant belongs to another technician")
		}
		// The consent window and the grant lifetime are enforced here as well
		// as at the endpoint, so a paused, overdue or expired grant is refused
		// before it reaches the machine.
		a = g.refresh(ctx, c, a, oc.input)
		if err := a.Usable(now); err != nil {
			return nil, denied(proto.ErrGrantInvalid, "access grant is "+err.Error())
		}
		// A grant made under a technician unlock lasts only while the unlock
		// does: its Lock, expiry or idle timeout ends every call at once.
		if a.Unlock != "" {
			if cerr := g.unlockLive(ctx, a, now); cerr != nil {
				return nil, cerr
			}
			unlocked = a.Unlock
		}
		req.Capability = &proto.Capability{GrantID: a.GrantID, AccessID: a.ID, Nonce: a.Nonce, Client: a.Client, Device: a.Device, Technician: a.Technician, Operations: a.EffectiveOperations, Paths: a.EffectiveScope, IssuedAt: *a.DecidedAt, ExpiresAt: a.ExpiresAt, IdleTimeout: a.IdleTimeout, PolicyVersion: a.PolicyVersion, Unlock: a.Unlock, EndpointConsent: a.EndpointConsent}
		if a.State == model.AccessApproved {
			activate = &a
		}
		access = &a
		if oc.before != nil {
			if cerr := oc.before(a); cerr != nil {
				return nil, cerr
			}
		}
	}
	resp, cerr := g.rpc(ctx, client.Slug, dev.ID, req)
	if cerr != nil {
		return nil, cerr
	}
	// Whatever the machine answered under an unlock, served or refused, is
	// what the technician's companion lists, and what keeps it from idling.
	if unlocked != "" {
		g.recordUnlockUse(ctx, unlocked, req, dev.ID, resp)
	}
	m := resp.Meta
	e.ResolvedPath, e.RuleID, e.Redactions = m.ResolvedPath, m.RuleID, m.Redactions
	e.AgentVersion = cmp.Or(m.AgentVersion, e.AgentVersion)
	if !m.AgentTime.IsZero() {
		at := m.AgentTime
		e.AgentTime = &at
	}
	if !resp.OK {
		return nil, agentError(resp.Error)
	}
	if cerr := checkIntegrity(resp); cerr != nil {
		g.log.Warn("gateway: agent result failed its integrity check", "client", client.Slug, "device", dev.ID, "request", req.ID)
		return nil, cerr
	}
	out, err := oc.render(dev, resp)
	if err != nil {
		return nil, failed(proto.ErrInternal, "the agent's result could not be read: "+err.Error())
	}
	e.Bytes, e.SHA256 = m.Bytes, m.SHA256
	if m.Change != nil {
		e.Change, _ = json.Marshal(m.Change) // what a remediation op changed, for the audit entry
	}
	if activate != nil {
		if cerr := g.activate(ctx, c, *activate, oc.input); cerr != nil {
			return nil, cerr
		}
	}
	if oc.after != nil && access != nil {
		if cerr := oc.after(*access, resp); cerr != nil {
			return nil, cerr
		}
	}
	return out, nil
}

// listDevices answers list_devices from the directory; it reaches no device.
func (g *Gateway) listDevices(ctx context.Context, c caller, clientSlug string, input json.RawMessage) *mcp.CallToolResult {
	unlock := g.budgets.lock(c.session.ID)
	defer unlock()
	began := time.Now()
	e := g.entry(c, ToolListDevices, input)
	if c.technician {
		e.Client = g.auditClient(ctx, c)
	}
	out, cerr := func() (*mcp.CallToolResult, *callError) {
		client, cerr := g.admitClient(ctx, c, clientSlug)
		if cerr != nil {
			return nil, cerr
		}
		e.Client = client.Slug
		devs, err := g.dir.Devices(ctx, client.Slug)
		if err != nil {
			g.log.Error("gateway: device lookup failed", "client", client.Slug, "err", err)
			return nil, failed(proto.ErrInternal, "device lookup failed")
		}
		raw, err := json.Marshal(deviceList(client, devs, g.now()))
		if err != nil {
			return nil, failed(proto.ErrInternal, "could not encode the device list")
		}
		e.Bytes, e.SHA256 = int64(len(raw)), sha256Hex(raw)
		return jsonResult(raw), nil
	}()
	e.DurationMS = time.Since(began).Milliseconds()
	return g.finish(ctx, c, &e, out, cerr)
}

// auditClient chooses a stable authorized audit partition for a technician
// call before its target ACL is known. A successful admission replaces it
// with the target client. This records cross-client probes in an authorized
// client's chain and never writes them into the probed client's chain.
func (g *Gateway) auditClient(ctx context.Context, c caller) string {
	clients, err := g.acl.ClientsForTechnician(ctx, c.session.Tech)
	if err != nil || len(clients) == 0 {
		return ""
	}
	slices.SortFunc(clients, func(a, b model.Client) int { return strings.Compare(a.Slug, b.Slug) })
	return clients[0].Slug
}

// ClientView deliberately contains no policy or device details. Those remain
// behind list_devices and another ACL check.
type ClientView struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

func (g *Gateway) listClients(ctx context.Context, c caller, input json.RawMessage) *mcp.CallToolResult {
	if err := c.session.Valid(g.now()); err != nil {
		return toolError(proto.ErrUnauthorized, "this session is "+err.Error())
	}
	clients := []model.Client{c.client}
	if c.technician {
		var err error
		clients, err = g.acl.ClientsForTechnician(ctx, c.session.Tech)
		if err != nil {
			g.log.Error("gateway: technician ACL lookup failed", "technician", c.session.Tech, "err", err)
			return toolError(proto.ErrInternal, "client authorization lookup failed")
		}
	}
	views := make([]ClientView, 0, len(clients))
	for _, client := range clients {
		if !client.Disabled {
			views = append(views, ClientView{Slug: client.Slug, Name: client.Name})
		}
	}
	slices.SortFunc(views, func(a, b ClientView) int { return strings.Compare(a.Slug, b.Slug) })
	raw, err := json.Marshal(struct {
		Clients []ClientView `json:"clients"`
	}{Clients: views})
	if err != nil {
		return toolError(proto.ErrInternal, "could not encode client list")
	}
	// The audit store is client-partitioned. Record this cross-client control
	// call in every visible client's chain without exposing one client's name
	// in another client's record.
	for _, client := range clients {
		if client.Disabled {
			continue
		}
		e := audit.Entry{Kind: audit.KindTool, Client: client.Slug, Tech: c.session.Tech,
			SessionID: c.session.ID, Tool: ToolListClients, Args: input, Result: audit.ResultOK,
			Bytes: int64(len(raw)), SHA256: sha256Hex(raw)}
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
		err := g.audit.Append(actx, &e)
		cancel()
		if err != nil {
			return toolError(proto.ErrAuditFailed, "the call could not be recorded in every visible client's audit log")
		}
	}
	return jsonResult(raw)
}

// DeviceView is one machine in the list_devices result.
type DeviceView struct {
	ID           string     `json:"id"`
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	OSVersion    string     `json:"os_version,omitempty"`
	Online       bool       `json:"online"`
	LastSeen     *time.Time `json:"last_seen,omitempty"`
	AgentVersion string     `json:"agent_version,omitempty"`
}

// DeviceList is the list_devices result: the client's usable machines and,
// for each OS among them, the locations Keyhole may read.
type DeviceList struct {
	Client       string                       `json:"client"`
	Devices      []DeviceView                 `json:"devices"`
	AllowedPaths map[string][]proto.AllowRule `json:"allowed_paths"`
}

func deviceList(client model.Client, devs []model.Device, now time.Time) DeviceList {
	out := DeviceList{Client: client.Slug, Devices: []DeviceView{}, AllowedPaths: map[string][]proto.AllowRule{}}
	for _, d := range devs {
		// An expired temporary install is gone as far as the AI is concerned,
		// whether or not the reconcile loop has revoked it yet.
		if d.Client != client.Slug || d.RevokedAt != nil || d.Expired(now) {
			continue
		}
		out.Devices = append(out.Devices, DeviceView{ID: d.ID, Hostname: d.Hostname, OS: d.OS, OSVersion: d.OSVersion,
			Online: d.Online(now), LastSeen: d.LastSeen, AgentVersion: d.AgentVersion})
		if _, ok := out.AllowedPaths[d.OS]; !ok {
			rules := client.Policy.For(d.OS).Allow
			if rules == nil {
				rules = []proto.AllowRule{} // "nothing", not "unknown"
			}
			out.AllowedPaths[d.OS] = rules
		}
	}
	slices.SortFunc(out.Devices, func(a, b DeviceView) int {
		return cmp.Or(strings.Compare(strings.ToLower(a.Hostname), strings.ToLower(b.Hostname)), strings.Compare(a.ID, b.ID))
	})
	return out
}

func (g *Gateway) entry(c caller, tool string, input json.RawMessage) audit.Entry {
	return audit.Entry{Kind: audit.KindTool, Client: c.client.Slug, Tech: c.session.Tech, SessionID: c.session.ID,
		Tool: tool, Args: input}
}

// finish audits the call and only then returns its content. If the entry
// cannot be written, the content is dropped.
func (g *Gateway) finish(ctx context.Context, c caller, e *audit.Entry, out *mcp.CallToolResult, cerr *callError) *mcp.CallToolResult {
	e.Result = audit.ResultOK
	if cerr != nil {
		e.Result, e.ErrorCode, e.ErrorMessage = cerr.result, cerr.code, cerr.msg
		e.Bytes, e.SHA256 = 0, ""
	}
	// A technician with no remaining client ACL has no tenant audit chain in
	// which this denied call can truthfully be recorded. It is still refused
	// and logged; no endpoint or client data has been reached.
	if e.Client == "" && cerr != nil {
		g.log.Info("gateway: refused unassigned technician", "tech", e.Tech, "session", e.SessionID, "tool", e.Tool, "code", e.ErrorCode)
		return toolError(cerr.code, cerr.msg)
	}
	// The record is written even if Claude has gone away mid-call.
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := g.audit.Append(actx, e); err != nil {
		g.log.Error("gateway: audit append failed; result withheld", "client", e.Client, "tool", e.Tool,
			"device", e.DeviceID, "request", e.RequestID, "err", err)
		return toolError(proto.ErrAuditFailed, "the call could not be recorded in the audit log, so its result was withheld")
	}
	g.log.Info("gateway: tool call", "client", e.Client, "tech", e.Tech, "session", e.SessionID, "tool", e.Tool,
		"device", e.DeviceID, "result", e.Result, "code", e.ErrorCode, "bytes", e.Bytes, "n", e.N)
	if cerr != nil {
		return toolError(cerr.code, cerr.msg)
	}
	g.budgets.add(c.session, e.Bytes, g.now())
	return out
}

// admit preserves the legacy client-bound path.
func (g *Gateway) admit(ctx context.Context, c caller) (model.Client, *callError) {
	return g.admitClient(ctx, c, "")
}

// admitClient rechecks identity, ACL and the client kill switch on every call.
func (g *Gateway) admitClient(ctx context.Context, c caller, slug string) (model.Client, *callError) {
	if err := c.session.Valid(g.now()); err != nil {
		return model.Client{}, denied(proto.ErrUnauthorized, "this session is "+err.Error())
	}
	if c.technician {
		if strings.TrimSpace(slug) == "" {
			return model.Client{}, failed(proto.ErrBadRequest, "client is required; call list_clients")
		}
		allowed, err := g.acl.TechnicianCanAccess(ctx, c.session.Tech, slug)
		if err != nil {
			g.log.Error("gateway: technician ACL lookup failed", "technician", c.session.Tech, "client", slug, "err", err)
			return model.Client{}, failed(proto.ErrInternal, "client authorization lookup failed")
		}
		if !allowed {
			return model.Client{}, denied(proto.ErrUnauthorized, "client not found or not authorized")
		}
	} else {
		if slug != "" && slug != c.client.Slug {
			return model.Client{}, denied(proto.ErrUnauthorized, "client not found or not authorized")
		}
		slug = c.client.Slug
	}
	client, err := g.dir.Client(ctx, slug)
	switch {
	case errors.Is(err, model.ErrNotFound):
		return model.Client{}, denied(proto.ErrUnauthorized, "client not found or not authorized")
	case err != nil:
		g.log.Error("gateway: client lookup failed", "client", slug, "err", err)
		return model.Client{}, failed(proto.ErrInternal, "client lookup failed")
	case client.Disabled:
		return client, denied(proto.ErrClientDisabled, "the MSP has switched off AI access for this client")
	}
	return client, nil
}

// resolveDevice finds the device argument among client's devices only: an
// exact device ID, or else a case-insensitive hostname. A device in another
// client is indistinguishable from one that does not exist.
func (g *Gateway) resolveDevice(ctx context.Context, client, arg string) (model.Device, *callError) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return model.Device{}, failed(proto.ErrBadRequest, "device is required; call list_devices to see this client's machines")
	}
	devs, err := g.dir.Devices(ctx, client)
	if err != nil {
		g.log.Error("gateway: device lookup failed", "client", client, "err", err)
		return model.Device{}, failed(proto.ErrInternal, "device lookup failed")
	}
	devs = slices.DeleteFunc(devs, func(d model.Device) bool { return d.Client != client })
	if i := slices.IndexFunc(devs, func(d model.Device) bool { return d.ID == arg }); i >= 0 {
		return devs[i], nil
	}
	var live, revoked []model.Device
	for _, d := range devs {
		switch {
		case !strings.EqualFold(d.Hostname, arg):
		case d.RevokedAt == nil:
			live = append(live, d)
		default:
			revoked = append(revoked, d)
		}
	}
	switch {
	case len(live) == 1:
		return live[0], nil
	case len(live) > 1:
		ids := make([]string, len(live))
		for i, d := range live {
			ids[i] = d.ID
		}
		return model.Device{}, failed(proto.ErrAmbiguous, fmt.Sprintf("%d machines are named %q (%s); pass a device ID instead", len(live), arg, strings.Join(ids, ", ")))
	case len(revoked) > 0: // only revoked enrollments carry this name: report the latest
		return slices.MaxFunc(revoked, func(a, b model.Device) int { return a.EnrolledAt.Compare(b.EnrolledAt) }), nil
	}
	return model.Device{}, denied(proto.ErrUnknownDevice, fmt.Sprintf("no machine %q in this client; call list_devices to see its machines", arg))
}

func offlineMessage(d model.Device) string {
	if d.LastSeen == nil {
		return deviceLabel(d) + " has never connected"
	}
	return fmt.Sprintf("%s has not been heard from since %s", deviceLabel(d), d.LastSeen.UTC().Format(time.RFC3339))
}

// rpc sends req to the device through the relay's connection in client's
// account, which cannot reach any other client's subjects.
func (g *Gateway) rpc(ctx context.Context, client, deviceID string, req proto.Request) (*proto.Response, *callError) {
	nc, err := g.conns.Conn(client)
	if err != nil {
		g.log.Error("gateway: no relay connection for client", "client", client, "err", err)
		return nil, failed(proto.ErrInternal, "the relay has no connection to this client")
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, failed(proto.ErrInternal, "could not encode the request")
	}
	rctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	msg, err := nc.RequestWithContext(rctx, proto.RPCSubject(deviceID, req.Op), data)
	switch {
	case err == nil:
	case errors.Is(err, nats.ErrNoResponders):
		return nil, failed(proto.ErrDeviceOffline, "the machine's agent is not connected")
	case ctx.Err() != nil:
		return nil, failed(proto.ErrTimeout, "the call was cancelled before the machine answered")
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout):
		return nil, failed(proto.ErrDeviceOffline, fmt.Sprintf("the machine did not answer within %s", g.timeout))
	default:
		g.log.Error("gateway: request to device failed", "client", client, "device", deviceID, "err", err)
		return nil, failed(proto.ErrInternal, "the request to the machine failed")
	}
	var resp proto.Response
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return nil, failed(proto.ErrInternal, "the machine sent a malformed response")
	}
	if resp.ID != req.ID {
		return nil, failed(proto.ErrInternal, "the machine answered a different request")
	}
	return &resp, nil
}

// checkIntegrity recomputes Meta.Bytes and Meta.SHA256 over the exact Result
// bytes, which are what the AI receives and what the audit entry vouches for.
func checkIntegrity(r *proto.Response) *callError {
	got := sha256Hex(r.Result)
	if r.Meta.SHA256 == got && r.Meta.Bytes == int64(len(r.Result)) {
		return nil
	}
	return failed(proto.ErrInternal, fmt.Sprintf(
		"integrity check failed: the agent reported %d bytes with sha256 %s but the relay received %d bytes with sha256 %s; nothing was returned",
		r.Meta.Bytes, r.Meta.SHA256, len(r.Result), got))
}

// agentError maps an agent refusal to a denial and anything else to an error.
func agentError(e *proto.Error) *callError {
	if e == nil {
		return failed(proto.ErrInternal, "the agent reported a failure without saying why")
	}
	switch e.Code {
	case proto.ErrNotAllowed, proto.ErrHardDenied, proto.ErrUnsafePath:
		return denied(e.Code, e.Message)
	}
	return failed(e.Code, e.Message)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
