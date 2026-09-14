package fstools

import (
	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Service operations are Change-level authority over a named service and
// nothing else: there is no command line, no arguments, and no way to reach a
// service the client's policy does not list. Restarting is gated three times —
// the capability must contain the op, the client policy must name the service,
// and the agent's compiled-in deny list must not refuse it — and it is
// serialised with file changes, one mutating operation at a time per device.

func (c *call) serviceQuery(a proto.ServiceQueryArgs) (proto.ServiceResult, error) {
	cc, err := c.change()
	if err != nil {
		return proto.ServiceResult{}, err
	}
	if err := cc.checkService(a.Name, false); err != nil {
		return proto.ServiceResult{}, err
	}
	res, err := queryService(cc.ctx, a.Name)
	if err != nil {
		return proto.ServiceResult{}, err
	}
	res.CheckedAt = cc.now
	cc.noteChange(proto.ChangeMeta{Service: a.Name})
	return res, nil
}

func (c *call) serviceRestart(a proto.ServiceRestartArgs) (proto.ServiceResult, error) {
	var zero, out proto.ServiceResult
	cc, err := c.change()
	if err != nil {
		return zero, err
	}
	if err := cc.checkService(a.Name, true); err != nil {
		return zero, err
	}
	replayed, err := cc.replay(&out)
	if err != nil {
		return zero, err
	}
	if replayed {
		cc.noteChange(proto.ChangeMeta{Service: a.Name, Replayed: true})
		return out, nil
	}
	if !cc.store.mu.TryLock() {
		return zero, failf(proto.ErrConflict, "another change is in progress on this machine; retry when it finishes")
	}
	defer cc.store.mu.Unlock()
	if err := cc.store.charge(cc.key, 1, 0); err != nil {
		return zero, err
	}
	// A restart cannot be undone by writing bytes back, so the journal records
	// it the moment it is attempted: a retry of the same request ID reports
	// the recorded outcome instead of restarting the service twice.
	if err := cc.intent("", "", ""); err != nil {
		return zero, err
	}
	out, err = restartService(cc.ctx, a.Name)
	if err != nil {
		return zero, err
	}
	out.CheckedAt, out.Restarted = cc.now, true
	change := proto.ChangeMeta{Service: a.Name}
	if err := cc.commit("", out, change); err != nil {
		return zero, err
	}
	cc.noteChange(change)
	return out, nil
}

// checkService applies the name's shape, the client policy's allow list and,
// for a restart, the compiled-in deny list. A query is state only, so the deny
// list does not hide a service the policy deliberately lists.
func (cc *changeCall) checkService(name string, restart bool) error {
	if err := policy.CheckServiceName(name); err != nil {
		return failf(proto.ErrBadRequest, "%v", err)
	}
	if !policy.ServiceAllowed(cc.pol.ServiceAllow, name) {
		return failf(proto.ErrNotAllowed, "%s is not one of the services this client's policy allows Keyhole to touch", name)
	}
	if restart {
		if id, denied := policy.ServiceDenied(cc.goos, name); denied {
			cc.meta.RuleID = id
			return failf(proto.ErrChangeDenied, "%s is on the agent's service deny list (%s); it can never be restarted through Keyhole", name, id)
		}
	}
	return nil
}

// serviceState normalises a platform's own state names.
func serviceState(running, stopped, starting, stopping bool) string {
	switch {
	case running:
		return proto.ServiceRunning
	case stopped:
		return proto.ServiceStopped
	case starting:
		return proto.ServiceStarting
	case stopping:
		return proto.ServiceStopping
	}
	return proto.ServiceUnknown
}
