// Package consentscript is a scriptable stand-in for the Windows consent
// application. It drives the endpoint's asynchronous consent path without a
// desktop: a test decides when and how each request is answered, and can
// pause, resume, terminate, report that nobody is signed in, or make the
// application disappear the way a crash or a sign-out does.
//
// It implements agent.ConsentAdapter and is used by the relay and end-to-end
// tests, which must run on macOS and Linux.
package consentscript

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Adapter hands out one Conversation per access request.
type Adapter struct {
	mu       sync.Mutex
	convs    map[string]*Conversation
	arrivals chan *Conversation
	acts     []proto.ConsentActivity
	refuse   error // Request fails: no consent application at all
}

// New returns an adapter that presents every request and waits to be told
// what the endpoint user decided.
func New() *Adapter {
	return &Adapter{convs: map[string]*Conversation{}, arrivals: make(chan *Conversation, 16)}
}

// Refuse makes every later Request fail, as when no consent application is
// installed or it cannot be started.
func (a *Adapter) Refuse(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refuse = err
}

func (a *Adapter) Request(ctx context.Context, r proto.ConsentRequest) (<-chan proto.ConsentUpdate, error) {
	a.mu.Lock()
	if a.refuse != nil {
		err := a.refuse
		a.mu.Unlock()
		return nil, err
	}
	c := &Conversation{Request: r, updates: make(chan proto.ConsentUpdate, 8), ctx: ctx}
	if old := a.convs[r.AccessID]; old != nil {
		old.close() // a repeat presentation replaces the one on screen
	}
	a.convs[r.AccessID] = c
	a.mu.Unlock()
	select {
	case a.arrivals <- c:
	default:
	}
	return c.updates, nil
}

func (a *Adapter) Activity(act proto.ConsentActivity) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.acts = append(a.acts, act)
}

// Activity returns every operation the endpoint has shown, in order.
func (a *Adapter) Activities() []proto.ConsentActivity {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.acts)
}

// Next waits for the next request to be presented.
func (a *Adapter) Next(ctx context.Context) (*Conversation, error) {
	select {
	case c := <-a.arrivals:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Wait returns the conversation for accessID once it has been presented.
func (a *Adapter) Wait(ctx context.Context, accessID string) (*Conversation, error) {
	return a.WaitAfter(ctx, accessID, nil)
}

// WaitAfter returns the conversation for accessID once it is not prev, which
// is how a test waits for the endpoint to present a grant again after the
// consent application went away.
func (a *Adapter) WaitAfter(ctx context.Context, accessID string, prev *Conversation) (*Conversation, error) {
	for {
		a.mu.Lock()
		c := a.convs[accessID]
		a.mu.Unlock()
		if c != nil && c != prev {
			return c, nil
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("consentscript: no request for " + accessID)
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// Conversation is one access request on screen and everything the endpoint
// user does with it afterwards.
type Conversation struct {
	Request proto.ConsentRequest

	mu      sync.Mutex
	updates chan proto.ConsentUpdate
	ctx     context.Context
	decided bool
	closed  bool
}

// Waiting reports why the request is still undecided, e.g. proto.ReasonNoUser
// while nobody is signed in. The endpoint uses the last reason it was given
// when its own consent deadline runs out.
func (c *Conversation) Waiting(reason string) {
	c.send(proto.ConsentUpdate{State: proto.ConsentAwaiting, Reason: reason})
}

// Approve grants exactly what was requested.
func (c *Conversation) Approve(approver string) { c.ApproveFrom(approver, "") }

// ApproveFrom grants what was requested and records the OS session the
// approver answered in. A second decision on the same request is ignored,
// which is how the first session to answer wins.
func (c *Conversation) ApproveFrom(approver, session string) {
	c.decide(proto.ConsentUpdate{State: proto.ConsentApproved, Approver: approver, ApproverSession: session,
		Paths: slices.Clone(c.Request.Paths), Operations: slices.Clone(c.Request.Operations)})
}

// Narrow approves a subset of the requested paths.
func (c *Conversation) Narrow(approver string, paths ...string) {
	c.decide(proto.ConsentUpdate{State: proto.ConsentNarrowed, Approver: approver,
		Paths: slices.Clone(paths), Operations: slices.Clone(c.Request.Operations)})
}

// Widen approves more than was requested. The endpoint must refuse it.
func (c *Conversation) Widen(approver string, paths ...string) {
	c.decide(proto.ConsentUpdate{State: proto.ConsentApproved, Approver: approver,
		Paths: slices.Clone(paths), Operations: slices.Clone(c.Request.Operations)})
}

// Deny refuses the request.
func (c *Conversation) Deny(approver, reason string) {
	c.decide(proto.ConsentUpdate{State: proto.ConsentDenied, Approver: approver, Reason: reason})
}

// Pause makes an approved grant temporarily unusable.
func (c *Conversation) Pause() { c.send(proto.ConsentUpdate{State: proto.ConsentPaused}) }

// Resume returns a paused grant to use with the same capability.
func (c *Conversation) Resume() {
	c.send(proto.ConsentUpdate{State: proto.ConsentApproved, Approver: "resumed",
		Paths: slices.Clone(c.Request.Paths), Operations: slices.Clone(c.Request.Operations)})
}

// Terminate ends the grant from the endpoint, e.g. because the user pressed
// Terminate (proto.ReasonUser) or signed out (proto.ReasonLogoff).
func (c *Conversation) Terminate(reason string) {
	c.send(proto.ConsentUpdate{State: proto.ConsentTerminated, Reason: reason})
}

// Crash makes the consent application disappear without deciding or ending
// anything, as a crash or a sign-out does.
func (c *Conversation) Crash() { c.close() }

// Decided reports whether this request has been answered.
func (c *Conversation) Decided() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.decided
}

func (c *Conversation) decide(u proto.ConsentUpdate) {
	c.mu.Lock()
	if c.decided || c.closed {
		c.mu.Unlock()
		return // first decision wins
	}
	c.decided = true
	c.mu.Unlock()
	c.send(u)
}

func (c *Conversation) send(u proto.ConsentUpdate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	select {
	case c.updates <- u:
	case <-c.ctx.Done():
	}
}

func (c *Conversation) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.updates)
	}
}
