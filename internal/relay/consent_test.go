package relay

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// consentFixture enrolls one device and stores one access request awaiting
// the endpoint user's answer, which is the state request_access leaves
// behind now that consent is asynchronous.
type consentFixture struct {
	h      *harness
	agent  *agent
	device string
	access model.AccessRequest
}

func newConsentFixture(t *testing.T) *consentFixture {
	t.Helper()
	h := newHarness(t)
	h.createClient("acme")
	resp, k := h.enrollDevice(h.mintToken("acme", adminapi.MintTokenRequest{}).Secret, "m-1")
	a := h.connectAgent(resp, k)
	access := h.storeAccess("acc_one", "acme", resp.DeviceID, "tech_alice")
	return &consentFixture{h: h, agent: a, device: resp.DeviceID, access: access}
}

// storeAccess stores an access request awaiting the endpoint user's answer.
func (h *harness) storeAccess(id, client, device, technician string) model.AccessRequest {
	h.t.Helper()
	now := time.Now().UTC()
	deadline := now.Add(proto.ConsentTimeout)
	access := model.AccessRequest{ID: id, Client: client, Device: device, Technician: technician,
		Session: "idp_" + technician, Purpose: "diagnose", State: model.AccessAwaiting,
		RequestedScope: []string{`C:\Logs`, `C:\Temp`}, RequestedOperations: []string{proto.OpReadFile},
		RequestedAt: now, ExpiresAt: now.Add(30 * time.Minute), IdleTimeout: 10 * time.Minute,
		PolicyVersion: 1, ConsentDeadline: &deadline}
	if err := h.st.CreateAccess(bg, access); err != nil {
		h.t.Fatal(err)
	}
	return access
}

// publish sends one consent event the way the endpoint does.
func (f *consentFixture) publish(ev proto.ConsentEvent) {
	f.h.t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		f.h.t.Fatal(err)
	}
	if err := f.agent.Publish(proto.EventSubject(f.device, proto.EvtConsent), b); err != nil {
		f.h.t.Fatal(err)
	}
	if err := f.agent.Flush(); err != nil {
		f.h.t.Fatal(err)
	}
}

func (f *consentFixture) state() model.AccessRequest {
	f.h.t.Helper()
	a, err := f.h.st.Access(bg, f.access.ID)
	if err != nil {
		f.h.t.Fatal(err)
	}
	return a
}

func (f *consentFixture) waitState(state string) model.AccessRequest {
	f.h.t.Helper()
	var got model.AccessRequest
	eventually(f.h.t, "access request to become "+state, func() bool {
		got = f.state()
		return got.State == state
	})
	return got
}

func (f *consentFixture) capability(paths []string) *proto.Capability {
	return &proto.Capability{GrantID: "grt_one", AccessID: f.access.ID, Nonce: "nonce_one", Client: "acme",
		Device: f.device, Technician: f.access.Technician, Operations: []string{proto.OpReadFile}, Paths: paths,
		IssuedAt: time.Now().UTC(), ExpiresAt: f.access.ExpiresAt, IdleTimeout: f.access.IdleTimeout, PolicyVersion: 1}
}

// approval is a well-formed approval of paths, as the endpoint sends it.
func (f *consentFixture) approval(seq uint64, paths []string) proto.ConsentEvent {
	return proto.ConsentEvent{AccessID: f.access.ID, Client: "acme", Device: f.device, Technician: f.access.Technician,
		State: proto.ConsentApproved, Approver: `ACME\sam`, Operations: []string{proto.OpReadFile},
		Paths: slices.Clone(paths), Capability: f.capability(slices.Clone(paths)), Seq: seq, Time: time.Now().UTC()}
}

// event is a well-formed transition with no capability, as the endpoint
// sends a pause, a denial or a termination.
func (f *consentFixture) event(seq uint64, state, reason string) proto.ConsentEvent {
	return proto.ConsentEvent{AccessID: f.access.ID, Client: "acme", Device: f.device, Technician: f.access.Technician,
		State: state, Reason: reason, Seq: seq, Time: time.Now().UTC()}
}

// consentEntries returns acme's consent audit entries recorded under tool.
func (f *consentFixture) consentEntries(tool string) []audit.Entry {
	f.h.t.Helper()
	var out []audit.Entry
	for _, e := range f.h.entries("acme") {
		if e.Kind == audit.KindConsent && e.Tool == tool {
			out = append(out, e)
		}
	}
	return out
}

// waitRefusals waits until n endpoint events have been refused. Every
// refusal is audited, so its entry is how a test knows the relay has
// finished with an event it did not apply.
func (f *consentFixture) waitRefusals(n int) []audit.Entry {
	f.h.t.Helper()
	var got []audit.Entry
	eventually(f.h.t, fmt.Sprintf("%d refused consent events", n), func() bool {
		got = f.consentEntries(ConsentRefusedTool)
		return len(got) >= n
	})
	return got
}

// The endpoint's answer arrives as an event, minutes after the request, and
// the relay is what makes it durable and auditable.
func TestEndpointConsentEventIsDurableAndAudited(t *testing.T) {
	f := newConsentFixture(t)
	narrowed := []string{`C:\Logs`}

	// A narrowed approval is two transitions in the record but one write. A
	// reader polling the whole time never sees a narrowed request, which no
	// call could use, or an approval that has no capability yet.
	var seen sync.Map
	stop, polled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(polled)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if a, err := f.h.st.Access(bg, f.access.ID); err == nil {
				seen.Store(a.State, true)
				if a.State == model.AccessApproved && (a.GrantID == "" || a.Nonce == "") {
					seen.Store("approved without a capability", true)
				}
			}
		}
	}()
	ev := f.approval(1, narrowed)
	ev.State, ev.ApproverSession = proto.ConsentNarrowed, "2"
	f.publish(ev)
	got := f.waitState(model.AccessApproved)
	close(stop)
	<-polled
	for _, bad := range []string{model.AccessNarrowed, "approved without a capability"} {
		if _, ok := seen.Load(bad); ok {
			t.Fatalf("a reader observed the request %s", bad)
		}
	}
	switch {
	case !slices.Equal(got.EffectiveScope, narrowed):
		t.Fatalf("effective scope %v", got.EffectiveScope)
	case got.Approver != `ACME\sam` || got.ApproverSession != "2":
		t.Fatalf("approver %q session %q", got.Approver, got.ApproverSession)
	case got.GrantID != "grt_one" || got.Nonce != "nonce_one" || got.DecidedAt == nil:
		t.Fatalf("capability not adopted: %+v", got)
	}
	// Narrowing is two transitions in the record, as it is when the
	// technician's own call produced it.
	for _, state := range []string{model.AccessNarrowed, model.AccessApproved} {
		if n := len(f.consentEntries("access." + state)); n != 1 {
			t.Fatalf("audit has %d access.%s entries, want 1", n, state)
		}
	}

	// Pausing and resuming keep the same capability.
	f.publish(f.event(2, proto.ConsentPaused, proto.ReasonUIGone))
	if paused := f.waitState(model.AccessPaused); paused.PausedAt == nil || paused.Reason != proto.ReasonUIGone {
		t.Fatalf("paused: %+v", paused)
	}
	resume := f.approval(3, narrowed)
	resume.Reason = proto.ReasonUIRestored
	f.publish(resume)
	resumed := f.waitState(model.AccessApproved)
	if resumed.GrantID != "grt_one" || resumed.Nonce != "nonce_one" || resumed.PausedAt != nil ||
		!slices.Equal(resumed.EffectiveScope, narrowed) || resumed.Reason != proto.ReasonUIRestored {
		t.Fatalf("resumed: %+v", resumed)
	}

	// A terminated grant is final: a later approval cannot revive it, and the
	// attempt is on record.
	f.publish(f.event(4, proto.ConsentTerminated, proto.ReasonUser))
	if ended := f.waitState(model.AccessTerminated); ended.TerminatedAt == nil || ended.Reason != proto.ReasonUser {
		t.Fatalf("terminated: %+v", ended)
	}
	f.publish(f.approval(5, narrowed))
	refused := f.waitRefusals(1)
	if got := f.state(); got.State != model.AccessTerminated {
		t.Fatalf("a terminated grant was revived: %+v", got)
	}
	if r := refused[0]; !strings.Contains(r.ErrorMessage, "cannot become") || r.RequestID != f.access.ID ||
		r.Tech != f.access.Technician || r.Result != audit.ResultDenied {
		t.Fatalf("revival refusal: %+v", r)
	}
}

// The relay believes the subject, not the payload, and checks every binding
// on the capability the endpoint reports. Every event it turns down is
// refused before anything is stored, and every refusal is audited.
func TestRelayRejectsMismatchedConsentEvents(t *testing.T) {
	f := newConsentFixture(t)
	all := f.access.RequestedScope
	type bad struct {
		name, why string // why is part of the audited reason
		ev        proto.ConsentEvent
	}
	var cases []bad
	add := func(name, why string, mutate func(*proto.ConsentEvent)) {
		ev := f.approval(uint64(len(cases)+1), all)
		mutate(&ev)
		cases = append(cases, bad{name, why, ev})
	}
	add("payload names another client", "another client", func(ev *proto.ConsentEvent) { ev.Client = "beta" })
	add("payload names another device", "another device", func(ev *proto.ConsentEvent) { ev.Device = "dev_elsewhere" })
	add("no capability", "no capability", func(ev *proto.ConsentEvent) { ev.Capability = nil })
	add("no approver", "no approver", func(ev *proto.ConsentEvent) { ev.Approver = "" })
	add("another access ID", string(noSuchRequest), func(ev *proto.ConsentEvent) { ev.AccessID = "acc_other" })
	add("capability for another access request", "another access request", func(ev *proto.ConsentEvent) {
		ev.Capability.AccessID = "acc_other"
	})
	add("capability outlives the request", "outlives", func(ev *proto.ConsentEvent) {
		ev.Capability.ExpiresAt = f.access.ExpiresAt.Add(time.Hour)
	})
	add("capability bound to another device", "another device", func(ev *proto.ConsentEvent) {
		ev.Capability.Device = "dev_elsewhere"
	})
	add("capability bound to another client", "another client", func(ev *proto.ConsentEvent) { ev.Capability.Client = "beta" })
	add("capability bound to another technician", "another technician", func(ev *proto.ConsentEvent) {
		ev.Capability.Technician = "tech_mallory"
	})
	add("event names another technician", "another technician", func(ev *proto.ConsentEvent) { ev.Technician = "tech_mallory" })
	add("no nonce", "nonce", func(ev *proto.ConsentEvent) { ev.Capability.Nonce = "" })
	add("another policy version", "policy version", func(ev *proto.ConsentEvent) { ev.Capability.PolicyVersion = 2 })
	add("longer idle timeout", "idle timeout", func(ev *proto.ConsentEvent) { ev.Capability.IdleTimeout = time.Hour })
	add("path above the request", "outside the request", func(ev *proto.ConsentEvent) {
		ev.Paths, ev.Capability.Paths = []string{`C:\`}, []string{`C:\`}
	})
	add("sibling of a requested path", "outside the request", func(ev *proto.ConsentEvent) {
		ev.Paths, ev.Capability.Paths = []string{`C:\LogsOther`}, []string{`C:\LogsOther`}
	})
	add("operation that was not requested", "not requested", func(ev *proto.ConsentEvent) {
		ops := []string{proto.OpReadFile, proto.OpGrep}
		ev.Operations, ev.Capability.Operations = ops, slices.Clone(ops)
	})
	add("event and capability disagree", "disagree", func(ev *proto.ConsentEvent) { ev.Paths = []string{`C:\Logs`} })
	add("unsequenced approval", "sequence number", func(ev *proto.ConsentEvent) { ev.Seq = 0 })
	add("endpoint claims active", "cannot report", func(ev *proto.ConsentEvent) { ev.State = model.AccessActive })
	add("endpoint claims expired", "cannot report", func(ev *proto.ConsentEvent) { ev.State = model.AccessExpired })
	add("pause before any decision", "cannot become paused", func(ev *proto.ConsentEvent) {
		ev.State, ev.Capability = proto.ConsentPaused, nil
	})

	for i, c := range cases {
		c.ev.Time = time.Now().UTC()
		f.publish(c.ev)
		refused := f.waitRefusals(i + 1)
		r := refused[len(refused)-1]
		if !strings.Contains(r.ErrorMessage, c.why) {
			t.Errorf("%s: refused because %q, want a reason mentioning %q", c.name, r.ErrorMessage, c.why)
		}
		if r.Client != "acme" || r.DeviceID != f.device || r.Result != audit.ResultDenied || r.ErrorCode != proto.ErrGrantInvalid {
			t.Errorf("%s: refusal entry %+v", c.name, r)
		}
		if got := f.state(); got.State != model.AccessAwaiting || got.GrantID != "" || got.EventSeq != 0 {
			t.Fatalf("%s moved the request: %+v", c.name, got)
		}
	}

	// A waiting update only records why the endpoint is still waiting.
	f.publish(f.event(0, proto.ConsentAwaiting, proto.ReasonNoUser))
	eventually(t, "the waiting reason to be recorded", func() bool { return f.state().Reason == proto.ReasonNoUser })
	if got := f.state(); got.State != model.AccessAwaiting {
		t.Fatalf("a waiting update changed the state: %+v", got)
	}

	// A well-formed approval is accepted; delivering it again is refused.
	good := f.approval(100, all)
	f.publish(good)
	approved := f.waitState(model.AccessApproved)
	f.publish(good)
	refused := f.waitRefusals(len(cases) + 1)
	if r := refused[len(refused)-1]; !strings.Contains(r.ErrorMessage, "not newer") {
		t.Fatalf("replayed approval refused because %q", r.ErrorMessage)
	}
	if got := f.state(); got.State != model.AccessApproved || got.GrantID != approved.GrantID || got.EventSeq != 100 {
		t.Fatalf("a replayed approval changed the grant: %+v", got)
	}
	if n := len(f.consentEntries("access." + model.AccessApproved)); n != 1 {
		t.Fatalf("audit has %d approvals, want exactly the one applied", n)
	}
	if n := len(f.consentEntries("access." + model.AccessNarrowed)); n != 0 {
		t.Fatalf("an approval of the whole request was recorded as narrowed %d times", n)
	}
}

// A device only ever answers for its own client's requests. An event naming
// another tenant's request changes nothing there, writes nothing into that
// tenant's audit chain, and copies nothing about it into the sender's.
func TestRelayRefusesConsentForAnotherTenantsRequest(t *testing.T) {
	f := newConsentFixture(t)
	f.h.createClient("globex")
	resp, _ := f.h.enrollDevice(f.h.mintToken("globex", adminapi.MintTokenRequest{}).Secret, "g-1")
	theirs := f.h.storeAccess("acc_globex", "globex", resp.DeviceID, "tech_bob")
	before := len(f.h.entries("globex"))

	ev := f.approval(1, theirs.RequestedScope)
	ev.AccessID, ev.Capability.AccessID = theirs.ID, theirs.ID
	f.publish(ev)
	refused := f.waitRefusals(1)

	stored, err := f.h.st.Access(bg, theirs.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != model.AccessAwaiting || stored.GrantID != "" {
		t.Fatalf("another tenant's request moved: %+v", stored)
	}
	if n := len(f.h.entries("globex")); n != before {
		t.Fatalf("the refusal wrote %d entries into the other tenant's chain", n-before)
	}
	r := refused[0]
	if r.ErrorMessage != string(noSuchRequest) || r.Tech != "" || r.SessionID != "" ||
		strings.Contains(string(r.Args), "tech_bob") || strings.Contains(string(r.Args), "globex") {
		t.Fatalf("the refusal copied the other tenant's details: %+v", r)
	}
}

// TestAccessAdvanceRules pins the one transition rule every writer uses. The
// property that matters most is checked last: every state a request can
// rest in can still be denied, terminated and expired, so no grant is ever
// out of reach of the fail-closed exits.
func TestAccessAdvanceRules(t *testing.T) {
	exits := []string{model.AccessDenied, model.AccessExpired, model.AccessTerminated}
	allowed := map[string][]string{
		model.AccessRequested: append([]string{model.AccessAwaiting}, exits...),
		model.AccessAwaiting:  append([]string{model.AccessNarrowed, model.AccessApproved}, exits...),
		model.AccessNarrowed:  append([]string{model.AccessApproved, model.AccessPaused}, exits...),
		model.AccessApproved:  append([]string{model.AccessActive, model.AccessPaused}, exits...),
		model.AccessActive:    append([]string{model.AccessPaused}, exits...),
		model.AccessPaused:    append([]string{model.AccessApproved}, exits...),
	}
	states := []string{model.AccessRequested, model.AccessAwaiting, model.AccessApproved, model.AccessNarrowed,
		model.AccessActive, model.AccessPaused, model.AccessDenied, model.AccessExpired, model.AccessTerminated}
	for _, cur := range states {
		for _, next := range states {
			want := slices.Contains(allowed[cur], next)
			if got := model.AccessAdvance(cur, next); got != want {
				t.Errorf("AccessAdvance(%q, %q) = %t, want %t", cur, next, got, want)
			}
		}
	}
	for _, cur := range states {
		if model.AccessTerminal(cur) != slices.Contains(exits, cur) {
			t.Errorf("AccessTerminal(%q) = %t", cur, model.AccessTerminal(cur))
		}
		if model.AccessTerminal(cur) {
			continue
		}
		for _, exit := range exits {
			if !model.AccessAdvance(cur, exit) {
				t.Errorf("a request that is %s can never become %s", cur, exit)
			}
		}
	}
}
