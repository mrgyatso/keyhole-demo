package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/agent/consentscript"
	"github.com/mrgyatso/keyhole/internal/fstools"
	"github.com/mrgyatso/keyhole/internal/proto"
)

var discard = slog.New(slog.DiscardHandler)

// signedUnlock is the unlock the relay attaches to cr once the technician has
// approved it with a passkey. The assertion is marked so a test can tell if
// it ever reaches a log.
func signedUnlock(cr proto.ConsentRequest, expires time.Time) *proto.TechnicianApproval {
	return &proto.TechnicianApproval{Kind: proto.ApprovalUnlock, ID: "unl_one", Technician: cr.Technician, Client: cr.Client,
		Purpose: cr.Purpose, Nonce: "nonce-one", ExpiresAt: expires,
		Credential: "Y3JlZGVudGlhbC1vbmU", ApprovedAt: expires.Add(-time.Hour),
		Assertion: &proto.PasskeyAssertion{CredentialID: "Y3JlZGVudGlhbC1vbmU", AuthenticatorData: []byte("SECRET-authenticator-data"),
			ClientDataJSON: []byte(`{"type":"webauthn.get","challenge":"SECRET-challenge"}`), Signature: []byte("SECRET-signature")}}
}

// technicianRequest is an access request the relay forwards under an active
// unlock of its client.
func technicianRequest() proto.ConsentRequest {
	cr := consentRequest()
	cr.Approval = signedUnlock(cr, time.Now().Add(30*time.Minute))
	return cr
}

func TestTechnicianConsent(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	skew := proto.ApprovalClockSkew
	cases := []struct {
		name   string
		change func(cr *proto.ConsentRequest)
		ok     bool
	}{
		{"valid", func(*proto.ConsentRequest) {}, true},
		{"no approval", func(cr *proto.ConsentRequest) { cr.Approval = nil }, false},
		{"a change approval", func(cr *proto.ConsentRequest) { cr.Approval.Kind = proto.ApprovalChange }, false},
		{"no unlock ID", func(cr *proto.ConsentRequest) { cr.Approval.ID = "" }, false},
		{"unsigned: no credential", func(cr *proto.ConsentRequest) { cr.Approval.Credential = "" }, false},
		{"unsigned: no approval time", func(cr *proto.ConsentRequest) { cr.Approval.ApprovedAt = time.Time{} }, false},
		{"another client", func(cr *proto.ConsentRequest) { cr.Approval.Client = "globex" }, false},
		{"another technician", func(cr *proto.ConsentRequest) { cr.Approval.Technician = "bob" }, false},
		{"expired beyond the skew", func(cr *proto.ConsentRequest) { cr.Approval.ExpiresAt = now.Add(-skew - time.Second) }, false},
		{"expired exactly at the skew", func(cr *proto.ConsentRequest) { cr.Approval.ExpiresAt = now.Add(-skew) }, false},
		{"expired, but within the skew", func(cr *proto.ConsentRequest) {
			cr.Approval.ExpiresAt, cr.ExpiresAt = now.Add(-time.Minute), now.Add(30*time.Second)
		}, true},
		{"a grant that outlives the unlock", func(cr *proto.ConsentRequest) { cr.ExpiresAt = cr.Approval.ExpiresAt.Add(skew + time.Second) }, false},
		{"a grant that ends within the skew", func(cr *proto.ConsentRequest) { cr.ExpiresAt = cr.Approval.ExpiresAt.Add(skew) }, true},
		{"a duration that outlives the unlock", func(cr *proto.ConsentRequest) {
			cr.ExpiresAt, cr.Duration, cr.Approval.ExpiresAt = time.Time{}, time.Hour, now.Add(10*time.Minute)
		}, false},
		{"a duration within the unlock", func(cr *proto.ConsentRequest) { cr.ExpiresAt, cr.Duration = time.Time{}, 5*time.Minute }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cr := consentRequest()
			cr.ExpiresAt = now.Add(20 * time.Minute)
			cr.Approval = signedUnlock(cr, now.Add(30*time.Minute))
			c.change(&cr)
			ch, err := TechnicianConsent{Now: func() time.Time { return now }, Logger: discard}.Request(context.Background(), cr)
			if !c.ok {
				if err == nil || ch != nil {
					t.Fatalf("approved: err=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			u, open := <-ch
			switch {
			case !open:
				t.Fatal("no decision")
			case u.State != proto.ConsentApproved || !u.Final:
				t.Errorf("decision %+v; want a final approval", u)
			case u.Approver != cr.Approval.ApproverLabel():
				t.Errorf("approver %q; want %q", u.Approver, cr.Approval.ApproverLabel())
			case !slices.Equal(u.Paths, cr.Paths) || !slices.Equal(u.Operations, cr.Operations):
				t.Errorf("approved %v %v; want exactly what was requested", u.Paths, u.Operations)
			}
			if _, open := <-ch; open {
				t.Error("the channel carried more than the one decision")
			}
		})
	}
}

// lockedBuffer collects log output written from several goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// The assertion is the technician's signature. Nothing the endpoint logs,
// for an approval or a refusal, may carry it.
func TestTechnicianUnlockNeverReachesTheLogs(t *testing.T) {
	var out lockedBuffer
	log := slog.New(slog.NewJSONHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r := consentRunner(RoutedConsent{Technician: TechnicianConsent{Logger: log}})
	r.log = log
	cr := technicianRequest()
	ack(t, r, cr)
	waitGrant(t, r, cr.AccessID, proto.ConsentApproved)
	refused := technicianRequest()
	refused.AccessID, refused.Approval.Client = "acc_two", "globex"
	if resp := r.consent(context.Background(), refused); resp.Error == nil {
		t.Fatal("an unlock for another client was accepted")
	}
	logs := out.String()
	if !strings.Contains(logs, "unl_one") {
		t.Fatalf("the test logged nothing about the unlock:\n%s", logs)
	}
	if strings.Contains(logs, "SECRET") || strings.Contains(logs, "U0VDUkVU") { // "SECRET" in base64
		t.Errorf("the assertion reached the logs:\n%s", logs)
	}
}

// probe is a consent adapter that only records what reached it.
type probe struct {
	mu   sync.Mutex
	reqs []string
	acts []string
}

func (p *probe) Request(_ context.Context, cr proto.ConsentRequest) (<-chan proto.ConsentUpdate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reqs = append(p.reqs, cr.AccessID)
	ch := make(chan proto.ConsentUpdate)
	close(ch)
	return ch, nil
}

func (p *probe) Activity(a proto.ConsentActivity) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.acts = append(p.acts, a.AccessID)
}

func (p *probe) seen() ([]string, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.reqs), slices.Clone(p.acts)
}

func TestRoutedConsent(t *testing.T) {
	legacy := consentRequest()
	unlocked := technicianRequest()
	both := technicianRequest()
	both.EndpointConsent = true
	badBoth := both
	bad := *both.Approval
	bad.Client = "globex"
	badBoth.Approval = &bad
	expiredBoth := both
	expired := *both.Approval
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	expiredBoth.Approval = &expired

	cases := []struct {
		name                   string
		noTechnician, noWindow bool
		cr                     proto.ConsentRequest
		want                   string // "technician", "endpoint", or "" for a refusal
	}{
		{"no unlock goes to the consent window", false, false, legacy, "endpoint"},
		{"no unlock and no consent window is refused", false, true, legacy, ""},
		{"an unlock alone is approved by the technician adapter", false, false, unlocked, "technician"},
		{"an unlock alone needs no consent window", false, true, unlocked, "technician"},
		{"an unlock without a technician adapter is refused", true, false, unlocked, ""},
		{"an unlock the policy also puts to the machine goes to the window", false, false, both, "endpoint"},
		{"endpoint consent without a window is refused", false, true, both, ""},
		{"endpoint consent under another client's unlock is refused", false, false, badBoth, ""},
		{"endpoint consent under an expired unlock is refused", false, false, expiredBoth, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tech, window := &probe{}, &probe{}
			rc := RoutedConsent{Technician: tech, Endpoint: window}
			if c.noTechnician {
				rc.Technician = nil
			}
			if c.noWindow {
				rc.Endpoint = nil
			}
			ch, err := rc.Request(context.Background(), c.cr)
			techReqs, _ := tech.seen()
			windowReqs, _ := window.seen()
			switch c.want {
			case "":
				if err == nil || ch != nil {
					t.Fatal("routed a request that should have been refused")
				}
			case "technician":
				if err != nil || len(techReqs) != 1 {
					t.Fatalf("technician adapter saw %v (err %v)", techReqs, err)
				}
			case "endpoint":
				if err != nil || len(windowReqs) != 1 {
					t.Fatalf("consent window saw %v (err %v)", windowReqs, err)
				}
			}
			if c.want != "technician" && len(techReqs) > 0 {
				t.Errorf("the technician adapter saw %v", techReqs)
			}
			if c.want != "endpoint" && len(windowReqs) > 0 {
				t.Errorf("the consent window saw %v", windowReqs)
			}
		})
	}

	t.Run("activity goes to the consent window, if there is one", func(t *testing.T) {
		tech, window := &probe{}, &probe{}
		RoutedConsent{Technician: tech, Endpoint: window}.Activity(proto.ConsentActivity{AccessID: "acc_one"})
		RoutedConsent{Technician: tech}.Activity(proto.ConsentActivity{AccessID: "acc_two"}) // must not panic
		if _, acts := window.seen(); !slices.Equal(acts, []string{"acc_one"}) {
			t.Errorf("consent window was shown %v", acts)
		}
		if _, acts := tech.seen(); len(acts) != 0 {
			t.Errorf("technician adapter was shown %v", acts)
		}
	})
}

func TestTechnicianUnlockMintsAGrantThatRemembersIt(t *testing.T) {
	t.Run("an unlock alone", func(t *testing.T) {
		r := consentRunner(RoutedConsent{Technician: TechnicianConsent{Logger: discard}})
		cr := technicianRequest()
		ack(t, r, cr)
		c := waitGrant(t, r, cr.AccessID, proto.ConsentApproved).cap
		if c.Unlock != cr.Approval.ID || c.EndpointConsent {
			t.Errorf("capability unlock %q endpoint consent %t; want %q and false", c.Unlock, c.EndpointConsent, cr.Approval.ID)
		}
	})
	t.Run("an unlock the person at the machine approved as well", func(t *testing.T) {
		script := consentscript.New()
		r := consentRunner(RoutedConsent{Technician: TechnicianConsent{Logger: discard}, Endpoint: script})
		cr := technicianRequest()
		cr.EndpointConsent = true
		ack(t, r, cr)
		conv, err := script.Wait(context.Background(), cr.AccessID)
		if err != nil {
			t.Fatal(err)
		}
		conv.Approve(`ACME\sam`)
		c := waitGrant(t, r, cr.AccessID, proto.ConsentApproved).cap
		if c.Unlock != cr.Approval.ID || !c.EndpointConsent {
			t.Errorf("capability unlock %q endpoint consent %t; want %q and true", c.Unlock, c.EndpointConsent, cr.Approval.ID)
		}
	})
	t.Run("a legacy request", func(t *testing.T) {
		r := consentRunner(TestConsentAdapter{Approver: "local-user"})
		cr := consentRequest()
		ack(t, r, cr)
		if c := waitGrant(t, r, cr.AccessID, proto.ConsentApproved).cap; c.Unlock != "" || c.EndpointConsent {
			t.Errorf("a legacy grant claims unlock %q endpoint consent %t", c.Unlock, c.EndpointConsent)
		}
	})
	t.Run("an unlock the endpoint refuses leaves no grant", func(t *testing.T) {
		r := consentRunner(RoutedConsent{Technician: TechnicianConsent{Logger: discard}})
		cr := technicianRequest()
		cr.Approval.Client = "globex"
		resp := r.consent(context.Background(), cr)
		if resp.Error == nil || resp.Error.Code != proto.ErrConsentRequired || !strings.Contains(resp.Error.Message, "another client") {
			t.Fatalf("an unlock for another client answered %+v", resp)
		}
		r.grants.mu.Lock()
		_, kept := r.grants.grants[cr.AccessID]
		r.grants.mu.Unlock()
		if kept {
			t.Error("the endpoint kept a grant for a request it refused")
		}
	})
	t.Run("without a consent window a legacy request is refused", func(t *testing.T) {
		r := consentRunner(RoutedConsent{Technician: TechnicianConsent{Logger: discard}})
		if resp := r.consent(context.Background(), consentRequest()); resp.Error == nil || resp.Error.Code != proto.ErrConsentRequired {
			t.Fatalf("a legacy request was accepted with nobody to ask: %+v", resp)
		}
	})
}

// A relay that drops the unlock from a capability, swaps it, or flips
// EndpointConsent would change how the grant's paths apply and whether its
// changes need the technician's approval, so each is a different grant.
func TestAuthorizeComparesTheUnlock(t *testing.T) {
	r := consentRunner(RoutedConsent{Technician: TechnicianConsent{Logger: discard}})
	cr := technicianRequest()
	ack(t, r, cr)
	cap := waitGrant(t, r, cr.AccessID, proto.ConsentApproved).cap
	base := proto.Request{Op: proto.OpReadFile, Caller: proto.Caller{Tech: "alice"}, Capability: &cap}
	if err := r.authorize(&base); err != nil {
		t.Fatalf("the grant as minted: %v", err)
	}
	for name, mutate := range map[string]func(*proto.Capability){
		"no unlock":               func(c *proto.Capability) { c.Unlock = "" },
		"another unlock":          func(c *proto.Capability) { c.Unlock = "unl_other" },
		"endpoint consent turned": func(c *proto.Capability) { c.EndpointConsent = true },
	} {
		c := cap
		mutate(&c)
		req := base
		req.Capability = &c
		if err := r.authorize(&req); err == nil || err.Code != proto.ErrGrantInvalid {
			t.Errorf("%s: accepted", name)
		}
	}

	legacy := consentRunner(TestConsentAdapter{Approver: "local-user"})
	lcr := consentRequest()
	ack(t, legacy, lcr)
	lc := waitGrant(t, legacy, lcr.AccessID, proto.ConsentApproved).cap
	lc.Unlock = "unl_one"
	req := proto.Request{Op: proto.OpReadFile, Caller: proto.Caller{Tech: "alice"}, Capability: &lc}
	if err := legacy.authorize(&req); err == nil || err.Code != proto.ErrGrantInvalid {
		t.Error("a legacy grant presented as an unlocked one was accepted")
	}
}

func writeTestFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// readUnder authorizes a read_file of p under c with the client's policy
// rules, as the runner does, and runs it through the real executor. It
// returns the allow list the operation ran with and the response.
func readUnder(t *testing.T, r *Runner, c proto.Capability, rules []proto.AllowRule, p string) ([]proto.AllowRule, *proto.Response) {
	t.Helper()
	args, err := json.Marshal(proto.ReadFileArgs{Path: p})
	if err != nil {
		t.Fatal(err)
	}
	req := &proto.Request{V: proto.Version, ID: "req_read", Op: proto.OpReadFile, Args: args, Caller: proto.Caller{Tech: c.Technician},
		Capability: &c, Deadline: time.Now().Add(time.Minute), Policy: proto.Policy{Version: c.PolicyVersion, Allow: slices.Clone(rules)}}
	if err := r.authorize(req); err != nil {
		t.Fatalf("authorize %s: %v", p, err)
	}
	return req.Policy.Allow, fstools.New(fstools.Options{Logger: discard}).Execute(context.Background(), req)
}

// Auto-approval never widens the client's policy: a grant approved on a
// technician unlock reaches only what both it and the policy allow, with the
// policy's Files filters, whatever broader root the capability names.
func TestTechnicianGrantIsNarrowedToThePolicy(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(root, "app", "logs")
	logFile, txtFile := filepath.Join(logs, "a.log"), filepath.Join(logs, "a.txt")
	secret, other := filepath.Join(root, "app", "secret.txt"), filepath.Join(root, "other.log")
	for _, p := range []string{logFile, txtFile, secret, other} {
		writeTestFile(t, p, "contents of "+filepath.Base(p)+"\n")
	}
	app := filepath.Join(root, "app")
	cases := []struct {
		name      string
		policy    []proto.AllowRule
		grant     []string
		wantRules []proto.AllowRule
		allowed   []string
		refused   []string
	}{
		{"a policy rule inside the granted root is kept whole",
			[]proto.AllowRule{{ID: "app-logs", Path: logs, Files: []string{"*.log"}}}, []string{root},
			[]proto.AllowRule{{ID: "app-logs", Path: logs, Files: []string{"*.log"}}},
			[]string{logFile}, []string{txtFile, secret, other}},
		{"a granted root inside a policy rule keeps the rule's Files filter",
			[]proto.AllowRule{{ID: "all-logs", Path: root, Files: []string{"*.log"}}}, []string{app},
			[]proto.AllowRule{{ID: "all-logs", Path: app, Files: []string{"*.log"}}},
			[]string{logFile}, []string{txtFile, secret, other}},
		{"a grant outside the policy reaches nothing",
			[]proto.AllowRule{{ID: "app-logs", Path: logs}}, []string{filepath.Join(root, "elsewhere")},
			nil, nil, []string{logFile, txtFile, secret, other}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := consentRunner(RoutedConsent{Technician: TechnicianConsent{Logger: discard}})
			cr := technicianRequest()
			cr.Paths = c.grant
			ack(t, r, cr)
			cap := waitGrant(t, r, cr.AccessID, proto.ConsentApproved).cap
			for _, p := range c.allowed {
				rules, resp := readUnder(t, r, cap, c.policy, p)
				if !reflect.DeepEqual(rules, c.wantRules) {
					t.Errorf("ran with rules %+v; want %+v", rules, c.wantRules)
				}
				if resp.Error != nil {
					t.Errorf("%s refused: %+v", p, resp.Error)
				}
			}
			for _, p := range c.refused {
				if _, resp := readUnder(t, r, cap, c.policy, p); resp.Error == nil || resp.Error.Code != proto.ErrNotAllowed {
					t.Errorf("%s: got %+v; want %s", p, resp.Error, proto.ErrNotAllowed)
				}
			}
		})
	}
}

// A person at the machine saw and approved the paths of a grant the client's
// policy put to them, so those paths still replace the policy's rules, as
// they do for a legacy grant.
func TestAuthorizeKeepsThePathsAPersonApproved(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "app", "secret.txt")
	writeTestFile(t, secret, "approved at the machine\n")
	policy := []proto.AllowRule{{ID: "app-logs", Path: filepath.Join(root, "app", "logs")}}

	script := consentscript.New()
	r := consentRunner(RoutedConsent{Technician: TechnicianConsent{Logger: discard}, Endpoint: script})
	cr := technicianRequest()
	cr.Paths, cr.EndpointConsent = []string{root}, true
	ack(t, r, cr)
	conv, err := script.Wait(context.Background(), cr.AccessID)
	if err != nil {
		t.Fatal(err)
	}
	conv.Approve(`ACME\sam`)
	cap := waitGrant(t, r, cr.AccessID, proto.ConsentApproved).cap
	rules, resp := readUnder(t, r, cap, policy, secret)
	if want := []proto.AllowRule{{ID: "grant-" + cr.AccessID, Path: root}}; !reflect.DeepEqual(rules, want) {
		t.Errorf("ran with rules %+v; want %+v", rules, want)
	}
	if resp.Error != nil {
		t.Errorf("a path the person at the machine approved was refused: %+v", resp.Error)
	}
}
