package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/agent"
	"github.com/mrgyatso/keyhole/internal/agent/hostinfo"
	"github.com/mrgyatso/keyhole/internal/proto"
)

const tempSecret = "khe_acme_temporary_secret_not_for_logs"

// tempHarness is an application whose every side effect is recorded instead
// of performed: no service manager, no relay, no ProgramData.
type tempHarness struct {
	*application
	out, errOut bytes.Buffer

	data     agent.DataDir
	receipts string
	clock    time.Time

	installed   bool
	installedAt agent.DataDir
	removedSvc  int
	removedExe  int
	revoked     []string // reasons, in order
	receipt     *agent.Receipt
	served      tempStats
	serveBlocks bool
	terms       proto.TempOffer
	enrollErr   error
	installErr  error
	answer      string
}

func newTempHarness(t *testing.T) *tempHarness {
	t.Helper()
	root := t.TempDir()
	h := &tempHarness{
		data:     agent.DataDir(filepath.Join(root, "session")),
		receipts: filepath.Join(root, "receipts"),
		clock:    time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC),
		answer:   "yes",
		terms: proto.TempOffer{
			Client: "acme", ClientName: "ACME Corp", Technician: "alice@msp", Reason: "ticket 4471",
			Operations: proto.ReadOps, Paths: []string{`C:\Windows\Logs`},
			MaxDuration: time.Hour, Ephemeral: true,
		},
	}
	a := newApplication(&h.out, &h.errOut)
	h.application = a
	a.tempRoot = func() string { return root } // h.data is a session directory under it
	a.getenv = func(key string) string {
		if key == enrollTokenEnv {
			return tempSecret
		}
		return ""
	}
	a.now = func() time.Time { return h.clock }
	a.gather = func(context.Context) (hostinfo.Info, error) {
		return hostinfo.Info{Hostname: "LAPTOP-7", MachineID: "m-7", OS: "windows", Arch: "amd64"}, nil
	}
	a.status = func(context.Context) (serviceState, error) { return serviceState{}, nil }
	a.tempStatus = func(context.Context) (serviceState, error) { return serviceState{}, nil }
	a.confirm = func(string) (bool, error) { return strings.EqualFold(h.answer, "yes"), nil }
	a.offer = func(context.Context, string, string) (*proto.TempOffer, error) {
		o := h.terms
		return &o, nil
	}
	a.newTempDir = func() (agent.DataDir, string, error) {
		return h.data, filepath.Base(string(h.data)), h.data.Ensure()
	}
	a.enroll = func(_ context.Context, o agent.EnrollOptions) (*agent.Enrollment, error) {
		if h.enrollErr != nil {
			return nil, h.enrollErr
		}
		if o.Token != tempSecret {
			t.Fatalf("enrollment got token %q", o.Token)
		}
		e := &agent.Enrollment{
			RelayURL: "https://keyhole.test", DeviceID: "dev_temp1", Client: "acme",
			PublicKey: "UTEMP1", NATSURLs: []string{"wss://keyhole.test/nats"}, EnrolledAt: h.clock,
		}
		writeEnrollment(t, o.DataDir, e)
		return e, nil
	}
	a.tempInstall = func(_ context.Context, _ string, data agent.DataDir) error {
		if h.installErr != nil {
			return h.installErr
		}
		h.installed, h.installedAt = true, data
		return nil
	}
	a.tempRemove = func(context.Context) error { h.removedSvc++; return nil }
	a.removeBinary = func(context.Context) error { h.removedExe++; return nil }
	a.selfRevoke = func(_ context.Context, e *agent.Enrollment, creds, reason string) error {
		if e == nil || e.DeviceID == "" {
			t.Fatal("revoked without an enrollment")
		}
		if creds != h.data.CredsPath() {
			t.Fatalf("revoked with credentials %q", creds)
		}
		h.revoked = append(h.revoked, reason)
		return nil
	}
	a.writeReceipt = func(r agent.Receipt) (string, error) {
		h.receipt = &r
		return agent.WriteReceipt(h.receipts, r)
	}
	a.serveSession = func(ctx context.Context, _ agent.DataDir, _ io.Writer) (tempStats, error) {
		if h.serveBlocks {
			<-ctx.Done()
		}
		return h.served, nil
	}
	a.tempSupervise = func(ctx context.Context, _ agent.DataDir, run func(context.Context, io.Writer) error) error {
		return run(ctx, &h.errOut)
	}
	return h
}

// writeEnrollment puts an agent.json and a device.creds on disk, as a real
// enrollment would.
func writeEnrollment(t *testing.T, data agent.DataDir, e *agent.Enrollment) {
	t.Helper()
	if err := data.Ensure(); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(data.File(agent.AgentFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(data.CredsPath(), []byte("-----BEGIN NATS USER JWT-----\nfake\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *tempHarness) install(t *testing.T, args ...string) error {
	t.Helper()
	return h.run(context.Background(), append([]string{"temporary", "--url", "https://keyhole.test"}, args...))
}

func (h *tempHarness) session(t *testing.T) *agent.TempSession {
	t.Helper()
	s, err := h.data.LoadTempSession()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTemporaryShowsTheOfferAndNeedsConsent(t *testing.T) {
	h := newTempHarness(t)
	h.answer = "no"
	if err := h.install(t); err == nil {
		t.Fatal("installed without consent")
	}
	for _, want := range []string{"ACME Corp", "acme", "alice@msp", "ticket 4471", `C:\Windows\Logs`, "read only", "1h0m0s"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("the consent prompt never mentions %q:\n%s", want, h.out.String())
		}
	}
	if h.installed || len(h.revoked) != 0 {
		t.Fatal("a refusal still touched the machine")
	}
	if _, err := os.Stat(h.data.File(agent.TempSessionFile)); err == nil {
		t.Fatal("a refusal left a session behind")
	}
	if strings.Contains(h.out.String()+h.errOut.String(), tempSecret) {
		t.Fatal("token leaked in command output")
	}
}

func TestTemporaryRefusesBesideAManagedInstall(t *testing.T) {
	h := newTempHarness(t)
	h.application.status = func(context.Context) (serviceState, error) {
		return serviceState{Installed: true, Status: "running"}, nil
	}
	var offered bool
	h.application.offer = func(context.Context, string, string) (*proto.TempOffer, error) {
		offered = true
		return nil, nil
	}
	err := h.install(t)
	if err == nil || !strings.Contains(err.Error(), serviceName) {
		t.Fatalf("temporary mode ran beside a managed install: %v", err)
	}
	if offered {
		t.Fatal("the token was sent to the relay before the managed install was ruled out")
	}
}

func TestTemporaryRefusesASecondSession(t *testing.T) {
	h := newTempHarness(t)
	h.application.tempStatus = func(context.Context) (serviceState, error) {
		return serviceState{Installed: true, Status: "running"}, nil
	}
	if err := h.install(t); err == nil || !strings.Contains(err.Error(), tempServiceName) {
		t.Fatalf("a second temporary session was allowed: %v", err)
	}
}

func TestTemporaryEnrollsAndInstallsAfterConsent(t *testing.T) {
	h := newTempHarness(t)
	if err := h.install(t, "--ttl", "30m"); err != nil {
		t.Fatal(err)
	}
	if !h.installed || h.installedAt != h.data {
		t.Fatalf("service installed=%v at %q", h.installed, h.installedAt)
	}
	s := h.session(t)
	switch {
	case s.State != agent.TempEnrolled:
		t.Fatalf("state %q", s.State)
	case s.DeviceID != "dev_temp1" || s.Client != "acme" || s.ClientName != "ACME Corp":
		t.Fatalf("session %+v", s)
	case s.Technician != "alice@msp" || s.Reason != "ticket 4471":
		t.Fatalf("session lost the consented terms: %+v", s)
	case !s.ExpiresAt.Equal(h.clock.Add(30 * time.Minute)):
		t.Fatalf("expires at %s", s.ExpiresAt)
	}
	// The session file is the record of what was consented to, and it must
	// not be a place a credential ends up.
	b, err := os.ReadFile(h.data.File(agent.TempSessionFile))
	if err != nil || strings.Contains(string(b), tempSecret) {
		t.Fatalf("session file carries the token (%v)", err)
	}
}

func TestTemporaryRefusesATTLOverTheMSPsMaximum(t *testing.T) {
	h := newTempHarness(t)
	if err := h.install(t, "--ttl", "4h"); err == nil {
		t.Fatal("accepted a session longer than the token allows")
	}
	if h.installed {
		t.Fatal("installed anyway")
	}
}

func TestTemporaryLeavesNothingWhenEnrollmentFails(t *testing.T) {
	h := newTempHarness(t)
	h.enrollErr = errors.New("relay refused")
	if err := h.install(t); err == nil {
		t.Fatal("enrollment failure ignored")
	}
	if h.installed {
		t.Fatal("installed after a failed enrollment")
	}
	if _, err := os.Stat(string(h.data)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the session directory outlived a failed enrollment")
	}
}

// A credential handed out but never supervised is the worst outcome: nothing
// would ever expire it from this end. It must be given back at once.
func TestTemporaryRevokesWhenTheServiceCannotBeInstalled(t *testing.T) {
	h := newTempHarness(t)
	h.installErr = errors.New("access denied")
	if err := h.install(t); err == nil {
		t.Fatal("install failure ignored")
	}
	if len(h.revoked) != 1 || h.revoked[0] != proto.RevokeTerminated {
		t.Fatalf("revocations %v", h.revoked)
	}
	if _, err := os.Stat(string(h.data)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the credential was left on disk")
	}
	// The Windows install copies the binary into Program Files before it can
	// fail on the service, so a failed install removes that copy too.
	if h.removedExe != 1 {
		t.Fatalf("removed the copied binary %d times after a failed install", h.removedExe)
	}
}

// Ctrl-C during the install cancels the helper's context. The half-made
// session must still give its credential back, and a cancelled context would
// stop the revocation before it is flushed to the relay.
func TestTemporaryAbandonRevokesAfterAnInterrupt(t *testing.T) {
	h := newTempHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.application.tempInstall = func(context.Context, string, agent.DataDir) error {
		cancel() // the person pressed Ctrl-C while the service was being set up
		return errors.New("install interrupted")
	}
	revokeErr := errors.New("selfRevoke was not called")
	h.application.selfRevoke = func(rctx context.Context, _ *agent.Enrollment, _, reason string) error {
		revokeErr = rctx.Err()
		h.revoked = append(h.revoked, reason)
		return nil
	}
	if err := h.run(ctx, []string{"temporary", "--url", "https://keyhole.test"}); err == nil {
		t.Fatal("an interrupted install reported success")
	}
	if revokeErr != nil {
		t.Fatalf("the credential was given back on a dead context: %v", revokeErr)
	}
	if len(h.revoked) != 1 {
		t.Fatalf("revocations %v", h.revoked)
	}
}

// startedSession puts a running session on disk, as the helper would have.
func (h *tempHarness) startedSession(t *testing.T, state string, expiresIn time.Duration) *agent.TempSession {
	t.Helper()
	writeEnrollment(t, h.data, &agent.Enrollment{
		RelayURL: "https://keyhole.test", DeviceID: "dev_temp1", Client: "acme",
		PublicKey: "UTEMP1", NATSURLs: []string{"wss://keyhole.test/nats"}, EnrolledAt: h.clock,
	})
	s := &agent.TempSession{
		ID: "tmpsession", State: state, RelayURL: "https://keyhole.test",
		Client: "acme", ClientName: "ACME Corp", Technician: "alice@msp", Reason: "ticket 4471",
		Operations: proto.ReadOps, DeviceID: "dev_temp1", Hostname: "LAPTOP-7",
		EnrolledAt: h.clock, ExpiresAt: h.clock.Add(expiresIn),
	}
	if err := h.data.SaveTempSession(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTemporaryLifecycleRunsThenRemovesItself(t *testing.T) {
	h := newTempHarness(t)
	h.startedSession(t, agent.TempEnrolled, time.Hour)
	h.served = tempStats{Requests: 3, Hashes: []string{"aa", "bb", "cc"}}
	// The session's hour is up the moment serving returns.
	h.application.serveSession = func(context.Context, agent.DataDir, io.Writer) (tempStats, error) {
		h.clock = h.clock.Add(time.Hour)
		return h.served, nil
	}

	if err := h.run(context.Background(), []string{"temporary-run", "--data", string(h.data)}); err != nil {
		t.Fatal(err)
	}
	if len(h.revoked) != 1 || h.revoked[0] != proto.RevokeExpired {
		t.Fatalf("revocations %v", h.revoked)
	}
	if h.removedSvc != 1 || h.removedExe != 1 {
		t.Fatalf("removed service %d times, binary %d times", h.removedSvc, h.removedExe)
	}
	if _, err := os.Stat(string(h.data)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the session directory survived cleanup")
	}
	if h.receipt == nil {
		t.Fatal("no receipt")
	}
	r := *h.receipt
	switch {
	case r.EndReason != agent.EndExpired:
		t.Fatalf("end reason %q", r.EndReason)
	case r.Requests != 3 || len(r.Hashes) != 3:
		t.Fatalf("receipt activity %+v", r)
	case !r.Revoked:
		t.Fatal("receipt does not record the revocation")
	case r.DeviceID != "dev_temp1" || r.Client != "acme" || r.Technician != "alice@msp":
		t.Fatalf("receipt %+v", r)
	}
	assertReceiptSurvives(t, h, r)
}

func assertReceiptSurvives(t *testing.T, h *tempHarness, r agent.Receipt) {
	t.Helper()
	entries, err := os.ReadDir(h.receipts)
	if err != nil || len(entries) != 1 {
		t.Fatalf("receipt directory %v (%v)", entries, err)
	}
	b, err := os.ReadFile(filepath.Join(h.receipts, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	// The receipt outlives the session precisely so the customer keeps
	// evidence; it must not also outlive the credential.
	for _, forbidden := range []string{tempSecret, "BEGIN NATS", "device.creds", r.Session + ".creds"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("the receipt carries %q:\n%s", forbidden, b)
		}
	}
	var back agent.Receipt
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.DeviceID != r.DeviceID || back.EndReason != r.EndReason || back.Note == "" {
		t.Fatalf("receipt on disk %+v", back)
	}
	if !strings.HasPrefix(filepath.Base(entries[0].Name()), "keyhole-"+r.DeviceID) {
		t.Fatalf("receipt name %q", entries[0].Name())
	}
}

func TestTemporaryLifecycleEndsOnTermination(t *testing.T) {
	h := newTempHarness(t)
	h.startedSession(t, agent.TempEnrolled, time.Hour)
	h.serveBlocks = true
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Wait until the session has recorded that it is running, then stop
		// it the way a service stop or Ctrl-C would.
		for {
			if s, err := h.data.LoadTempSession(); err == nil && s.State == agent.TempRunning {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	if err := h.run(ctx, []string{"temporary-run", "--data", string(h.data)}); err != nil {
		t.Fatal(err)
	}
	if len(h.revoked) != 1 || h.revoked[0] != proto.RevokeTerminated {
		t.Fatalf("revocations %v", h.revoked)
	}
	if h.receipt == nil || h.receipt.EndReason != agent.EndTerminated {
		t.Fatalf("receipt %+v", h.receipt)
	}
	if h.removedSvc != 1 || h.removedExe != 1 {
		t.Fatal("a terminated session did not remove itself")
	}
}

// A machine that was switched off past the deadline, or rebooted mid-session,
// starts the service again. It must finish the session, not resume it.
func TestTemporaryLifecycleFinishesAnInterruptedSession(t *testing.T) {
	for name, tc := range map[string]struct {
		state      string
		expiresIn  time.Duration
		terminated bool
		want       string
		wantRevoke string
	}{
		"deadline passed while the machine was off": {
			state: agent.TempRunning, expiresIn: -time.Minute,
			want: agent.EndExpired, wantRevoke: proto.RevokeExpired,
		},
		"killed before it finished tearing down": {
			state: agent.TempCleanup, expiresIn: time.Hour, terminated: true,
			want: agent.EndInterrupted, wantRevoke: proto.RevokeInterrupted,
		},
		"killed while expiring": {
			state: agent.TempExpiring, expiresIn: time.Hour,
			want: agent.EndInterrupted, wantRevoke: proto.RevokeInterrupted,
		},
		// The shape the Windows acceptance procedure forces by creating the
		// marker: the session is still inside its deadline, so it did not
		// expire, whatever state session.json last recorded.
		"marked terminating inside its deadline": {
			state: agent.TempRunning, expiresIn: time.Hour, terminated: true,
			want: agent.EndInterrupted, wantRevoke: proto.RevokeInterrupted,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTempHarness(t)
			h.startedSession(t, tc.state, tc.expiresIn)
			if tc.terminated {
				if err := h.data.MarkTerminating(); err != nil {
					t.Fatal(err)
				}
			}
			var served bool
			h.application.serveSession = func(context.Context, agent.DataDir, io.Writer) (tempStats, error) {
				served = true
				return tempStats{}, nil
			}
			if err := h.run(context.Background(), []string{"temporary-run", "--data", string(h.data)}); err != nil {
				t.Fatal(err)
			}
			if served {
				t.Fatal("an interrupted session went back to serving requests")
			}
			if h.receipt == nil || h.receipt.EndReason != tc.want {
				t.Fatalf("receipt %+v, want end reason %q", h.receipt, tc.want)
			}
			if len(h.revoked) != 1 || h.revoked[0] != tc.wantRevoke {
				t.Fatalf("revocations %v", h.revoked)
			}
			if _, err := os.Stat(string(h.data)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("the session directory survived")
			}
		})
	}
}

// Everything else in cleanup must still happen when the relay cannot be
// reached: the relay expires the device by itself, so the endpoint's job is
// to stop existing.
func TestTemporaryCleanupCompletesWithoutTheRelay(t *testing.T) {
	h := newTempHarness(t)
	h.startedSession(t, agent.TempRunning, -time.Minute)
	h.application.selfRevoke = func(context.Context, *agent.Enrollment, string, string) error {
		return errors.New("no route to host")
	}
	if err := h.run(context.Background(), []string{"temporary-run", "--data", string(h.data)}); err != nil {
		t.Fatal(err)
	}
	if h.receipt == nil || h.receipt.Revoked {
		t.Fatalf("the receipt claims a revocation that did not happen: %+v", h.receipt)
	}
	if h.removedSvc != 1 || h.removedExe != 1 {
		t.Fatal("cleanup stopped when the relay was unreachable")
	}
	if _, err := os.Stat(string(h.data)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the credential was left on disk")
	}
}

// The marker is what makes a crash mid-teardown safe, so it must be on disk
// before anything irreversible happens.
func TestTemporaryCleanupMarksBeforeItRevokes(t *testing.T) {
	h := newTempHarness(t)
	h.startedSession(t, agent.TempRunning, -time.Minute)
	marked := false
	h.application.selfRevoke = func(context.Context, *agent.Enrollment, string, string) error {
		marked = h.data.Terminating()
		return nil
	}
	if err := h.run(context.Background(), []string{"temporary-run", "--data", string(h.data)}); err != nil {
		t.Fatal(err)
	}
	if !marked {
		t.Fatal("the terminating marker was not written before the revocation")
	}
}

func TestTemporarySessionStates(t *testing.T) {
	now := time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	live := agent.TempSession{State: agent.TempRunning, ExpiresAt: now.Add(time.Minute)}
	if live.Unfinished(now) {
		t.Fatal("a live session is unfinished")
	}
	for _, s := range []agent.TempSession{
		{State: agent.TempRunning, ExpiresAt: now.Add(-time.Second)},
		{State: agent.TempEnrolled, ExpiresAt: now},
		{State: agent.TempExpiring, ExpiresAt: now.Add(time.Hour)},
		{State: agent.TempCleanup, ExpiresAt: now.Add(time.Hour)},
		{State: agent.TempDone, ExpiresAt: now.Add(time.Hour)},
	} {
		if !s.Unfinished(now) {
			t.Fatalf("%+v is treated as live", s)
		}
	}
}

func TestReceiptHashesAreBounded(t *testing.T) {
	s := agent.TempSession{ID: "s", DeviceID: "dev_x"}
	hashes := make([]string, agent.MaxReceiptHashes+10)
	for i := range hashes {
		hashes[i] = string(rune('a' + i%26))
	}
	r := s.NewReceipt(time.Now(), agent.EndExpired, len(hashes), hashes, true)
	if len(r.Hashes) != agent.MaxReceiptHashes {
		t.Fatalf("%d hashes kept", len(r.Hashes))
	}
	if r.Hashes[len(r.Hashes)-1] != hashes[len(hashes)-1] {
		t.Fatal("the receipt kept the oldest hashes rather than the newest")
	}
	if r.Requests != len(hashes) {
		t.Fatalf("request count %d was clipped with the hashes", r.Requests)
	}
}

// Cleanup can be interrupted between removing the session directory and
// removing the service. The next start has nothing to revoke and must finish
// the removal, not fail forever.
func TestTemporaryServiceWithNoSessionRemovesItself(t *testing.T) {
	h := newTempHarness(t)
	if err := h.data.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := h.run(context.Background(), []string{"temporary-run", "--data", string(h.data)}); err != nil {
		t.Fatal(err)
	}
	if h.removedSvc != 1 || h.removedExe != 1 {
		t.Fatalf("removed service %d times, binary %d times", h.removedSvc, h.removedExe)
	}
	if len(h.revoked) != 0 || h.receipt != nil {
		t.Fatal("a session that was already torn down was revoked or receipted again")
	}
	if _, err := os.Stat(string(h.data)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the empty session directory survived")
	}
}

// A session that reached "done" had already revoked and written its receipt;
// only the removal was cut short. Finishing it must not revoke again or leave a
// second receipt that contradicts the first (no revocation, no requests).
func TestTemporaryDoneSessionOnlyFinishesRemoval(t *testing.T) {
	h := newTempHarness(t)
	h.startedSession(t, agent.TempDone, time.Hour)
	if err := h.run(context.Background(), []string{"temporary-run", "--data", string(h.data)}); err != nil {
		t.Fatal(err)
	}
	if len(h.revoked) != 0 || h.receipt != nil {
		t.Fatalf("a finished session was revoked %v or receipted again: %+v", h.revoked, h.receipt)
	}
	if h.removedSvc != 1 || h.removedExe != 1 {
		t.Fatalf("removed service %d times, binary %d times", h.removedSvc, h.removedExe)
	}
	if _, err := os.Stat(string(h.data)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the session directory survived")
	}
}

// On Windows the service keeps its log open inside the session directory
// until the lifecycle returns, and an open file cannot be deleted there, so
// cleanup's own removal leaves the directory and that log behind. Once the
// service manager has let go, temporary-run must finish the job.
func TestTemporaryRunRemovesWhatTheServiceLogKeptOpen(t *testing.T) {
	h := newTempHarness(t)
	h.startedSession(t, agent.TempRunning, -time.Minute)
	h.application.tempSupervise = func(ctx context.Context, data agent.DataDir, run func(context.Context, io.Writer) error) error {
		err := run(ctx, &h.errOut)
		// What Windows leaves: the directory, holding only the log that was
		// open while cleanup ran.
		if err := data.Ensure(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(data.File(agent.LogFile), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return err
	}
	if err := h.run(context.Background(), []string{"temporary-run", "--data", string(h.data)}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(string(h.data)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the session directory outlived the service that held its log open")
	}

	t.Run("a session that still needs its directory keeps it", func(t *testing.T) {
		h := newTempHarness(t)
		if err := h.data.Ensure(); err != nil {
			t.Fatal(err)
		}
		// An unreadable session file stops the lifecycle before cleanup, and
		// the next start needs it, so nothing may be removed.
		if err := os.WriteFile(h.data.File(agent.TempSessionFile), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := h.run(context.Background(), []string{"temporary-run", "--data", string(h.data)}); err == nil {
			t.Fatal("an unreadable session was accepted")
		}
		if _, err := os.Stat(h.data.File(agent.TempSessionFile)); err != nil {
			t.Fatalf("the unfinished session's file was removed: %v", err)
		}
	})
}

// temporary-run removes the directory it is given, and --data defaults to the
// managed data dir. Pointed anywhere but a session directory under the temp
// root it must refuse before touching anything; otherwise one mistyped command
// deletes a managed install's credential and its event source.
func TestTemporaryRunRefusesAManagedDataDir(t *testing.T) {
	h := newTempHarness(t)
	managed := agent.DataDir(filepath.Join(t.TempDir(), "Keyhole"))
	writeEnrollment(t, managed, &agent.Enrollment{
		RelayURL: "https://keyhole.test", DeviceID: "dev_managed", Client: "acme",
		PublicKey: "UMANAGED", NATSURLs: []string{"wss://keyhole.test/nats"}, EnrolledAt: h.clock,
	})
	if err := h.run(context.Background(), []string{"temporary-run", "--data", string(managed)}); err == nil {
		t.Fatal("temporary-run accepted a data dir outside the temp root")
	}
	if _, err := managed.Load(); err != nil {
		t.Fatalf("the managed enrollment did not survive: %v", err)
	}
	// With no --data at all the directory is the managed data dir itself.
	if err := h.run(context.Background(), []string{"temporary-run"}); err == nil {
		t.Fatal("temporary-run accepted its default, the managed data dir")
	}
	if h.removedSvc != 0 || h.removedExe != 0 || len(h.revoked) != 0 || h.receipt != nil {
		t.Fatalf("refused, but still touched the machine: service %d, binary %d, revoked %v",
			h.removedSvc, h.removedExe, h.revoked)
	}
}
