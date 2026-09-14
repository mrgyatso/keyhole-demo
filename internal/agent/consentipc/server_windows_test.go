//go:build windows

package consentipc

// These tests need a real Windows machine: the named pipe, its DACL, the
// peer checks and Authenticode are Windows APIs. Build them with
//
//	GOOS=windows GOARCH=amd64 go test -c -o dist/windows-tests/consentipc.test.exe ./internal/agent/consentipc
//
// and run consentipc.test.exe -test.v from an ordinary PowerShell and again
// from an elevated one; the Slice 3 handoff says what each run prints. They
// serve their own pipe, never the installed service's, and never start a
// program in anyone's session.

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/mrgyatso/keyhole/internal/proto"
)

var pipeSeq atomic.Int64

func testPipe() string {
	return fmt.Sprintf(`\\.\pipe\keyhole-consent-test-%d-%d`, os.Getpid(), pipeSeq.Add(1))
}

// logBuffer collects the server's log so a test can wait for what it did.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *logBuffer) wait(t *testing.T, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(l.String(), what) {
		if time.Now().After(deadline) {
			t.Fatalf("the server never logged %q; its log:\n%s", what, l.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type testServer struct {
	*Server
	pipe     string
	log      *logBuffer
	launched atomic.Int64
}

// startServer serves a fresh consent pipe with o, launching nothing.
func startServer(t *testing.T, o ServerOptions) *testServer {
	t.Helper()
	ts := &testServer{pipe: testPipe(), log: &logBuffer{}}
	o.Logger = slog.New(slog.NewTextHandler(ts.log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	o.Pipe = ts.pipe
	o.Hello = Hello{Device: "dev_test", Client: "acme", Hostname: "test-host", Agent: "test"}
	o.Sessions = func() []string { return []string{"test"} }
	o.Launch = func(string) error { ts.launched.Add(1); return nil }
	srv, err := NewServer(o)
	if err != nil {
		t.Fatal(err)
	}
	ts.Server = srv
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	ts.log.wait(t, "consent pipe listening")
	return ts
}

func thisExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// identity is who the service should see on the other end of the pipe.
type identity struct {
	user, session string
	elevated      bool
}

func me(t *testing.T) identity {
	t.Helper()
	token := windows.GetCurrentProcessToken()
	tu, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	user := tu.User.Sid.String()
	if account, domain, _, err := tu.User.Sid.LookupAccount(""); err == nil {
		user = account
		if domain != "" {
			user = domain + `\` + account
		}
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		t.Fatal(err)
	}
	return identity{user: user, session: strconv.FormatUint(uint64(session), 10), elevated: token.IsElevated()}
}

func isSystem(t *testing.T) bool {
	t.Helper()
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return tu.User.Sid.String() == "S-1-5-18"
}

func dial(t *testing.T, pipe string) *Client {
	t.Helper()
	c, err := DialPipe(context.Background(), pipe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// receive reads messages until one matches, as the consent window's reader
// does.
func receive(t *testing.T, c *Client, what string, match func(Envelope) bool) Envelope {
	t.Helper()
	type result struct {
		e   Envelope
		err error
	}
	ch := make(chan result, 1)
	go func() {
		for {
			e, err := c.Receive()
			if err != nil || match(e) {
				ch <- result{e, err}
				return
			}
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("waiting for %s: %v", what, r.err)
		}
		return r.e
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
	return Envelope{}
}

// recv reads one update, reporting whether the conversation is still open.
func recv(t *testing.T, ch <-chan proto.ConsentUpdate) (proto.ConsentUpdate, bool) {
	t.Helper()
	select {
	case u, ok := <-ch:
		return u, ok
	case <-time.After(5 * time.Second):
		t.Fatal("no consent update")
	}
	return proto.ConsentUpdate{}, false
}

func windowsRequest(id string) proto.ConsentRequest {
	return proto.ConsentRequest{AccessID: id, Client: "acme", Device: "dev_test", Technician: "alice",
		Purpose: "windows acceptance", Operations: []string{proto.OpReadFile}, Paths: []string{`C:\Windows\Logs`},
		Duration: 10 * time.Minute, ExpiresAt: time.Now().Add(10 * time.Minute)}
}

// The pipe's DACL is exactly SYSTEM, Administrators and interactive users,
// protected from inheritance. Nobody else can even open it.
func TestWindowsPipeACL(t *testing.T) {
	ts := startServer(t, ServerOptions{Image: thisExecutable(t)})
	c := dial(t, ts.pipe)
	h, ok := c.conn.(interface{ Fd() uintptr })
	if !ok {
		t.Fatal("the pipe connection exposes no handle")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(h.Fd()), windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := sd.String()
	t.Logf("pipe DACL: %s", sddl)
	if !strings.HasPrefix(sddl, "D:P") {
		t.Errorf("the DACL is not protected from inheritance: %s", sddl)
	}
	for _, sid := range []string{"SY", "BA", "IU"} {
		if !strings.Contains(sddl, ";;;"+sid+")") {
			t.Errorf("the DACL does not grant %s: %s", sid, sddl)
		}
	}
	if n := strings.Count(sddl, "("); n != 3 {
		t.Errorf("the DACL has %d entries, want exactly 3: %s", n, sddl)
	}
}

// A process that is not the installed consent application is turned away
// before it is told anything, although the DACL lets it connect.
func TestWindowsPipeRefusesAnotherExecutable(t *testing.T) {
	ts := startServer(t, ServerOptions{Image: `C:\Windows\System32\notepad.exe`})
	c := dial(t, ts.pipe)
	if e, err := c.Receive(); err == nil {
		t.Fatalf("a peer running another executable was sent %+v", e)
	}
	ts.log.wait(t, "refused a consent pipe client")
	if !strings.Contains(ts.log.String(), "is not the installed consent application") {
		t.Fatalf("refused for another reason:\n%s", ts.log.String())
	}
	t.Log("a process running another executable was refused")
}

// With signature checking on, an unsigned consent application is refused.
// Keyhole has no certificate yet, so the check is off unless
// KEYHOLE_REQUIRE_SIGNED_CONSENT_UI=1; this proves the check itself.
func TestWindowsPipeRefusesAnUnsignedConsentApp(t *testing.T) {
	ts := startServer(t, ServerOptions{Image: thisExecutable(t), RequireSignature: true})
	c := dial(t, ts.pipe)
	if e, err := c.Receive(); err == nil {
		t.Fatalf("an unsigned peer was sent %+v", e)
	}
	ts.log.wait(t, "is not validly signed")
	t.Log("an unsigned consent application was refused while signatures are required")
	signed := os.Getenv("KEYHOLE_TEST_SIGNED_EXE")
	if signed == "" {
		t.Log("set KEYHOLE_TEST_SIGNED_EXE to a validly Authenticode-signed .exe to check the accepting side")
		return
	}
	if err := verifySignature(signed); err != nil {
		t.Fatalf("%s: %v", signed, err)
	}
	t.Logf("%s passes the Authenticode check", signed)
}

// The service identifies its peer from the pipe itself: its image, session,
// user and whether its token is elevated. Denying works from any window;
// approving works only from an elevated one, which is what the UAC relaunch
// provides.
func TestWindowsPipeIdentifiesItsPeer(t *testing.T) {
	who := me(t)
	t.Logf("this process: user %s, session %s, elevated %t", who.user, who.session, who.elevated)
	ts := startServer(t, ServerOptions{Image: thisExecutable(t)})
	cr := windowsRequest("acc_identity")
	updates, err := ts.Adapter().Request(context.Background(), cr)
	if err != nil {
		t.Fatal(err)
	}
	c := dial(t, ts.pipe)
	hello := receive(t, c, "the service's hello", func(e Envelope) bool { return e.Type == TypeHello })
	if hello.Hello.Version != ProtocolVersion || hello.Hello.Device != "dev_test" || hello.Hello.Hostname != "test-host" {
		t.Fatalf("hello: %+v", hello.Hello)
	}
	receive(t, c, "the request", func(e Envelope) bool { return e.Type == TypeRequest && e.Request.AccessID == cr.AccessID })
	ts.log.wait(t, "consent application attached")
	if !strings.Contains(ts.log.String(), "elevated="+strconv.FormatBool(who.elevated)) {
		t.Errorf("the service saw a different elevation than this token has:\n%s", ts.log.String())
	}

	if err := c.Decide(cr.AccessID, DecideApprove, nil, ""); err != nil {
		t.Fatal(err)
	}
	if who.elevated {
		u, _ := recv(t, updates)
		if u.State != proto.ConsentApproved || u.Approver != who.user || u.ApproverSession != who.session {
			t.Fatalf("approval from an elevated process: %+v", u)
		}
		t.Logf("approved from an elevated process as %s in session %s", u.Approver, u.ApproverSession)
		return
	}
	ts.log.wait(t, "refused a consent decision")
	if len(updates) != 0 {
		t.Fatalf("an unelevated process approved: %+v", <-updates)
	}
	if err := c.Decide(cr.AccessID, DecideDeny, nil, "not now"); err != nil {
		t.Fatal(err)
	}
	u, _ := recv(t, updates)
	if u.State != proto.ConsentDenied || u.Approver != who.user || u.ApproverSession != who.session || u.Reason != "not now" {
		t.Fatalf("denial from an unelevated process: %+v", u)
	}
	t.Logf("refused an unelevated approval; denied as %s in session %s", u.Approver, u.ApproverSession)
}

// A message type the service does not know is ignored: the connection stays
// up and the next message is served. This is what lets the protocol grow.
func TestWindowsPipeIgnoresUnknownMessages(t *testing.T) {
	ts := startServer(t, ServerOptions{Image: thisExecutable(t)})
	cr := windowsRequest("acc_future")
	updates, err := ts.Adapter().Request(context.Background(), cr)
	if err != nil {
		t.Fatal(err)
	}
	c := dial(t, ts.pipe)
	receive(t, c, "the request", func(e Envelope) bool { return e.Type == TypeRequest && e.Request.AccessID == cr.AccessID })
	if err := c.Send(Envelope{Type: "plan_review"}); err != nil {
		t.Fatal(err)
	}
	ts.log.wait(t, "unknown consent message")
	if err := c.Decide(cr.AccessID, DecideDeny, nil, "after an unknown message"); err != nil {
		t.Fatal(err)
	}
	if u, _ := recv(t, updates); u.State != proto.ConsentDenied {
		t.Fatalf("the connection did not survive an unknown message: %+v", u)
	}
	t.Log("an unknown message type was ignored and the connection kept serving")
}

// When the window's process goes away the service asks Windows whether its
// session still has a user: if so the window crashed and the grant pauses;
// if not the user signed out and the grant ends. Only SYSTEM may ask, so an
// ordinary run sees the logoff answer; the service, which runs as SYSTEM,
// sees the pause. Either way the service must agree with Windows.
func TestWindowsPipeDisconnectPausesOrEnds(t *testing.T) {
	who := me(t)
	if !who.elevated {
		t.Skip("approving needs an elevated process: run consentipc.test.exe from an elevated PowerShell")
	}
	ts := startServer(t, ServerOptions{Image: thisExecutable(t)})
	cr := windowsRequest("acc_drop")
	updates, err := ts.Adapter().Request(context.Background(), cr)
	if err != nil {
		t.Fatal(err)
	}
	c := dial(t, ts.pipe)
	receive(t, c, "the request", func(e Envelope) bool { return e.Type == TypeRequest && e.Request.AccessID == cr.AccessID })
	if err := c.Decide(cr.AccessID, DecideApprove, nil, ""); err != nil {
		t.Fatal(err)
	}
	if u, _ := recv(t, updates); u.State != proto.ConsentApproved {
		t.Fatalf("approval: %+v", u)
	}
	hasUser := sessionHasUser(who.session)
	t.Logf("session %s has a user as far as this process may ask: %t (SYSTEM: %t)", who.session, hasUser, isSystem(t))
	c.Close()
	u, open := recv(t, updates)
	switch {
	case hasUser && open:
		t.Fatalf("a window that went away in a signed-in session ended the grant: %+v", u)
	case hasUser:
		t.Log("the grant paused: the window went away while its session stayed signed in")
	case !open:
		t.Fatal("a session Windows reports as signed out only paused the grant")
	case u.State != proto.ConsentTerminated || u.Reason != proto.ReasonLogoff:
		t.Fatalf("grant after its session was reported signed out: %+v", u)
	default:
		t.Log("the grant ended with logoff: this process may not ask Windows about session users, so the session counted as signed out; run as SYSTEM to see the pause")
	}
}

// The sessions the service would show a request in, as this process sees
// them. Only SYSTEM may read another session's user, so an ordinary run lists
// nothing; the service sees every signed-in session, a locked one included.
func TestWindowsInteractiveSessions(t *testing.T) {
	who := me(t)
	sessions := interactiveSessions()
	console := windows.WTSGetActiveConsoleSessionId()
	t.Logf("user %s in session %s; console session %d; sessions with a user: %v", who.user, who.session, console, sessions)
	if !isSystem(t) {
		t.Log("not SYSTEM: Windows does not let this process read session users, so the list is expected to be empty")
		return
	}
	if console != 0xFFFFFFFF && !slices.Contains(sessions, strconv.FormatUint(uint64(console), 10)) {
		t.Errorf("the console session %d, which has a user, is not listed", console)
	}
}
