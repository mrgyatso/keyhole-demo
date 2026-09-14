package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mrgyatso/keyhole/internal/agent"
	"github.com/mrgyatso/keyhole/internal/agent/hostinfo"
	"github.com/mrgyatso/keyhole/internal/agent/mirror"
	"github.com/mrgyatso/keyhole/internal/fstools"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/redact"
	"github.com/mrgyatso/keyhole/internal/version"
)

// Temporary installation (Slice 4).
//
// `temporary` is the one-time helper the customer runs: it reads the MSP's
// terms from the relay, shows them, takes consent, enrolls with a one-use
// ephemeral token, and installs a service that is separate from any managed
// one. `temporary-run` is what that service executes; it serves requests
// until the deadline and then removes everything, including itself. It is
// also what finishes a session that was interrupted, because it runs again on
// the next start.
//
// The lifecycle is durable, not in-memory:
//
//	enrolled → running → expiring → cleanup → done
//
// Every state is written to session.json before it is entered, and cleanup
// drops a terminating marker that survives a crash, so a kill or a reboot
// mid-session resumes at cleanup rather than at running.

// tempServiceName is the temporary service. It is deliberately not
// serviceName: a temporary install must never collide with, replace or
// inherit anything from a managed one.
const tempServiceName = "KeyholeTemp"

// defaultTempTTL is used when --ttl is not given and the relay offered a
// longer maximum.
const defaultTempTTL = time.Hour

// errTempServiceUnsupported means this OS has no temporary service manager,
// so the session runs in the foreground of the helper process instead. The
// lifecycle is identical; only the supervision differs.
var errTempServiceUnsupported = errors.New("temporary service installation is not supported on this operating system")

// tempStats is what the receipt reports about the session's activity. It
// comes from the local audit mirror, which sees every served request.
type tempStats struct {
	Requests int
	Hashes   []string
}

// countingMirror counts served requests and keeps their response hashes for
// the receipt, then passes everything through to the real mirror.
type countingMirror struct {
	inner agent.Mirror

	mu    sync.Mutex
	stats tempStats
}

func (m *countingMirror) Call(c mirror.Call) {
	m.mu.Lock()
	m.stats.Requests++
	if c.SHA256 != "" {
		m.stats.Hashes = append(m.stats.Hashes, c.SHA256)
		if len(m.stats.Hashes) > agent.MaxReceiptHashes {
			m.stats.Hashes = m.stats.Hashes[len(m.stats.Hashes)-agent.MaxReceiptHashes:]
		}
	}
	m.mu.Unlock()
	if m.inner != nil {
		m.inner.Call(c)
	}
}

func (m *countingMirror) Lifecycle(event, detail string) {
	if m.inner != nil {
		m.inner.Lifecycle(event, detail)
	}
}

func (m *countingMirror) snapshot() tempStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return tempStats{Requests: m.stats.Requests, Hashes: append([]string(nil), m.stats.Hashes...)}
}

type temporaryFlags struct {
	enrollFlags
	ttl time.Duration
}

func (a *application) parseTemporary(args []string) (temporaryFlags, error) {
	fs := flag.NewFlagSet("temporary", flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	var f temporaryFlags
	fs.StringVar(&f.url, "url", "", "relay public URL")
	fs.StringVar(&f.token, "token", "", "one-use enrollment token (prefer KEYHOLE_ENROLL_TOKEN)")
	fs.StringVar(&f.org, "org", "", "expected client slug")
	fs.DurationVar(&f.ttl, "ttl", 0, "how long the session may last; capped by the MSP's maximum")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	if fs.NArg() != 0 {
		return f, fmt.Errorf("temporary: unexpected argument %q", fs.Arg(0))
	}
	if strings.TrimSpace(f.url) == "" {
		return f, errors.New("temporary requires --url")
	}
	if f.token == "" {
		f.token = a.getenv(enrollTokenEnv)
	}
	if strings.TrimSpace(f.token) == "" {
		return f, fmt.Errorf("temporary requires --token or %s", enrollTokenEnv)
	}
	if f.ttl < 0 {
		return f, errors.New("temporary: --ttl must not be negative")
	}
	// The session's own directory is chosen by the agent, not the caller: a
	// temporary install must not be pointed at a managed data dir.
	return f, nil
}

// runTemporary is the one-time helper. It installs nothing before the person
// at the keyboard has seen the MSP's terms and said yes.
func (a *application) runTemporary(ctx context.Context, args []string) error {
	f, err := a.parseTemporary(args)
	if err != nil {
		return err
	}
	// A managed install owns this machine's Keyhole state. Temporary mode
	// never touches it, so it refuses to run alongside it rather than risk
	// removing a managed service or credential on its way out.
	state, err := a.status(ctx)
	if err != nil {
		return fmt.Errorf("check the %s service: %w", serviceName, err)
	}
	if state.Installed {
		return fmt.Errorf("the managed %s service is installed on this machine; "+
			"temporary access is for unmanaged devices. Use the managed access request instead", serviceName)
	}
	tempState, err := a.tempStatus(ctx)
	if err != nil {
		return fmt.Errorf("check the %s service: %w", tempServiceName, err)
	}
	if tempState.Installed {
		return fmt.Errorf("a temporary Keyhole session is already installed (%s service); "+
			"let it finish or stop it before starting another", tempServiceName)
	}

	offer, err := a.offer(ctx, f.url, f.token)
	if err != nil {
		return err
	}
	ttl := f.ttl
	if ttl == 0 {
		ttl = min(defaultTempTTL, offer.MaxDuration)
	}
	if ttl > offer.MaxDuration {
		return fmt.Errorf("--ttl %s is longer than the %s this token allows", ttl, offer.MaxDuration)
	}
	a.printOffer(offer, f.url, ttl)
	ok, err := a.confirm(fmt.Sprintf("Allow this for %s? Type yes to allow: ", ttl))
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(a.out, "Refused. Nothing was installed and no credential was issued.")
		return errors.New("the person at this machine did not consent")
	}

	data, id, err := a.newTempDir()
	if err != nil {
		return err
	}
	host, gatherErr := a.gather(ctx)
	if gatherErr != nil {
		fmt.Fprintln(a.errOut, "warning: some host facts were unavailable:", gatherErr)
	}
	e, err := a.enroll(ctx, agent.EnrollOptions{
		RelayURL: f.url, Token: f.token, Org: f.org, DataDir: data, Host: host,
	})
	f.token = "" // drop the last reference as soon as the request is done
	if err != nil {
		_ = data.Remove()
		return err
	}
	now := a.now()
	session := &agent.TempSession{
		ID: id, State: agent.TempEnrolled, RelayURL: e.RelayURL,
		Client: e.Client, ClientName: offer.ClientName, Technician: offer.Technician, Reason: offer.Reason,
		Operations: offer.Operations, Paths: offer.Paths,
		DeviceID: e.DeviceID, Hostname: host.Hostname, AgentVersion: version.Version,
		EnrolledAt: now.UTC(), ExpiresAt: now.Add(ttl).UTC(),
	}
	if err := data.SaveTempSession(session); err != nil {
		// Without the session file nothing would ever clean this up, so the
		// credential must not survive this failure.
		a.abandon(ctx, data, e)
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		a.abandon(ctx, data, e)
		return fmt.Errorf("locate executable: %w", err)
	}
	switch err := a.tempInstall(ctx, exe, data); {
	case err == nil:
		fmt.Fprintf(a.out, "\nTemporary Keyhole is running as device %s until %s.\n",
			e.DeviceID, session.ExpiresAt.Local().Format(time.RFC1123))
		fmt.Fprintf(a.out, "It removes itself then. To end it now, stop the %s service.\n", tempServiceName)
		return nil
	case errors.Is(err, errTempServiceUnsupported):
		// No service manager for temporary installs here: run the same
		// lifecycle in the foreground. Ctrl-C ends the session and cleans up.
		fmt.Fprintf(a.out, "\nTemporary Keyhole is running as device %s until %s.\n",
			e.DeviceID, session.ExpiresAt.Local().Format(time.RFC1123))
		fmt.Fprintln(a.out, "Press Ctrl-C to end it now. Leave this window open until it finishes.")
		return a.temporaryLifecycle(ctx, data, a.errOut)
	default:
		a.abandon(ctx, data, e)
		return fmt.Errorf("install the %s service: %w", tempServiceName, err)
	}
}

// abandon undoes a half-made session: the device credential is revoked at the
// relay and removed from disk. It is the fail-closed path for every error
// after enrolment but before the session is supervised, because nothing would
// be left running to clean up later.
func (a *application) abandon(ctx context.Context, data agent.DataDir, e *agent.Enrollment) {
	// A Ctrl-C that lands during the install cancels ctx, and giving the
	// credential back must not be cancelled with it. SelfRevoke bounds itself.
	ctx = context.WithoutCancel(ctx)
	if err := a.selfRevoke(ctx, e, data.CredsPath(), proto.RevokeTerminated); err != nil {
		fmt.Fprintf(a.errOut, "warning: could not revoke device %s; the relay expires it on its own: %v\n", e.DeviceID, err)
	}
	if err := data.Remove(); err != nil {
		fmt.Fprintln(a.errOut, "warning:", err)
	}
	// On Windows the binary was copied into Program Files before the service
	// could fail; nothing will run it, and nothing else would remove it.
	if err := a.removeBinary(ctx); err != nil {
		fmt.Fprintln(a.errOut, "warning: remove the temporary binary:", err)
	}
}

func (a *application) printOffer(o *proto.TempOffer, relayURL string, ttl time.Duration) {
	w := a.out
	fmt.Fprintln(w, "Temporary Keyhole access request")
	fmt.Fprintln(w, "--------------------------------")
	fmt.Fprintln(w, "  MSP relay:  ", relayURL)
	client := o.Client
	if o.ClientName != "" {
		client = fmt.Sprintf("%s (%s)", o.ClientName, o.Client)
	}
	fmt.Fprintln(w, "  Client:     ", client)
	if o.Technician != "" {
		fmt.Fprintln(w, "  Technician: ", o.Technician)
	} else {
		fmt.Fprintln(w, "  Technician:  not named by the MSP")
	}
	if o.Reason != "" {
		fmt.Fprintln(w, "  Reason:     ", o.Reason)
	}
	fmt.Fprintln(w, "  Powers:      read only —", strings.Join(o.Operations, ", "))
	if len(o.Paths) > 0 {
		fmt.Fprintln(w, "  Paths:      ", strings.Join(o.Paths, ", "))
	}
	fmt.Fprintln(w, "  Maximum:    ", o.MaxDuration, "(this session:", ttl.String()+")")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Keyhole cannot write to this machine and cannot read its own credentials.")
	fmt.Fprintln(w, "Every action is recorded in this machine's own event log. At the end of the")
	fmt.Fprintln(w, "session the service, its credential and its files are removed and a receipt")
	fmt.Fprintf(w, "is left in %s.\n\n", agent.ReceiptDir())
}

// confirmConsole asks the person at the keyboard. Only a typed "yes" counts:
// a bare Enter, a closed stdin (no interactive user) and anything else all
// mean no.
func (a *application) confirmConsole(prompt string) (bool, error) {
	fmt.Fprint(a.out, prompt)
	line, err := bufio.NewReader(a.in).ReadString('\n')
	if err != nil && line == "" {
		if errors.Is(err, io.EOF) {
			return false, errors.New("no interactive console to consent at; temporary access needs a person at this machine")
		}
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(line), "yes"), nil
}

// runTemporarySession is the service's entry point. It is not in the usage
// text because a person never runs it.
func (a *application) runTemporarySession(ctx context.Context, args []string) error {
	data, err := dataFlag("temporary-run", args, a.errOut)
	if err != nil {
		return err
	}
	// temporary-run removes the directory it is given, and --data defaults to
	// the managed data dir. It only ever runs a session directory directly
	// under the temp root, so a mistyped command cannot delete a managed
	// install's credential, state or event source.
	if !a.isTempSessionDir(data) {
		return fmt.Errorf("temporary-run: %s is not a temporary session directory under %s", data, a.tempRoot())
	}
	err = a.tempSupervise(ctx, data, func(runCtx context.Context, logOut io.Writer) error {
		return a.temporaryLifecycle(runCtx, data, logOut)
	})
	// The Windows service handler keeps its log open inside the session
	// directory while the lifecycle runs, and Windows will not delete an open
	// file, so cleanup's removal leaves the directory and that log behind. The
	// handler has closed it by now: once cleanup has removed the session file,
	// finish the removal. A session file still present is needed next start.
	if _, serr := os.Stat(data.File(agent.TempSessionFile)); errors.Is(serr, os.ErrNotExist) {
		if rerr := data.Remove(); rerr != nil {
			err = errors.Join(err, rerr)
		}
	}
	return err
}

// isTempSessionDir reports whether data is a session directory directly under
// the temp root: never the managed data dir, the temp root itself, or the
// receipts directory beside it.
func (a *application) isTempSessionDir(data agent.DataDir) bool {
	dir := filepath.Clean(string(data))
	return samePath(filepath.Dir(dir), filepath.Clean(a.tempRoot()))
}

// temporaryLifecycle drives one temporary session from whatever state it is
// found in to done. It never returns leaving the machine enrolled: every exit
// path other than "still running" goes through cleanup.
func (a *application) temporaryLifecycle(ctx context.Context, data agent.DataDir, logOut io.Writer) error {
	log := slog.New(slog.NewJSONHandler(logOut, nil))
	s, err := data.LoadTempSession()
	if errors.Is(err, agent.ErrNoTempSession) {
		// Cleanup got as far as removing the session's directory but not its
		// service, so this start has nothing to revoke and nothing to serve.
		// Finish the removal rather than fail on every start from now on.
		log.Warn("temporary service started with no session; removing it", "data", string(data))
		return a.removeTemporaryInstall(ctx, data, log)
	}
	if err != nil {
		return err
	}
	// "done" is recorded after the revocation and the receipt, so only the
	// removal was cut short. Revoking again would fail against a revoked
	// credential, and a second receipt would contradict the first.
	if s.State == agent.TempDone {
		log.Warn("temporary session already finished; completing its removal", "session", s.ID, "device", s.DeviceID)
		return a.removeTemporaryInstall(ctx, data, log)
	}
	// An interrupted session — killed process, reboot, or a deadline that
	// passed while the machine was off — is finished, not resumed. This is
	// what makes a crash mid-session safe.
	if data.Terminating() || s.Unfinished(a.now()) {
		// Expired means the deadline passed while the session was live. One
		// found mid-teardown, or marked terminating inside its deadline, was
		// interrupted, whatever state session.json last recorded.
		reason := agent.EndInterrupted
		if (s.State == agent.TempRunning || s.State == agent.TempEnrolled) && !a.now().Before(s.ExpiresAt) {
			reason = agent.EndExpired
		}
		log.Warn("temporary session was interrupted; completing cleanup",
			"session", s.ID, "device", s.DeviceID, "state", s.State, "expires_at", s.ExpiresAt)
		return a.cleanupTemporary(ctx, data, s, reason, tempStats{}, log)
	}

	s.State = agent.TempRunning
	if err := data.SaveTempSession(s); err != nil {
		return err
	}
	// The deadline is the session's, not the caller's: a service stop ends
	// the session early, but nothing can make it run past ExpiresAt.
	runCtx, cancel := context.WithDeadline(ctx, s.ExpiresAt)
	defer cancel()
	log.Info("temporary session running", "session", s.ID, "device", s.DeviceID,
		"client", s.Client, "expires_at", s.ExpiresAt)

	stats, serveErr := a.serveSession(runCtx, data, logOut)
	reason := agent.EndTerminated
	if !a.now().Before(s.ExpiresAt) {
		reason = agent.EndExpired
	}
	if serveErr != nil {
		log.Error("temporary session stopped early", "err", serveErr)
	}
	return errors.Join(serveErr, a.cleanupTemporary(context.WithoutCancel(ctx), data, s, reason, stats, log))
}

// cleanupTemporary is the teardown, in the order that fails safest: mark, so
// an interrupted teardown is finished next time; revoke, so the credential
// stops working even if removal fails; receipt, written outside the data dir
// so it survives; then remove the service, the data dir and the binary.
func (a *application) cleanupTemporary(ctx context.Context, data agent.DataDir, s *agent.TempSession,
	reason string, stats tempStats, log *slog.Logger) error {
	s.State = agent.TempExpiring
	_ = data.SaveTempSession(s)
	if err := data.MarkTerminating(); err != nil {
		log.Warn("could not mark the session terminating", "err", err)
	}
	s.State = agent.TempCleanup
	_ = data.SaveTempSession(s)

	revoked := false
	e, loadErr := data.Load()
	if loadErr != nil {
		log.Warn("no enrollment to revoke", "err", loadErr)
	} else if err := a.selfRevoke(ctx, e, data.CredsPath(), revokeReasonFor(reason)); err != nil {
		// Not fatal: the relay expires the device on its own schedule, and
		// the credential is about to be deleted from this machine anyway.
		log.Warn("could not revoke the device credential; the relay expires it regardless", "err", err)
	} else {
		revoked = true
	}

	receipt := s.NewReceipt(a.now(), reason, stats.Requests, stats.Hashes, revoked)
	path, err := a.writeReceipt(receipt)
	if err != nil {
		log.Error("could not write the session receipt", "err", err)
	} else {
		log.Info("session receipt written", "path", path, "requests", stats.Requests)
	}

	s.State = agent.TempDone
	_ = data.SaveTempSession(s)

	if err := a.removeTemporaryInstall(ctx, data, log); err != nil {
		log.Error("temporary session cleanup incomplete", "session", s.ID, "device", s.DeviceID, "err", err)
		return err
	}
	log.Info("temporary session removed", "session", s.ID, "device", s.DeviceID, "reason", reason)
	return nil
}

// removeTemporaryInstall takes the install off the machine: the service (and
// its event-source registration), the session directory, and the copied
// binary. Each step is attempted even if an earlier one failed, because
// leaving two of the three behind is worse than leaving three.
func (a *application) removeTemporaryInstall(ctx context.Context, data agent.DataDir, log *slog.Logger) error {
	var errs []error
	if err := a.tempRemove(ctx); err != nil {
		errs = append(errs, fmt.Errorf("remove the %s service: %w", tempServiceName, err))
	}
	if err := data.Remove(); err != nil {
		errs = append(errs, err)
	}
	if err := a.removeBinary(ctx); err != nil {
		errs = append(errs, fmt.Errorf("remove the temporary binary: %w", err))
	}
	return errors.Join(errs...)
}

// revokeReasonFor maps a session end reason onto the protocol's revoke reason.
func revokeReasonFor(end string) string {
	switch end {
	case agent.EndExpired:
		return proto.RevokeExpired
	case agent.EndInterrupted:
		return proto.RevokeInterrupted
	default:
		return proto.RevokeTerminated
	}
}

// serveTemporary runs the agent for one temporary session, counting what it
// served so the receipt can report it.
func serveTemporary(ctx context.Context, data agent.DataDir, logOut io.Writer) (tempStats, error) {
	logger := slog.New(slog.NewJSONHandler(logOut, nil))
	e, err := data.Load()
	if err != nil {
		return tempStats{}, err
	}
	host, gatherErr := hostinfo.Gather(ctx)
	if gatherErr != nil {
		logger.Warn("some host facts unavailable", "err", gatherErr)
	}
	r, err := redact.New()
	if err != nil {
		return tempStats{}, err
	}
	m, err := mirror.Open(logger)
	if err != nil {
		return tempStats{}, err
	}
	defer m.Close(5 * time.Second)
	counter := &countingMirror{inner: m}
	x := fstools.New(fstools.Options{Redactor: r, AgentVersion: version.Version, Logger: logger})
	runner, err := agent.NewRunner(agent.RunnerOptions{
		Enrollment: e, CredsFile: data.CredsPath(), Executor: x, Mirror: counter, Host: host, Logger: logger,
	})
	if err != nil {
		return tempStats{}, err
	}
	runErr := runner.Run(ctx)
	// A session that ran to its deadline ends with a cancelled context; that
	// is success, not failure.
	if errors.Is(runErr, context.DeadlineExceeded) || errors.Is(runErr, context.Canceled) {
		runErr = nil
	}
	return counter.snapshot(), runErr
}
