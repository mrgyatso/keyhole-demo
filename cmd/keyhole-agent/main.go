// Command keyhole-agent enrolls an endpoint and runs its read-only service.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mrgyatso/keyhole/internal/agent"
	"github.com/mrgyatso/keyhole/internal/agent/hostinfo"
	"github.com/mrgyatso/keyhole/internal/agent/mirror"
	"github.com/mrgyatso/keyhole/internal/fstools"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/redact"
	"github.com/mrgyatso/keyhole/internal/version"
)

const enrollTokenEnv = "KEYHOLE_ENROLL_TOKEN"

type application struct {
	out, errOut io.Writer
	in          io.Reader
	getenv      func(string) string
	now         func() time.Time
	gather      func(context.Context) (hostinfo.Info, error)
	enroll      func(context.Context, agent.EnrollOptions) (*agent.Enrollment, error)
	install     func(context.Context, string, agent.DataDir) error
	uninstall   func(context.Context) error
	status      func(context.Context) (serviceState, error)
	runService  func(context.Context, agent.DataDir, func(context.Context, io.Writer) error) error

	// Temporary installation (Slice 4). Every step the lifecycle takes that
	// touches the machine or the relay is injectable, so the state machine is
	// tested without a service manager or a network.
	confirm       func(prompt string) (bool, error)
	offer         func(ctx context.Context, relayURL, token string) (*proto.TempOffer, error)
	newTempDir    func() (agent.DataDir, string, error)
	tempStatus    func(context.Context) (serviceState, error)
	tempInstall   func(ctx context.Context, exe string, data agent.DataDir) error
	tempRemove    func(context.Context) error
	tempSupervise func(context.Context, agent.DataDir, func(context.Context, io.Writer) error) error
	selfRevoke    func(ctx context.Context, e *agent.Enrollment, credsFile, reason string) error
	writeReceipt  func(agent.Receipt) (string, error)
	removeBinary  func(context.Context) error
	serveSession  func(ctx context.Context, data agent.DataDir, logOut io.Writer) (tempStats, error)
	tempRoot      func() string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := newApplication(os.Stdout, os.Stderr)
	if err := a.run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "keyhole-agent:", err)
		os.Exit(1)
	}
}

func newApplication(out, errOut io.Writer) *application {
	a := &application{
		out: out, errOut: errOut, in: os.Stdin, getenv: os.Getenv, now: time.Now, gather: hostinfo.Gather,
		enroll: agent.Enroll, install: installService, uninstall: uninstallService,
		status: serviceStatus, runService: runUnderServiceManager,
		offer: func(ctx context.Context, relayURL, token string) (*proto.TempOffer, error) {
			return agent.FetchOffer(ctx, relayURL, token, nil)
		},
		newTempDir: agent.NewTempDataDir,
		tempStatus: tempServiceStatus, tempInstall: installTempService, tempRemove: removeTempService,
		tempSupervise: runTempUnderServiceManager, selfRevoke: agent.SelfRevoke,
		writeReceipt: func(r agent.Receipt) (string, error) { return agent.WriteReceipt(agent.ReceiptDir(), r) },
		removeBinary: removeTempExecutable, serveSession: serveTemporary,
		tempRoot: agent.TempRoot,
	}
	a.confirm = a.confirmConsole
	return a
}

func (a *application) run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage(a.errOut)
		return errors.New("a command is required")
	}
	switch args[0] {
	case "install":
		return a.runInstall(ctx, args[1:])
	case "uninstall":
		return a.runUninstall(ctx, args[1:])
	case "enroll":
		return a.runEnroll(ctx, args[1:])
	case "run":
		return a.runAgent(ctx, args[1:])
	case "temporary":
		return a.runTemporary(ctx, args[1:])
	case "temporary-run": // the temporary service's own entry point
		return a.runTemporarySession(ctx, args[1:])
	case "status":
		return a.runStatus(ctx, args[1:])
	case "version":
		if len(args) != 1 {
			return errors.New("version takes no arguments")
		}
		fmt.Fprintln(a.out, version.Version)
		return nil
	case "help", "-h", "--help":
		usage(a.out)
		return nil
	default:
		usage(a.errOut)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  keyhole-agent install --url URL [--token TOKEN] [--org SLUG] [--data DIR]")
	fmt.Fprintln(w, "  keyhole-agent enroll  --url URL [--token TOKEN] [--org SLUG] [--data DIR]")
	fmt.Fprintln(w, "  keyhole-agent temporary --url URL [--token TOKEN] [--org SLUG] [--ttl 1h]")
	fmt.Fprintln(w, "  keyhole-agent run [--data DIR]")
	fmt.Fprintln(w, "  keyhole-agent status [--data DIR]")
	fmt.Fprintln(w, "  keyhole-agent uninstall")
	fmt.Fprintln(w, "  keyhole-agent version")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "--token defaults to KEYHOLE_ENROLL_TOKEN. The token is never stored or logged.")
	fmt.Fprintln(w, "temporary installs a one-off, self-removing session on an unmanaged machine;")
	fmt.Fprintln(w, "it shows the MSP's terms and needs consent at this console before it installs.")
}

type enrollFlags struct {
	url, token, org string
	data            agent.DataDir
}

func (a *application) parseEnroll(command string, args []string) (enrollFlags, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	var f enrollFlags
	data := fs.String("data", string(agent.DefaultDataDir()), "private agent data directory")
	fs.StringVar(&f.url, "url", "", "relay public URL")
	fs.StringVar(&f.token, "token", "", "enrollment token (prefer KEYHOLE_ENROLL_TOKEN)")
	fs.StringVar(&f.org, "org", "", "expected client slug")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	if fs.NArg() != 0 {
		return f, fmt.Errorf("%s: unexpected argument %q", command, fs.Arg(0))
	}
	if strings.TrimSpace(f.url) == "" {
		return f, fmt.Errorf("%s requires --url", command)
	}
	if f.token == "" {
		f.token = a.getenv(enrollTokenEnv)
	}
	if strings.TrimSpace(f.token) == "" {
		return f, fmt.Errorf("%s requires --token or %s", command, enrollTokenEnv)
	}
	f.data = agent.DataDir(*data)
	return f, nil
}

func (a *application) enrollEndpoint(ctx context.Context, f enrollFlags) (*agent.Enrollment, error) {
	host, gatherErr := a.gather(ctx)
	// MachineID has a private fallback. Other missing fields are useful but
	// do not weaken the device credential, so enrollment can continue.
	if gatherErr != nil {
		fmt.Fprintln(a.errOut, "warning: some host facts were unavailable:", gatherErr)
	}
	e, err := a.enroll(ctx, agent.EnrollOptions{
		RelayURL: f.url, Token: f.token, Org: f.org, DataDir: f.data, Host: host,
	})
	// Drop the application's last reference as soon as the request finishes.
	f.token = ""
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(a.out, "enrolled device %s in client %s\n", e.DeviceID, e.Client)
	return e, nil
}

func (a *application) runEnroll(ctx context.Context, args []string) error {
	f, err := a.parseEnroll("enroll", args)
	if err != nil {
		return err
	}
	_, err = a.enrollEndpoint(ctx, f)
	return err
}

func (a *application) runInstall(ctx context.Context, args []string) error {
	f, err := a.parseEnroll("install", args)
	if err != nil {
		return err
	}
	state, err := a.status(ctx)
	if err != nil {
		return fmt.Errorf("check service: %w", err)
	}
	if state.Installed {
		return errors.New("the Keyhole service is already installed; use enroll to replace its device credential")
	}
	if _, err := a.enrollEndpoint(ctx, f); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	if err := a.install(ctx, exe, f.data); err != nil {
		return fmt.Errorf("install service (enrollment was kept in %s): %w", f.data, err)
	}
	fmt.Fprintln(a.out, "Keyhole service installed and started")
	return nil
}

func (a *application) runUninstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("uninstall: unexpected argument %q", fs.Arg(0))
	}
	if err := a.uninstall(ctx); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "Keyhole service removed; device credentials were preserved")
	return nil
}

func dataFlag(command string, args []string, errOut io.Writer) (agent.DataDir, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(errOut)
	data := fs.String("data", string(agent.DefaultDataDir()), "private agent data directory")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 0 {
		return "", fmt.Errorf("%s: unexpected argument %q", command, fs.Arg(0))
	}
	return agent.DataDir(*data), nil
}

func (a *application) runStatus(ctx context.Context, args []string) error {
	data, err := dataFlag("status", args, a.errOut)
	if err != nil {
		return err
	}
	state, err := a.status(ctx)
	if err != nil {
		return err
	}
	service := "not installed"
	if state.Installed {
		service = state.Status
	}
	fmt.Fprintln(a.out, "service:", service)
	e, err := data.Load()
	if errors.Is(err, agent.ErrNotEnrolled) {
		fmt.Fprintln(a.out, "enrollment: none")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "enrollment: device %s, client %s, since %s\n", e.DeviceID, e.Client, e.EnrolledAt.Format(time.RFC3339))
	return nil
}

func (a *application) runAgent(ctx context.Context, args []string) error {
	data, err := dataFlag("run", args, a.errOut)
	if err != nil {
		return err
	}
	return a.runService(ctx, data, func(runCtx context.Context, logOut io.Writer) error {
		return serve(runCtx, data, logOut)
	})
}

func serve(ctx context.Context, data agent.DataDir, logOut io.Writer) error {
	logger := slog.New(slog.NewJSONHandler(logOut, nil))
	e, err := data.Load()
	if err != nil {
		return err
	}
	host, gatherErr := hostinfo.Gather(ctx)
	if gatherErr != nil {
		logger.Warn("some host facts unavailable", "err", gatherErr)
	}
	r, err := redact.New()
	if err != nil {
		return err
	}
	m, err := mirror.Open(logger)
	if err != nil {
		return err
	}
	defer m.Close(5 * time.Second)
	// The structured remediation store lives inside the agent's private data
	// dir, so it inherits its ACL (SYSTEM/Administrators on Windows, 0700 root
	// elsewhere). Reconcile any temporary file an interrupted apply left before
	// serving; without a ChangeDir the change ops answer ErrUnsupported and the
	// agent stays read-only. newConsent returns the consent adapter (technician
	// unlocks approved here, everything else routed to the consent window where
	// there is one) and, on Windows, the window's plan review; elsewhere there
	// is no plan review, and a change under a technician grant needs the
	// technician's approval instead.
	changeDir := data.File(agent.ChangeSubdir)
	if err := fstools.CleanupChangeStore(changeDir, logger); err != nil {
		logger.Warn("change store startup cleanup failed; structured remediation may be unavailable", "err", err)
	}
	consent, planApprover, err := newConsent(ctx, e, host, logger)
	if err != nil {
		return err
	}
	x := fstools.New(fstools.Options{Redactor: r, AgentVersion: version.Version, Logger: logger,
		ChangeDir: changeDir, PlanApprover: planApprover})
	runner, err := agent.NewRunner(agent.RunnerOptions{
		Enrollment: e, CredsFile: data.CredsPath(), Executor: x, Mirror: m, Host: host, Logger: logger,
		Consent: consent, GrantsFile: data.File(agent.GrantsFile),
	})
	if err != nil {
		return err
	}
	return runner.Run(ctx)
}
