//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/mrgyatso/keyhole/internal/agent"
	"github.com/mrgyatso/keyhole/internal/agent/mirror"
)

func samePath(a, b string) bool { return strings.EqualFold(a, b) }

func installedExecutable() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "Keyhole", "keyhole-agent.exe")
}

func installService(_ context.Context, source string, data agent.DataDir) (err error) {
	if err := data.Ensure(); err != nil {
		return err
	}
	dst := installedExecutable()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := protectProgramDir(filepath.Dir(dst)); err != nil {
		return err
	}
	// A stale binary with no registered service is safe to replace.
	if !samePath(source, dst) {
		if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale executable: %w", err)
		}
		if err := copyExecutable(source, dst); err != nil {
			return err
		}
	}
	// Slice 3: the per-user consent window lives beside the service and runs
	// at logon, so an access request has somewhere to appear.
	if err := installConsentApp(dst); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = removeConsentApp(dst)
		}
	}()
	if err := mirror.Install(); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = mirror.Uninstall()
		}
	}()
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.CreateService(serviceName, dst, mgr.Config{
		DisplayName:      "Keyhole Endpoint Agent",
		Description:      "Scoped, audited, read-only endpoint access for Keyhole",
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "LocalSystem",
		Dependencies:     []string{"Tcpip"},
	}, "run", "--data", string(data))
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = s.Delete()
		}
		s.Close()
	}()
	if err = s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

func protectProgramDir(path string) error {
	// The consent app is launched twice: first by the LocalSystem service in
	// the interactive user's session, then again by that user through UAC.
	// A filtered administrator token is not an effective Administrators SID,
	// so local users need read/execute access. They remain unable to alter the
	// installed binaries: only SYSTEM and Administrators have full control.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

func uninstallService(ctx context.Context) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	consentErr := removeConsentApp(installedExecutable()) // Slice 3
	s, err := m.OpenService(serviceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return errors.Join(consentErr, mirror.Uninstall())
	}
	if err != nil {
		return err
	}
	defer s.Close()
	st, qerr := s.Query()
	if qerr == nil && st.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		deadline := time.NewTimer(30 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for st.State != svc.Stopped {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-deadline.C:
				return errors.New("service did not stop within 30 seconds")
			case <-tick.C:
				st, err = s.Query()
				if err != nil {
					return err
				}
			}
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	return errors.Join(consentErr, mirror.Uninstall())
}

func serviceStatus(context.Context) (serviceState, error) {
	m, err := mgr.Connect()
	if err != nil {
		return serviceState{}, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return serviceState{}, nil
	}
	if err != nil {
		return serviceState{}, err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return serviceState{}, err
	}
	return serviceState{Installed: true, Status: stateName(st.State)}, nil
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continuing"
	case svc.PausePending:
		return "pausing"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("state-%d", s)
	}
}

func runUnderServiceManager(ctx context.Context, data agent.DataDir, run func(context.Context, io.Writer) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return run(ctx, os.Stderr)
	}
	return svc.Run(serviceName, &serviceHandler{data: data, run: run})
}

type serviceHandler struct {
	data agent.DataDir
	run  func(context.Context, io.Writer) error
}

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	if err := h.data.Ensure(); err != nil {
		return false, 1
	}
	logFile, err := os.OpenFile(h.data.File(agent.LogFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return false, 1
	}
	defer logFile.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx, logFile) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			status <- svc.Status{State: svc.Stopped}
			return false, boolCode(err != nil)
		case c := <-requests:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				err := <-done
				status <- svc.Status{State: svc.Stopped}
				return false, boolCode(err != nil)
			}
		}
	}
}

func boolCode(failed bool) uint32 {
	if failed {
		return 1
	}
	return 0
}
