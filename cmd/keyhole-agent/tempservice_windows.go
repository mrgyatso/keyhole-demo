//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/mrgyatso/keyhole/internal/agent"
	"github.com/mrgyatso/keyhole/internal/agent/mirror"
)

// The temporary install's Windows footprint, all of it distinct from the
// managed install's: its own service, its own binary next to (never over) the
// managed one, and its own data directory under the temp root.
func tempExecutable() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "Keyhole", "keyhole-agent-temp.exe")
}

// installTempService copies the helper to its own path and registers
// KeyholeTemp. StartType is automatic on purpose: if the machine reboots
// mid-session, the service starts again and finishes the cleanup rather than
// leaving an enrolled device behind.
func installTempService(_ context.Context, source string, data agent.DataDir) (err error) {
	dst := tempExecutable()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := protectProgramDir(filepath.Dir(dst)); err != nil {
		return err
	}
	if !samePath(source, dst) {
		if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale temporary executable: %w", err)
		}
		if err := copyExecutable(source, dst); err != nil {
			return err
		}
	}
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
	s, err := m.CreateService(tempServiceName, dst, mgr.Config{
		DisplayName:      "Keyhole Temporary Session",
		Description:      "One-off, self-removing Keyhole support session",
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "LocalSystem",
		Dependencies:     []string{"Tcpip"},
	}, "temporary-run", "--data", string(data))
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

// removeTempService deregisters KeyholeTemp and the event source. It is
// called from inside the service itself, so Delete only marks the service for
// deletion; Windows removes it when this process stops, moments later.
//
// The managed service's event source is the same one. Temporary mode refuses
// to start beside a managed install, but one can be installed while a session
// runs, so the source is kept whenever the managed service exists by now.
func removeTempService(ctx context.Context) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(tempServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return removeTempEventSource(m)
	}
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return err
	}
	return removeTempEventSource(m)
}

// removeTempEventSource removes the shared event source only when the managed
// service is confirmed absent. A stale registry key costs nothing; removing a
// managed install's source breaks its local audit mirror.
func removeTempEventSource(m *mgr.Mgr) error {
	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return nil
	}
	if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	return mirror.Uninstall()
}

func tempServiceStatus(context.Context) (serviceState, error) {
	m, err := mgr.Connect()
	if err != nil {
		return serviceState{}, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(tempServiceName)
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

// removeTempExecutable deletes the copied binary. A running image cannot
// delete itself on Windows, so this uses two mechanisms, in order:
//
//  1. A detached `cmd /c ping … & del …` that outlives this process, waits
//     for it to exit, removes the exe and then the directory if it is empty.
//     This is what leaves the machine clean without a reboot.
//  2. MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT, used when the helper
//     cannot be started (a locked-down machine, no comspec). The file is
//     gone after the next restart; nothing runs it in the meantime because
//     the service registration is already deleted.
//
// A file that is already absent is success: cleanup runs more than once when
// a session was interrupted.
func removeTempExecutable(context.Context) error {
	exe := tempExecutable()
	if _, err := os.Stat(exe); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	// Unix semantics do apply to a file no one has open, so try the cheap way
	// first: if this process is not the copied binary, it deletes now.
	if err := os.Remove(exe); err == nil {
		_ = os.Remove(filepath.Dir(exe))
		return nil
	}
	if err := spawnSelfDelete(exe); err == nil {
		return nil
	} else {
		if merr := markForDeletionOnReboot(exe); merr != nil {
			return errors.Join(err, merr)
		}
	}
	return nil
}

// spawnSelfDelete starts the detached deleter. DETACHED_PROCESS plus
// CREATE_NEW_PROCESS_GROUP keeps it alive after this process and its console
// are gone; nothing of ours waits on it.
func spawnSelfDelete(exe string) error {
	comspec := os.Getenv("ComSpec")
	if comspec == "" {
		comspec = filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	}
	if _, err := os.Stat(comspec); err != nil {
		return fmt.Errorf("no command interpreter to delete %s: %w", exe, err)
	}
	line, err := selfDeleteCommandLine(comspec, exe, filepath.Dir(exe))
	if err != nil {
		return err
	}
	// CmdLine is passed to CreateProcess verbatim; os/exec's own quoting is
	// wrong for cmd.exe (see selfDeleteCommandLine).
	cmd := exec.Command(comspec)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine:       line,
		HideWindow:    true,
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the deferred delete of %s: %w", exe, err)
	}
	return cmd.Process.Release()
}

// markForDeletionOnReboot is the fallback: the file is removed by the session
// manager during the next boot, before anything could run it.
func markForDeletionOnReboot(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
		return fmt.Errorf("schedule %s for deletion at reboot: %w", path, err)
	}
	return nil
}

// runTempUnderServiceManager runs the temporary lifecycle under KeyholeTemp,
// or directly when it is invoked from a console.
func runTempUnderServiceManager(ctx context.Context, data agent.DataDir, run func(context.Context, io.Writer) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return run(ctx, os.Stderr)
	}
	return svc.Run(tempServiceName, &serviceHandler{data: data, run: run})
}

// stopTempService is used by tests and by an operator ending a session by
// hand; the service's own shutdown path does the cleanup.
func stopTempService(ctx context.Context) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(tempServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil || st.State == svc.Stopped {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.New("the temporary service did not stop within 60 seconds")
}
