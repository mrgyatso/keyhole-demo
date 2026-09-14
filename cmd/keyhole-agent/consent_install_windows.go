//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"

	"github.com/mrgyatso/keyhole/internal/agent/consentipc"
)

// runKey is where a per-machine logon entry lives: every user who signs in
// starts the consent application, so a request has a window to appear in.
const (
	runKey      = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValue    = "KeyholeConsent"
	consentName = consentipc.ConsentExecutable
)

// installConsentApp copies the consent application next to the service, in
// the same ACL-protected program directory, and registers it to run at logon
// for every user. The service refuses a pipe client running from anywhere
// else, so this location is part of the security boundary, not a
// convenience.
func installConsentApp(serviceExe string) error {
	src := filepath.Join(filepath.Dir(mustExecutable()), consentName)
	dst := filepath.Join(filepath.Dir(serviceExe), consentName)
	if samePath(src, dst) {
		return registerConsentAtLogon(dst)
	}
	if _, err := os.Stat(src); err != nil {
		// An agent shipped without the consent application still installs and
		// still serves client-bound reads; consented access then has nowhere
		// to ask, and every request is refused.
		return fmt.Errorf("consent application %s was not found beside the installer: %w", consentName, err)
	}
	if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale consent application: %w", err)
	}
	if err := copyExecutable(src, dst); err != nil {
		return err
	}
	return registerConsentAtLogon(dst)
}

func registerConsentAtLogon(path string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("register the consent application at logon: %w", err)
	}
	defer k.Close()
	return k.SetStringValue(runValue, `"`+path+`"`)
}

// removeConsentApp undoes installConsentApp.
func removeConsentApp(serviceExe string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE)
	if err == nil {
		if err := k.DeleteValue(runValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
			k.Close()
			return fmt.Errorf("remove the consent application logon entry: %w", err)
		}
		k.Close()
	} else if !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	dst := filepath.Join(filepath.Dir(serviceExe), consentName)
	if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the consent application: %w", err)
	}
	return nil
}

func mustExecutable() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return exe
}
