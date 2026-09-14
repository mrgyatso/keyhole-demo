//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mrgyatso/keyhole/internal/agent"
)

const (
	darwinExecutable = "/Library/Keyhole/keyhole-agent"
	darwinPlist      = "/Library/LaunchDaemons/dev.example.keyhole-agent.plist"
	darwinLabel      = "dev.example.keyhole-agent"
)

func samePath(a, b string) bool { return a == b }

func installService(ctx context.Context, source string, data agent.DataDir) error {
	if err := data.Ensure(); err != nil {
		return err
	}
	if !samePath(source, darwinExecutable) {
		if err := os.Remove(darwinExecutable); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := copyExecutable(source, darwinExecutable); err != nil {
			return err
		}
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>` + darwinLabel + `</string>
<key>ProgramArguments</key><array><string>` + darwinExecutable + `</string><string>run</string><string>--data</string><string>` + xmlEscape(string(data)) + `</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
`
	if err := os.WriteFile(darwinPlist, []byte(plist), 0o644); err != nil {
		return err
	}
	if out, err := exec.CommandContext(ctx, "launchctl", "bootstrap", "system", darwinPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func uninstallService(ctx context.Context) error {
	_, _ = exec.CommandContext(ctx, "launchctl", "bootout", "system/"+darwinLabel).CombinedOutput()
	for _, p := range []string{darwinPlist, darwinExecutable} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_ = os.Remove(filepath.Dir(darwinExecutable))
	return nil
}

func serviceStatus(ctx context.Context) (serviceState, error) {
	if _, err := os.Stat(darwinPlist); errors.Is(err, os.ErrNotExist) {
		return serviceState{}, nil
	} else if err != nil {
		return serviceState{}, err
	}
	err := exec.CommandContext(ctx, "launchctl", "print", "system/"+darwinLabel).Run()
	status := "running"
	if err != nil {
		status = "not loaded"
	}
	return serviceState{Installed: true, Status: status}, nil
}

func runUnderServiceManager(ctx context.Context, _ agent.DataDir, run func(context.Context, io.Writer) error) error {
	return run(ctx, os.Stderr)
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}
