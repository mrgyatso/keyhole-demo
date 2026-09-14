//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mrgyatso/keyhole/internal/agent"
)

const (
	linuxExecutable = "/usr/local/lib/keyhole/keyhole-agent"
	linuxUnit       = "/etc/systemd/system/keyhole-agent.service"
)

func samePath(a, b string) bool { return a == b }

func installService(ctx context.Context, source string, data agent.DataDir) error {
	if err := data.Ensure(); err != nil {
		return err
	}
	if !samePath(source, linuxExecutable) {
		if err := os.Remove(linuxExecutable); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := copyExecutable(source, linuxExecutable); err != nil {
			return err
		}
	}
	unit := "[Unit]\nDescription=Keyhole Endpoint Agent\nAfter=network-online.target\nWants=network-online.target\n\n" +
		"[Service]\nType=simple\nExecStart=" + strconv.Quote(linuxExecutable) + " run --data " + strconv.Quote(string(data)) + "\n" +
		"Restart=always\nRestartSec=5s\nUser=root\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths=" + strconv.Quote(string(data)) + "\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
	if err := os.WriteFile(linuxUnit, []byte(unit), 0o644); err != nil {
		return err
	}
	if out, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "systemctl", "enable", "--now", "keyhole-agent.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func uninstallService(ctx context.Context) error {
	_, _ = exec.CommandContext(ctx, "systemctl", "disable", "--now", "keyhole-agent.service").CombinedOutput()
	if err := os.Remove(linuxUnit); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, _ = exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput()
	if err := os.Remove(linuxExecutable); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove(filepath.Dir(linuxExecutable))
	return nil
}

func serviceStatus(ctx context.Context) (serviceState, error) {
	if _, err := os.Stat(linuxUnit); errors.Is(err, os.ErrNotExist) {
		return serviceState{}, nil
	} else if err != nil {
		return serviceState{}, err
	}
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", "keyhole-agent.service").Output()
	status := strings.TrimSpace(string(out))
	if err != nil && status == "" {
		status = "inactive"
	}
	return serviceState{Installed: true, Status: status}, nil
}

func runUnderServiceManager(ctx context.Context, _ agent.DataDir, run func(context.Context, io.Writer) error) error {
	return run(ctx, os.Stderr)
}
