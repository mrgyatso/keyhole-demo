//go:build darwin

package hostinfo

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Absolute paths: the agent runs as root, so PATH is not trusted.
const (
	ioregPath  = "/usr/sbin/ioreg"
	swVersPath = "/usr/bin/sw_vers"
)

func machineID(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, ioregPath, "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", fmt.Errorf("ioreg: %w", err)
	}
	return parseIOPlatformUUID(out)
}

func osVersion(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, swVersPath, "-productVersion").Output()
	if err != nil {
		return "", fmt.Errorf("sw_vers: %w", err)
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "", fmt.Errorf("sw_vers printed nothing")
	}
	return "macOS " + v, nil
}
