//go:build linux

package hostinfo

import (
	"context"
	"errors"
	"os"
	"strings"
)

func machineID(context.Context) (string, error) {
	var errs []error
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		b, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// systemd writes "uninitialized" until first boot completes.
		if id := strings.TrimSpace(string(b)); id != "" && id != "uninitialized" {
			return id, nil
		}
		errs = append(errs, errors.New(p+" is empty"))
	}
	return "", errors.Join(errs...)
}

func osVersion(context.Context) (string, error) {
	var errs []error
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		b, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if v := parseOSRelease(b); v != "" {
			return v, nil
		}
		errs = append(errs, errors.New(p+" names no OS"))
	}
	return "", errors.Join(errs...)
}
