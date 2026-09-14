// Package hostinfo gathers the facts the agent reports about its machine,
// at enrollment and in its hello and ping replies.
package hostinfo

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Info describes the machine the agent runs on.
type Info struct {
	Hostname  string
	MachineID string // stable per OS install: MachineGuid, /etc/machine-id, IOPlatformUUID
	OS        string // runtime.GOOS
	OSVersion string // human-readable, e.g. "Windows Server 2025 Datacenter 24H2 (build 26100.1742)"
	Arch      string // runtime.GOARCH
}

// Gather collects Info. A fact that cannot be read is left empty and its
// error joined into err, so the caller decides which facts it needs.
func Gather(ctx context.Context) (Info, error) {
	info := Info{OS: runtime.GOOS, Arch: runtime.GOARCH}
	var errs []error
	var err error
	if info.Hostname, err = os.Hostname(); err != nil {
		errs = append(errs, fmt.Errorf("hostinfo: hostname: %w", err))
	}
	if info.MachineID, err = machineID(ctx); err != nil {
		errs = append(errs, fmt.Errorf("hostinfo: machine id: %w", err))
	}
	if info.OSVersion, err = osVersion(ctx); err != nil {
		errs = append(errs, fmt.Errorf("hostinfo: os version: %w", err))
	}
	return info, errors.Join(errs...)
}

// parseOSRelease returns a display name from an os-release file:
// PRETTY_NAME, or NAME and VERSION_ID.
func parseOSRelease(data []byte) string {
	vals := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `"'`)
		}
		vals[k] = v
	}
	if p := vals["PRETTY_NAME"]; p != "" {
		return p
	}
	return strings.TrimSpace(vals["NAME"] + " " + vals["VERSION_ID"])
}

// parseIOPlatformUUID extracts IOPlatformUUID from
// `ioreg -rd1 -c IOPlatformExpertDevice` output.
func parseIOPlatformUUID(out []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		rest, ok := strings.CutPrefix(line, `"IOPlatformUUID"`)
		if !ok {
			continue
		}
		_, val, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		if id := strings.Trim(strings.TrimSpace(val), `"`); id != "" {
			return id, nil
		}
	}
	return "", errors.New("IOPlatformUUID not found in ioreg output")
}

// windowsVersion formats the CurrentVersion registry values. Windows 11
// still reports ProductName "Windows 10 …"; build 22000 is the first
// Windows 11 build, and server editions are named correctly.
func windowsVersion(product, display, build string, ubr uint64) string {
	if n, err := strconv.Atoi(build); err == nil && n >= 22000 {
		if rest, ok := strings.CutPrefix(product, "Windows 10"); ok {
			product = "Windows 11" + rest
		}
	}
	s := product
	if s == "" {
		s = "Windows"
	}
	if display != "" {
		s += " " + display
	}
	if build != "" {
		s += " (build " + build
		if ubr > 0 {
			s += "." + strconv.FormatUint(ubr, 10)
		}
		s += ")"
	}
	return s
}
