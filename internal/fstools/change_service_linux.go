package fstools

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Linux service control is systemd, driven through systemctl with a fixed
// argument vector and never a shell: the unit name is passed as one argument,
// and it has already passed policy.CheckServiceName, so there is nothing to
// quote or escape. Everything systemctl writes to stderr stays on the endpoint
// except the first line, which becomes the error message.

const systemctlTimeout = 90

func queryService(ctx context.Context, name string) (proto.ServiceResult, error) {
	out, err := systemctl(ctx, "show", unit(name),
		"--property=Id", "--property=Description", "--property=ActiveState",
		"--property=SubState", "--property=UnitFileState", "--property=MainPID")
	if err != nil {
		return proto.ServiceResult{}, err
	}
	props := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	if props["Id"] == "" || props["ActiveState"] == "" {
		return proto.ServiceResult{}, failf(proto.ErrNotFound, "there is no unit named %s on this machine", unit(name))
	}
	pid, _ := strconv.Atoi(props["MainPID"])
	active, sub := props["ActiveState"], props["SubState"]
	return proto.ServiceResult{
		Name:        props["Id"],
		DisplayName: props["Description"],
		StartType:   props["UnitFileState"],
		PID:         pid,
		State: serviceState(active == "active" && sub != "start" && sub != "stop",
			active == "inactive" || active == "failed",
			active == "activating", active == "deactivating"),
	}, nil
}

func restartService(ctx context.Context, name string) (proto.ServiceResult, error) {
	before, err := queryService(ctx, name)
	if err != nil {
		return proto.ServiceResult{}, err
	}
	if _, err := systemctl(ctx, "restart", unit(name)); err != nil {
		return proto.ServiceResult{}, err
	}
	out, err := queryService(ctx, name)
	if err != nil {
		return proto.ServiceResult{}, err
	}
	out.StateBefore = before.State
	return out, nil
}

// unit gives a bare name systemd's default suffix, so "vendor" and
// "vendor.service" name the same unit in the policy allow list.
func unit(name string) string {
	if strings.ContainsRune(name, '.') {
		return name
	}
	return name + ".service"
}

func systemctl(ctx context.Context, args ...string) (string, error) {
	bin, err := exec.LookPath("systemctl")
	if err != nil {
		return "", failf(proto.ErrUnsupported, "this machine has no systemctl, so services cannot be managed through Keyhole")
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr, cmd.Env = &stdout, &stderr, []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		msg, _, _ := strings.Cut(strings.TrimSpace(stderr.String()), "\n")
		if msg == "" {
			msg = err.Error()
		}
		return "", failf(proto.ErrIO, "systemctl %s: %s", args[0], msg)
	}
	return stdout.String(), nil
}
