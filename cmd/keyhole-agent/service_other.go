//go:build !windows && !linux && !darwin

package main

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/mrgyatso/keyhole/internal/agent"
)

func samePath(a, b string) bool { return a == b }
func installService(context.Context, string, agent.DataDir) error {
	return errors.New("service installation is not supported on this operating system")
}
func uninstallService(context.Context) error              { return nil }
func serviceStatus(context.Context) (serviceState, error) { return serviceState{}, nil }
func runUnderServiceManager(ctx context.Context, _ agent.DataDir, run func(context.Context, io.Writer) error) error {
	return run(ctx, os.Stderr)
}
