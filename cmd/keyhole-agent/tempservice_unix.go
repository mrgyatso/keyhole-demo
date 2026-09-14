//go:build !windows

package main

import (
	"context"
	"io"
	"os"

	"github.com/mrgyatso/keyhole/internal/agent"
)

// Windows is the acceptance target for temporary installation. Elsewhere a
// temporary session runs in the foreground of the helper process: the same
// lifecycle, the same deadline, the same revocation, receipt and removal,
// supervised by the terminal instead of a service manager. Nothing is copied
// into a system location, so there is no binary to remove either.

func installTempService(context.Context, string, agent.DataDir) error {
	return errTempServiceUnsupported
}

func removeTempService(context.Context) error { return nil }

func tempServiceStatus(context.Context) (serviceState, error) { return serviceState{}, nil }

func removeTempExecutable(context.Context) error { return nil }

func runTempUnderServiceManager(ctx context.Context, _ agent.DataDir, run func(context.Context, io.Writer) error) error {
	return run(ctx, os.Stderr)
}
