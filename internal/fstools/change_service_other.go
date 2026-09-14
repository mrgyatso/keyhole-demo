//go:build !windows && !linux

package fstools

import (
	"context"
	"runtime"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Only Windows (the Service Control Manager) and Linux (systemd) have service
// primitives. Everywhere else the ops exist in the protocol and refuse, rather
// than pretending launchd or another init can be driven the same way.

func queryService(context.Context, string) (proto.ServiceResult, error) {
	return proto.ServiceResult{}, failf(proto.ErrUnsupported, "service operations are not implemented on %s", runtime.GOOS)
}

func restartService(context.Context, string) (proto.ServiceResult, error) {
	return proto.ServiceResult{}, failf(proto.ErrUnsupported, "service operations are not implemented on %s", runtime.GOOS)
}
