//go:build !windows

package main

import (
	"context"
	"log/slog"

	"github.com/mrgyatso/keyhole/internal/agent"
	"github.com/mrgyatso/keyhole/internal/agent/hostinfo"
	"github.com/mrgyatso/keyhole/internal/fstools"
)

// newConsent returns the consent adapter of a platform without a local consent
// application. Keyhole's consent UI is Windows-only, so here a request a
// technician unlock authorises on its own is approved without a person, and
// every request that needs the person at the machine is refused. There is no
// plan review either: a change under a technician grant needs the
// technician's approval instead. The client-bound read path is unchanged.
func newConsent(_ context.Context, _ *agent.Enrollment, _ hostinfo.Info, log *slog.Logger) (agent.ConsentAdapter, fstools.ChangeApprover, error) {
	return agent.RoutedConsent{Technician: agent.TechnicianConsent{Logger: log}}, nil, nil
}
