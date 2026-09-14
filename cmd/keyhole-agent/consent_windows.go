//go:build windows

package main

import (
	"context"
	"log/slog"

	"github.com/mrgyatso/keyhole/internal/agent"
	"github.com/mrgyatso/keyhole/internal/agent/consentipc"
	"github.com/mrgyatso/keyhole/internal/agent/hostinfo"
	"github.com/mrgyatso/keyhole/internal/fstools"
	"github.com/mrgyatso/keyhole/internal/version"
)

// newConsent starts the local consent transport and returns the adapter the
// runner asks for approval through, and the consent window's plan review. A
// request a technician unlock authorises on its own is approved without
// showing anything; the window is asked for legacy requests, and for those the
// client's policy also puts to the person at the machine. The service never
// shows a window of its own: it talks to the per-user consent application over
// a named pipe whose clients it verifies one by one.
func newConsent(ctx context.Context, e *agent.Enrollment, host hostinfo.Info, log *slog.Logger) (agent.ConsentAdapter, fstools.ChangeApprover, error) {
	srv, err := consentipc.NewServer(consentipc.ServerOptions{
		Logger: log,
		Hello: consentipc.Hello{Device: e.DeviceID, Client: e.Client, Hostname: host.Hostname,
			Agent: version.Version},
	})
	if err != nil {
		return nil, nil, err
	}
	go func() {
		if err := srv.Serve(ctx); err != nil {
			log.Error("consent pipe stopped", "err", err)
		}
	}()
	hub := srv.Adapter()
	return agent.RoutedConsent{Technician: agent.TechnicianConsent{Logger: log}, Endpoint: hub}, hub, nil
}
