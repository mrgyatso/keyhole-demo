package fstools

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Service control goes through the Service Control Manager, never through a
// command line: the name is all that crosses the boundary, so there is nothing
// to quote, escape or inject.

const (
	serviceSettle  = 60 * time.Second       // ceiling on one stop or one start
	servicePollGap = 250 * time.Millisecond // how often the SCM is asked again
)

func queryService(ctx context.Context, name string) (proto.ServiceResult, error) {
	m, s, err := openService(name)
	if err != nil {
		return proto.ServiceResult{}, err
	}
	defer closeService(m, s)
	return describe(s)
}

func restartService(ctx context.Context, name string) (proto.ServiceResult, error) {
	m, s, err := openService(name)
	if err != nil {
		return proto.ServiceResult{}, err
	}
	defer closeService(m, s)
	before, err := describe(s)
	if err != nil {
		return proto.ServiceResult{}, err
	}
	if before.State != proto.ServiceStopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return proto.ServiceResult{}, failf(proto.ErrIO, "stopping %s: %v", name, err)
		}
		if err := settle(ctx, s, svc.Stopped, name); err != nil {
			return proto.ServiceResult{}, err
		}
	}
	if err := s.Start(); err != nil {
		return proto.ServiceResult{}, failf(proto.ErrIO, "starting %s: %v", name, err)
	}
	if err := settle(ctx, s, svc.Running, name); err != nil {
		return proto.ServiceResult{}, err
	}
	out, err := describe(s)
	if err != nil {
		return proto.ServiceResult{}, err
	}
	out.StateBefore = before.State
	return out, nil
}

func openService(name string) (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, failf(proto.ErrIO, "cannot reach the service control manager: %v", err)
	}
	s, err := m.OpenService(name)
	if err != nil {
		m.Disconnect()
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) || errors.Is(err, fs.ErrNotExist) {
			return nil, nil, failf(proto.ErrNotFound, "there is no service named %s on this machine", name)
		}
		return nil, nil, failf(proto.ErrIO, "opening service %s: %v", name, err)
	}
	return m, s, nil
}

func closeService(m *mgr.Mgr, s *mgr.Service) {
	s.Close()
	m.Disconnect()
}

func describe(s *mgr.Service) (proto.ServiceResult, error) {
	st, err := s.Query()
	if err != nil {
		return proto.ServiceResult{}, failf(proto.ErrIO, "querying %s: %v", s.Name, err)
	}
	res := proto.ServiceResult{Name: s.Name, PID: int(st.ProcessId),
		State: serviceState(st.State == svc.Running, st.State == svc.Stopped,
			st.State == svc.StartPending, st.State == svc.StopPending)}
	if cfg, err := s.Config(); err == nil {
		res.DisplayName, res.StartType = cfg.DisplayName, startType(cfg.StartType)
	}
	return res, nil
}

func startType(t uint32) string {
	switch t {
	case mgr.StartAutomatic:
		return "automatic"
	case mgr.StartManual:
		return "manual"
	case mgr.StartDisabled:
		return "disabled"
	}
	return "unknown"
}

// settle waits for the service to reach want, or for the request's context or
// the settle ceiling to run out.
func settle(ctx context.Context, s *mgr.Service, want svc.State, name string) error {
	deadline := time.Now().Add(serviceSettle)
	for {
		st, err := s.Query()
		if err != nil {
			return failf(proto.ErrIO, "querying %s: %v", name, err)
		}
		if st.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return failf(proto.ErrTimeout, "%s did not reach the expected state within %s", name, serviceSettle)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(servicePollGap):
		}
	}
}
