//go:build windows

package mirror

import (
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/eventlog"
)

// sourceKey is where Install registers the event source.
const sourceKey = `SYSTEM\CurrentControlSet\Services\EventLog\Application\` + Source

// Open starts a Mirror writing to the Application event log as Source.
func Open(logger *slog.Logger) (*Mirror, error) {
	l, err := eventlog.Open(Source)
	if err != nil {
		return nil, fmt.Errorf("mirror: open event log source %q: %w", Source, err)
	}
	return newMirror(eventLogSink{l}, logger), nil
}

type eventLogSink struct{ l *eventlog.Log }

func (s eventLogSink) write(r record) error {
	switch r.level {
	case levelWarning:
		return s.l.Warning(r.event, r.line)
	case levelError:
		return s.l.Error(r.event, r.line)
	default:
		return s.l.Info(r.event, r.line)
	}
}

func (s eventLogSink) close() error { return s.l.Close() }

// Install registers Source in the Application log, using EventCreate.exe as
// its message file. It is idempotent. Requires administrator rights.
func Install() error {
	err := eventlog.InstallAsEventCreate(Source, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err == nil {
		return nil
	}
	if k, oerr := registry.OpenKey(registry.LOCAL_MACHINE, sourceKey, registry.QUERY_VALUE); oerr == nil {
		k.Close()
		return nil // already registered by an earlier install
	}
	return fmt.Errorf("mirror: register event source %q: %w", Source, err)
}

// Uninstall removes the event source registration. A missing registration
// is not an error.
func Uninstall() error {
	err := eventlog.Remove(Source)
	if err == nil || errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("mirror: remove event source %q: %w", Source, err)
}
