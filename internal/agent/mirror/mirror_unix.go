//go:build !windows

package mirror

import (
	"fmt"
	"log/slog"
	"log/syslog"
)

// Open starts a Mirror writing to the local syslog daemon (the journal on
// systemd hosts, the unified log on macOS) with tag SyslogTag.
func Open(logger *slog.Logger) (*Mirror, error) {
	w, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, SyslogTag)
	if err != nil {
		return nil, fmt.Errorf("mirror: connect to syslog: %w", err)
	}
	return newMirror(syslogSink{w}, logger), nil
}

type syslogSink struct{ w *syslog.Writer }

func (s syslogSink) write(r record) error {
	switch r.level {
	case levelWarning:
		return s.w.Warning(r.line)
	case levelError:
		return s.w.Err(r.line)
	default:
		return s.w.Info(r.line)
	}
}

func (s syslogSink) close() error { return s.w.Close() }

// Install has nothing to register outside Windows.
func Install() error { return nil }

// Uninstall has nothing to remove outside Windows.
func Uninstall() error { return nil }
