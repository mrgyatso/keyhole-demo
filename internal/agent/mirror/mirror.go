// Package mirror writes the agent's local copy of the audit trail: the
// Windows Event Log (Application log, source "Keyhole") or syslog (tag
// "keyhole-agent"). It exists so the client's own SIEM sees every read the
// AI made on their machines, independently of the MSP's audit log.
//
// The mirror is best effort. Records are queued and written by one
// background goroutine; a full queue or a failed write is logged and the
// record dropped. It never fails or delays a reply.
//
// Each record is one line of JSON, which SIEMs parse natively and which
// keeps Windows paths unambiguous.
package mirror

import (
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Source is the Windows event source; SyslogTag is the syslog tag.
const (
	Source    = "Keyhole"
	SyslogTag = "keyhole-agent"
)

// Event IDs. The Windows Event Log shows them as the event ID; syslog
// records carry them as "event_id".
const (
	EventOK        = 1000
	EventDenied    = 1001 // not_allowed, hard_denied, unsafe_path
	EventError     = 1002
	EventLifecycle = 2000 // start, stop, connect, disconnect, enroll
)

// Lifecycle events.
const (
	Start      = "start"
	Stop       = "stop"
	Connect    = "connect"
	Disconnect = "disconnect"
	Enroll     = "enroll"
)

// Results recorded for a Call, matching the relay's audit results.
const (
	ResultOK     = "ok"
	ResultDenied = "denied"
	ResultError  = "error"
)

// Call is one request the agent handled.
type Call struct {
	DeviceID     string `json:"device_id,omitempty"`
	RequestID    string `json:"request_id"`
	Tech         string `json:"tech,omitempty"`
	Session      string `json:"session,omitempty"`
	Op           string `json:"op"`
	Path         string `json:"path,omitempty"` // as requested
	ResolvedPath string `json:"resolved_path,omitempty"`
	RuleID       string `json:"rule_id,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"` // empty on success
	Bytes        int64  `json:"bytes"`
	SHA256       string `json:"sha256,omitempty"`
	Redactions   int    `json:"redactions"`
}

// Classify maps a proto error code ("" for success) to the record's event ID
// and result.
func Classify(code string) (event uint32, result string) {
	switch code {
	case "":
		return EventOK, ResultOK
	case proto.ErrNotAllowed, proto.ErrHardDenied, proto.ErrUnsafePath:
		return EventDenied, ResultDenied
	default:
		return EventError, ResultError
	}
}

// level maps onto the Event Log entry type and the syslog severity.
type level int

const (
	levelInfo level = iota
	levelWarning
	levelError
)

type record struct {
	event uint32
	level level
	line  string
}

// sink is where records end up.
type sink interface {
	write(record) error
	close() error
}

// queueSize bounds the backlog; beyond it records are dropped.
const queueSize = 1024

// Mirror is the local audit copy. Its methods are safe for concurrent use
// and never block.
type Mirror struct {
	sink sink
	log  *slog.Logger
	q    chan record
	done chan struct{}

	mu      sync.RWMutex // guards closed against sends on a closed q
	closed  bool
	dropped atomic.Int64
}

func newMirror(s sink, logger *slog.Logger) *Mirror {
	if logger == nil {
		logger = slog.Default()
	}
	m := &Mirror{sink: s, log: logger, q: make(chan record, queueSize), done: make(chan struct{})}
	go m.loop()
	return m
}

func (m *Mirror) loop() {
	defer close(m.done)
	for r := range m.q {
		if err := m.sink.write(r); err != nil {
			m.log.Warn("audit mirror: write failed", "event_id", r.event, "err", err)
		}
	}
}

// Call records one handled request.
func (m *Mirror) Call(c Call) {
	event, result := Classify(c.ErrorCode)
	lvl := levelInfo
	switch result {
	case ResultDenied:
		lvl = levelWarning
	case ResultError:
		lvl = levelError
	}
	line := struct {
		EventID uint32 `json:"event_id"`
		Kind    string `json:"kind"`
		Result  string `json:"result"`
		Call
	}{event, "call", result, c}
	m.enqueue(event, lvl, line)
}

// Lifecycle records an agent lifecycle event; detail may be empty.
func (m *Mirror) Lifecycle(event, detail string) {
	line := struct {
		EventID uint32 `json:"event_id"`
		Kind    string `json:"kind"`
		Event   string `json:"event"`
		Detail  string `json:"detail,omitempty"`
		Time    string `json:"time"`
	}{EventLifecycle, "lifecycle", event, detail, time.Now().UTC().Format(time.RFC3339)}
	m.enqueue(EventLifecycle, levelInfo, line)
}

func (m *Mirror) enqueue(event uint32, lvl level, v any) {
	if m == nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		m.log.Warn("audit mirror: encode failed", "event_id", event, "err", err)
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return
	}
	select {
	case m.q <- record{event: event, level: lvl, line: string(b)}:
	default:
		if n := m.dropped.Add(1); n == 1 || n%1000 == 0 {
			m.log.Warn("audit mirror: queue full, dropping records", "dropped", n)
		}
	}
}

// Close writes what is queued, waiting at most timeout, and closes the sink.
func (m *Mirror) Close(timeout time.Duration) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	close(m.q)
	m.mu.Unlock()

	var err error
	select {
	case <-m.done:
	case <-time.After(timeout):
		err = errors.New("audit mirror: timed out flushing queued records")
	}
	return errors.Join(err, m.sink.close())
}

// Dropped reports how many records were dropped because the queue was full.
func (m *Mirror) Dropped() int64 { return m.dropped.Load() }
