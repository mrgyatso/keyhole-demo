package mirror

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

type memSink struct {
	mu      sync.Mutex
	recs    []record
	block   chan struct{} // if set, write waits on it
	fail    bool
	closed  bool
	written chan struct{}
}

func (s *memSink) write(r record) error {
	if s.block != nil {
		<-s.block
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, r)
	if s.written != nil {
		s.written <- struct{}{}
	}
	if s.fail {
		return errors.New("sink down")
	}
	return nil
}

func (s *memSink) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *memSink) all() []record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]record(nil), s.recs...)
}

func TestCallRecords(t *testing.T) {
	s := &memSink{}
	m := newMirror(s, nil)
	m.Call(Call{DeviceID: "dev_1", RequestID: "req_ok", Tech: "alice", Session: "ses_1", Op: proto.OpReadFile,
		Path: `C:\Windows\Logs\CBS\CBS.log`, ResolvedPath: `C:\Windows\Logs\CBS\CBS.log`, RuleID: "win-logs",
		Bytes: 42, SHA256: "abc", Redactions: 2})
	m.Call(Call{RequestID: "req_denied", Op: proto.OpReadFile, Path: `C:\Windows\System32\config\SAM`, ErrorCode: proto.ErrHardDenied})
	m.Call(Call{RequestID: "req_err", Op: proto.OpGrep, ErrorCode: proto.ErrIO})
	m.Lifecycle(Connect, "wss://relay.example/nats")
	if err := m.Close(time.Second); err != nil {
		t.Fatal(err)
	}
	recs := s.all()
	if len(recs) != 4 || !s.closed {
		t.Fatalf("got %d records, closed=%v", len(recs), s.closed)
	}
	want := []struct {
		event  uint32
		level  level
		result string
	}{{EventOK, levelInfo, ResultOK}, {EventDenied, levelWarning, ResultDenied}, {EventError, levelError, ResultError}}
	for i, w := range want {
		var got map[string]any
		if err := json.Unmarshal([]byte(recs[i].line), &got); err != nil {
			t.Fatalf("record %d is not JSON: %v: %s", i, err, recs[i].line)
		}
		if recs[i].event != w.event || recs[i].level != w.level || got["result"] != w.result || got["event_id"] != float64(w.event) {
			t.Errorf("record %d = %+v %v", i, recs[i], got)
		}
	}
	var first map[string]any
	_ = json.Unmarshal([]byte(recs[0].line), &first)
	for k, v := range map[string]any{"request_id": "req_ok", "tech": "alice", "session": "ses_1", "op": "read_file",
		"path": `C:\Windows\Logs\CBS\CBS.log`, "rule_id": "win-logs", "bytes": float64(42), "sha256": "abc", "redactions": float64(2), "device_id": "dev_1"} {
		if first[k] != v {
			t.Errorf("%s = %v, want %v", k, first[k], v)
		}
	}
	if recs[3].event != EventLifecycle {
		t.Errorf("lifecycle event = %d", recs[3].event)
	}
}

func TestNeverBlocksAndDropsWhenFull(t *testing.T) {
	s := &memSink{block: make(chan struct{})}
	m := newMirror(s, nil)
	start := time.Now()
	for range queueSize + 100 {
		m.Call(Call{RequestID: "r", Op: proto.OpStat})
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("enqueue blocked for %v", d)
	}
	if m.Dropped() == 0 {
		t.Error("expected drops with a stuck sink")
	}
	close(s.block)
	if err := m.Close(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	m.Call(Call{RequestID: "after-close", Op: proto.OpStat}) // must not panic
}

func TestWriteFailureIsNotFatal(t *testing.T) {
	s := &memSink{fail: true, written: make(chan struct{}, 4)}
	m := newMirror(s, nil)
	m.Lifecycle(Start, "")
	m.Lifecycle(Stop, "")
	<-s.written
	<-s.written
	if err := m.Close(time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestNilMirrorIsNoop(t *testing.T) {
	var m *Mirror
	m.Call(Call{})
	m.Lifecycle(Start, "")
	if err := m.Close(time.Second); err != nil {
		t.Fatal(err)
	}
}
