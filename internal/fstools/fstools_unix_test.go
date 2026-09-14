//go:build linux || darwin

package fstools

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// A FIFO inside an allowed directory must be refused without being opened:
// opening one for reading blocks until a writer appears.
func TestFIFOIsRefusedWithoutBlocking(t *testing.T) {
	root := tempRoot(t)
	fifo := filepath.Join(root, "pipe.log")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	x := New(Options{})
	pol := testPolicy(rootRule(root))
	done := make(chan *proto.Response, 2)
	go func() { done <- run(t, x, proto.OpReadFile, proto.ReadFileArgs{Path: fifo}, pol) }()
	go func() { done <- run(t, x, proto.OpStat, proto.StatArgs{Path: fifo}, pol) }()
	for range 2 {
		select {
		case resp := <-done:
			wantError(t, resp, proto.ErrNotRegular)
		case <-time.After(5 * time.Second):
			t.Fatal("the agent blocked on a FIFO")
		}
	}
}
