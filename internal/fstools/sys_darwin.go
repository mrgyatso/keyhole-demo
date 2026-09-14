package fstools

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// pathBufs holds F_GETPATH buffers. They come from the heap, which the Go
// garbage collector never moves, so passing a buffer's address to fcntl as
// an integer is safe.
var pathBufs = sync.Pool{New: func() any { return new([unix.PathMax]byte) }}

// finalPath returns the path the kernel holds for an open file, via
// fcntl(F_GETPATH). It reports firmlinked paths as users see them
// (/Users, /private/var) rather than under /System/Volumes/Data.
func finalPath(f *os.File) (string, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return "", err
	}
	buf := pathBufs.Get().(*[unix.PathMax]byte)
	defer pathBufs.Put(buf)
	var ferr error
	if err := rc.Control(func(fd uintptr) {
		_, ferr = unix.FcntlInt(fd, unix.F_GETPATH, int(uintptr(unsafe.Pointer(&buf[0]))))
	}); err != nil {
		return "", err
	}
	runtime.KeepAlive(buf)
	if ferr != nil {
		return "", fmt.Errorf("fcntl F_GETPATH: %w", ferr)
	}
	return unix.ByteSliceToString(buf[:]), nil
}
