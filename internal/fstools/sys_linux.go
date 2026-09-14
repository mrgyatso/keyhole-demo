package fstools

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// finalPath returns the path the kernel holds for an open file: the target
// of /proc/self/fd/N.
func finalPath(f *os.File) (string, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return "", err
	}
	var p string
	var perr error
	if err := rc.Control(func(fd uintptr) {
		p, perr = os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(fd), 10))
	}); err != nil {
		return "", err
	}
	switch {
	case perr != nil:
		return "", fmt.Errorf("readlink /proc/self/fd: %w", perr)
	case !strings.HasPrefix(p, "/"):
		return "", fmt.Errorf("open file has no filesystem path (%q)", p)
	case strings.HasSuffix(p, " (deleted)"):
		return "", errors.New("the file was deleted while it was being opened")
	}
	return p, nil
}
