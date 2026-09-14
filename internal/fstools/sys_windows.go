package fstools

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

const openFlags = os.O_RDONLY

// GetFinalPathNameByHandle flags; x/sys/windows does not name them.
const (
	fileNameNormalized = 0x0 // FILE_NAME_NORMALIZED: long names, resolved junctions
	volumeNameDOS      = 0x0 // VOLUME_NAME_DOS: \\?\C:\...
)

// isLink reports whether fi, from Lstat or a directory listing, is a
// symbolic link, junction or any other reparse point.
func isLink(fi fs.FileInfo) bool {
	if fi.Mode()&fs.ModeSymlink != 0 {
		return true
	}
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// handleIsReparse reports whether an open handle is a reparse point
// (FILE_ATTRIBUTE_REPARSE_POINT), which the agent refuses to read.
func handleIsReparse(f *os.File) (bool, error) {
	var d windows.ByHandleFileInformation
	var herr error
	if err := control(f, func(h windows.Handle) { herr = windows.GetFileInformationByHandle(h, &d) }); err != nil {
		return false, err
	}
	if herr != nil {
		return false, fmt.Errorf("GetFileInformationByHandle: %w", herr)
	}
	return d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}

// finalPath returns GetFinalPathNameByHandle for an open file, normalized
// (long names, junctions and symlinks resolved) and without the \\?\
// prefix. Files on network shares are refused.
func finalPath(f *os.File) (string, error) {
	var p string
	var perr error
	if err := control(f, func(h windows.Handle) { p, perr = finalPathOfHandle(h) }); err != nil {
		return "", err
	}
	return p, perr
}

func finalPathOfHandle(h windows.Handle) (string, error) {
	buf := make([]uint16, 512)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), fileNameNormalized|volumeNameDOS)
		if err != nil {
			return "", fmt.Errorf("GetFinalPathNameByHandle: %w", err)
		}
		if int(n) < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]uint16, n) // n is the size needed, terminating NUL included
	}
	p := windows.UTF16ToString(buf)
	switch {
	case strings.HasPrefix(p, `\\?\UNC\`):
		return "", errors.New("the file is on a network share")
	case strings.HasPrefix(p, `\\?\`):
		p = p[len(`\\?\`):]
	}
	return p, nil
}

func control(f *os.File, fn func(windows.Handle)) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Control(func(fd uintptr) { fn(windows.Handle(fd)) })
}
