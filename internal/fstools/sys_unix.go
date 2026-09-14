//go:build linux || darwin

package fstools

import (
	"io/fs"
	"os"
	"syscall"
)

// openFlags opens read-only and without blocking, so a FIFO swapped in
// after the Lstat check cannot hang the agent. O_NONBLOCK does not affect
// reads of regular files.
const openFlags = os.O_RDONLY | syscall.O_NONBLOCK

// isLink reports whether fi, from Lstat or a directory listing, is a
// symbolic link.
func isLink(fi fs.FileInfo) bool { return fi.Mode()&fs.ModeSymlink != 0 }

// handleIsReparse reports whether an open handle is itself a link. On Unix
// an open follows a final symlink, so it never is.
func handleIsReparse(*os.File) (bool, error) { return false, nil }
