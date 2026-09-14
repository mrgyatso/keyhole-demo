//go:build linux || darwin

package fstools

import (
	"errors"
	"io/fs"
	"os"
	"syscall"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// fileIdentity is the device and inode of the open handle. Together they name
// the file itself, so a path that has been swapped for another file between
// prepare and apply fails the check even if its content hashes the same.
func fileIdentity(_ *os.File, fi fs.FileInfo) (proto.FileIdentity, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return proto.FileIdentity{}, errors.New("this filesystem reports no device and inode")
	}
	return proto.FileIdentity{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, nil
}

// applySecurity gives the replacement the target's mode and, where the agent
// has the privilege, its owner. Ownership is best effort: an unprivileged
// agent keeps its own, which is visible in the result's mode.
func applySecurity(root *os.Root, tempRel, _, _ string, info fs.FileInfo) error {
	if err := root.Chmod(tempRel, info.Mode().Perm()); err != nil {
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if err := root.Chown(tempRel, int(st.Uid), int(st.Gid)); err != nil && !errors.Is(err, fs.ErrPermission) {
			return err
		}
	}
	return nil
}

// replaceTarget renames the replacement over the target through the same
// os.Root the target was opened under, so the swap cannot land outside the
// allow rule's directory. rename(2) is atomic within a filesystem.
func replaceTarget(root *os.Root, tempRel, targetRel, _, _ string) error {
	return root.Rename(tempRel, targetRel)
}

// syncDir flushes the directory entry, so the rename survives power loss and
// not just a process crash.
func syncDir(root *os.Root, rel string) error {
	d, err := root.Open(rel)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
