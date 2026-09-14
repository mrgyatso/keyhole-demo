package fstools

import (
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/windows"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// fileIdentity is the volume serial number and file index of the open handle:
// NTFS's own name for the file, independent of the path it was reached by. A
// path that names a different file at apply time fails the check even when its
// content hashes the same.
func fileIdentity(f *os.File, _ fs.FileInfo) (proto.FileIdentity, error) {
	var d windows.ByHandleFileInformation
	var herr error
	if err := control(f, func(h windows.Handle) { herr = windows.GetFileInformationByHandle(h, &d) }); err != nil {
		return proto.FileIdentity{}, err
	}
	if herr != nil {
		return proto.FileIdentity{}, fmt.Errorf("GetFileInformationByHandle: %w", herr)
	}
	return proto.FileIdentity{
		VolumeSerial: uint64(d.VolumeSerialNumber),
		FileIndex:    uint64(d.FileIndexHigh)<<32 | uint64(d.FileIndexLow),
	}, nil
}

// applySecurity copies the target's DACL onto the replacement, protected or
// inherited exactly as the target's is, so the file that ends up in place
// grants what the original granted. Owner and group are carried too: a rename
// would otherwise silently inherit them from the directory. The SACL is left
// alone because reading or setting it requires audit privilege.
func applySecurity(_ *os.Root, _, tempPath, targetPath string, _ fs.FileInfo) error {
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION)
	sd, err := windows.GetNamedSecurityInfo(targetPath, windows.SE_FILE_OBJECT, info)
	if err != nil {
		return fmt.Errorf("read the DACL of %s: %w", targetPath, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("DACL of %s: %w", targetPath, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("owner of %s: %w", targetPath, err)
	}
	group, _, err := sd.Group()
	if err != nil {
		return fmt.Errorf("group of %s: %w", targetPath, err)
	}
	if control, _, err := sd.Control(); err == nil && control&windows.SE_DACL_PROTECTED != 0 {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(tempPath, windows.SE_FILE_OBJECT, info, owner, group, dacl, nil); err != nil {
		return fmt.Errorf("apply the DACL to %s: %w", tempPath, err)
	}
	// Carry the target's persistent attributes (read-only, hidden, system,
	// archive, not-content-indexed) onto the replacement, so a change preserves
	// them the way it preserves the DACL. Transient/derived bits are not
	// copied. Best effort: a file whose attributes cannot be read is still
	// replaced, it simply keeps the default attributes of a freshly written
	// file.
	if attrs, err := getFileAttributes(targetPath); err == nil {
		const keep = windows.FILE_ATTRIBUTE_READONLY | windows.FILE_ATTRIBUTE_HIDDEN |
			windows.FILE_ATTRIBUTE_SYSTEM | windows.FILE_ATTRIBUTE_ARCHIVE |
			windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
		if carry := attrs & keep; carry != 0 {
			if err := setFileAttributes(tempPath, carry); err != nil {
				return fmt.Errorf("carry the attributes of %s: %w", targetPath, err)
			}
		}
	}
	return nil
}

func getFileAttributes(path string) (uint32, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.GetFileAttributes(p)
}

func setFileAttributes(path string, attrs uint32) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.SetFileAttributes(p, attrs)
}

// clearReadOnly drops the read-only attribute of an existing file so it can be
// replaced. MoveFileEx(REPLACE_EXISTING) refuses a read-only destination; the
// replacement carries its own read-only bit forward from applySecurity.
func clearReadOnly(path string) {
	attrs, err := getFileAttributes(path)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_READONLY == 0 {
		return
	}
	_ = setFileAttributes(path, attrs&^windows.FILE_ATTRIBUTE_READONLY)
}

// replaceTarget swaps the replacement in with MoveFileEx. REPLACE_EXISTING
// makes it atomic for readers, and WRITE_THROUGH does not return until the
// swap is on the disk, so power loss leaves the original or the new file and
// never a partial one. Both paths are the final paths of handles this call
// already resolved and policy-checked.
func replaceTarget(_ *os.Root, _, _, tempPath, targetPath string) error {
	clearReadOnly(targetPath)
	from, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// syncDir is a no-op: MOVEFILE_WRITE_THROUGH already flushed the change, and
// Windows does not let a directory handle be flushed.
func syncDir(*os.Root, string) error { return nil }
