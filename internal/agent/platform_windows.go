//go:build windows

package agent

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// DefaultDataDir is where the service keeps its state: Keyhole under the
// ProgramData known folder (normally C:\ProgramData\Keyhole).
func DefaultDataDir() DataDir {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil || base == "" {
		base = `C:\ProgramData`
	}
	return DataDir(filepath.Join(base, "Keyhole"))
}

func mkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return setDACL(dir, dirSDDL)
}

func protectFile(f *os.File) error { return setDACL(f.Name(), fileSDDL) }

// setDACL replaces path's DACL with the one in sddl and marks it protected,
// so nothing is inherited from the parent directory.
func setDACL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse SDDL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("SDDL DACL: %w", err)
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("set DACL on %s: %w", path, err)
	}
	return nil
}
