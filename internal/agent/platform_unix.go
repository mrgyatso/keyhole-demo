//go:build !windows

package agent

import (
	"os"
	"runtime"
)

// DefaultDataDir is where the service keeps its state.
func DefaultDataDir() DataDir {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/Keyhole"
	}
	return "/var/lib/keyhole"
}

func mkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// MkdirAll applies the umask and leaves an existing directory alone.
	return os.Chmod(dir, 0o700)
}

func protectFile(f *os.File) error { return f.Chmod(0o600) }
