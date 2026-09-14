//go:build !darwin && !linux

package main

import "os"

// isTerminal reports whether f is a character device, which on these
// platforms is the best available sign of a terminal.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// readSecretFrom reads one line. These platforms are not a target for the
// admin CLI, so input is echoed.
func readSecretFrom(f *os.File) (string, error) { return readLine(f) }
