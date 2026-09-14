package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const serviceName = "Keyhole"

type serviceState struct {
	Installed bool
	Status    string
}

func copyExecutable(src, dst string) (err error) {
	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	if samePath(srcAbs, dstAbs) {
		return nil
	}
	in, err := os.Open(srcAbs)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dstAbs), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dstAbs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			os.Remove(dstAbs)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy executable: %w", err)
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
