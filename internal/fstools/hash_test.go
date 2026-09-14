package fstools

import (
	"path/filepath"
	"testing"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func TestHashFile(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "hello.txt"), "hello\n")
	writeFile(t, filepath.Join(root, "empty.bin"), "")
	writeFile(t, filepath.Join(root, "tool.exe"), "MZ\x00\x01binary")
	x := New(Options{})
	pol := testPolicy(rootRule(root))
	for name, want := range map[string]string{
		"hello.txt": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
		"empty.bin": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	} {
		h := result[proto.HashFileResult](t, run(t, x, proto.OpHashFile, proto.HashFileArgs{Path: filepath.Join(root, name)}, pol))
		if h.SHA256 != want || h.Path != filepath.Join(root, name) || h.ModTime.IsZero() {
			t.Errorf("hash %s = %+v; want %s", name, h, want)
		}
	}
	if h := result[proto.HashFileResult](t, run(t, x, proto.OpHashFile, proto.HashFileArgs{Path: filepath.Join(root, "tool.exe")}, pol)); h.Size != 10 {
		t.Errorf("binary files hash too: %+v", h)
	}
	capped := testPolicy(rootRule(root))
	capped.MaxFileBytes = 3
	wantError(t, run(t, x, proto.OpHashFile, proto.HashFileArgs{Path: filepath.Join(root, "hello.txt")}, capped), proto.ErrTooLarge)
	wantError(t, run(t, x, proto.OpHashFile, proto.HashFileArgs{Path: root}, pol), proto.ErrNotRegular)
}
