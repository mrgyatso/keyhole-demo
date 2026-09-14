//go:build linux || darwin

package fstools

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// wantOneOf fails unless resp is a refusal carrying one of codes. How a path
// race is caught (the Lstat that refuses a link, the final-path recheck, or
// the identity check) varies, so the tests accept the family of safe answers.
func wantOneOf(t *testing.T, resp *proto.Response, codes ...string) {
	t.Helper()
	if resp.OK || resp.Error == nil || !slices.Contains(codes, resp.Error.Code) || len(resp.Result) != 0 {
		t.Fatalf("got ok=%v error=%+v; want one of %v", resp.OK, resp.Error, codes)
	}
}

// The target is swapped for a symlink between prepare and apply. The endpoint
// reopens and rechecks the path, and a link is refused there, so the file the
// link points at is never written.
func TestTargetSwappedForASymlinkBetweenPrepareAndApply(t *testing.T) {
	f := newChangeFixture(t, nil)
	decoy := filepath.Join(f.root, "decoy.json")
	writeFile(t, decoy, original)
	p := f.prepare(t, proposed)

	if err := os.Remove(f.file); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, decoy, f.file) // config.json -> decoy.json, both inside scope

	wantOneOf(t, f.apply(t, p), proto.ErrUnsafePath, proto.ErrStalePlan, proto.ErrNotAllowed)
	if got := readBack(t, decoy); got != original {
		t.Errorf("the apply followed a symlink planted after prepare: %q", got)
	}
	if _, err := os.Lstat(f.file); err != nil {
		t.Errorf("the symlink was disturbed: %v", err)
	}
}

// A directory component of the target's path is swapped for a symlink to an
// outside directory between prepare and apply. os.Root containment plus the
// canonical-path recheck must refuse it, leaving the outside file untouched.
func TestDirectoryComponentSwappedBetweenPrepareAndApply(t *testing.T) {
	f := newChangeFixture(t, nil)
	inner := filepath.Join(f.root, "dir")
	mkdir(t, inner)
	victim := filepath.Join(inner, "config.json")
	writeFile(t, victim, original)

	p := result[proto.PrepareFileChangeResult](t, f.call(t, proto.OpPrepareFileChange,
		proto.PrepareFileChangeArgs{Path: victim, Content: proposed}))

	outside := tempRoot(t)
	writeFile(t, filepath.Join(outside, "config.json"), original)
	if err := os.RemoveAll(inner); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, outside, inner) // root/dir -> an outside directory

	wantOneOf(t, f.call(t, proto.OpApplyFileChange, proto.ApplyFileChangeArgs{PlanID: p.PlanID, PlanDigest: p.PlanDigest}),
		proto.ErrUnsafePath, proto.ErrStalePlan, proto.ErrNotAllowed)
	if got := readBack(t, filepath.Join(outside, "config.json")); got != original {
		t.Errorf("the apply crossed a swapped directory symlink: %q", got)
	}
}
