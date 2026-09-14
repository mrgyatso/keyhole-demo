package fstools

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// The Windows bypass shapes, exercised against a change instead of a read.
// They run on the Windows laptop; see the Slice 5 handoff for the acceptance
// procedure.

func TestChangeThroughAJunctionIsRefused(t *testing.T) {
	f := newChangeFixture(t, nil)
	outside := tempRoot(t)
	target := filepath.Join(outside, "config.json")
	writeFile(t, target, original)
	mklinkJunction(t, filepath.Join(f.root, "j"), outside)

	resp := f.call(t, proto.OpPrepareFileChange, proto.PrepareFileChangeArgs{
		Path: filepath.Join(f.root, "j", "config.json"), Content: proposed})
	wantRefusal(t, resp, proto.ErrUnsafePath, proto.ErrNotAllowed)
	if got := readBack(t, target); got != original {
		t.Errorf("a change reached through a junction: %q", got)
	}
}

// A junction swapped in after prepare must fail the apply: the target is
// reopened and rechecked, and a reparse point is refused there too.
func TestJunctionSwappedInBetweenPrepareAndApply(t *testing.T) {
	f := newChangeFixture(t, nil)
	outside := tempRoot(t)
	writeFile(t, filepath.Join(outside, "config.json"), original)
	inner := filepath.Join(f.root, "dir")
	mkdir(t, inner)
	victim := filepath.Join(inner, "config.json")
	writeFile(t, victim, original)

	p := result[proto.PrepareFileChangeResult](t, f.call(t, proto.OpPrepareFileChange,
		proto.PrepareFileChangeArgs{Path: victim, Content: proposed}))
	if err := os.RemoveAll(inner); err != nil {
		t.Fatal(err)
	}
	mklinkJunction(t, inner, outside)
	resp := f.call(t, proto.OpApplyFileChange, proto.ApplyFileChangeArgs{PlanID: p.PlanID, PlanDigest: p.PlanDigest})
	wantRefusal(t, resp, proto.ErrUnsafePath, proto.ErrStalePlan, proto.ErrNotAllowed)
	if got := readBack(t, filepath.Join(outside, "config.json")); got != original {
		t.Errorf("the apply followed a junction planted after prepare: %q", got)
	}
}

func TestChangeToAnAlternateDataStreamIsRefused(t *testing.T) {
	f := newChangeFixture(t, nil)
	if err := os.WriteFile(f.file+":secret", []byte("hidden"), 0o644); err != nil {
		t.Skipf("no alternate data streams here: %v", err)
	}
	for _, q := range []string{f.file + ":secret", f.file + "::$DATA", f.file + ":secret:$DATA"} {
		wantError(t, f.call(t, proto.OpPrepareFileChange, proto.PrepareFileChangeArgs{Path: q, Content: proposed}), proto.ErrUnsafePath)
	}
	if got := readBack(t, f.file); got != original {
		t.Errorf("an alternate data stream change touched the file: %q", got)
	}
}

func TestChangeThroughAShortNameIsRefused(t *testing.T) {
	f := newChangeFixture(t, nil)
	long := filepath.Join(f.root, "LongDirectoryName")
	file := filepath.Join(long, "config.json")
	writeFile(t, file, original)
	short := shortPath(t, long)
	if short == long {
		t.Skip("8.3 names are disabled on this volume")
	}
	wantError(t, f.call(t, proto.OpPrepareFileChange,
		proto.PrepareFileChangeArgs{Path: filepath.Join(short, "config.json"), Content: proposed}), proto.ErrUnsafePath)
}

// The replacement must carry the target's DACL, not the temporary file's
// default one, or a change would quietly re-permission the file.
func TestApplyPreservesTheTargetDACL(t *testing.T) {
	f := newChangeFixture(t, nil)
	before := daclString(t, f.file)
	p := f.prepare(t, proposed)
	result[proto.ApplyFileChangeResult](t, f.apply(t, p))
	if after := daclString(t, f.file); after != before {
		t.Errorf("the DACL changed:\nbefore %s\nafter  %s", before, after)
	}
}

// Applying through a different-case spelling of the path hits the same file,
// preserves its on-disk casing, and creates no second file.
func TestChangeViaACaseVariantPathHitsTheSameFile(t *testing.T) {
	f := newChangeFixture(t, nil) // root/config.json
	variant := filepath.Join(f.root, "CONFIG.JSON")
	p := result[proto.PrepareFileChangeResult](t, f.call(t, proto.OpPrepareFileChange,
		proto.PrepareFileChangeArgs{Path: variant, Content: proposed}))
	if base := filepath.Base(p.Before.Path); base != "config.json" {
		t.Errorf("plan path %q did not canonicalise to the on-disk name config.json", p.Before.Path)
	}
	result[proto.ApplyFileChangeResult](t, f.apply(t, p))
	entries, err := os.ReadDir(f.root)
	if err != nil {
		t.Fatal(err)
	}
	configs := 0
	for _, e := range entries {
		if name := e.Name(); name == "config.json" || name == "CONFIG.JSON" {
			if name != "config.json" {
				t.Errorf("on-disk casing changed to %q", name)
			}
			configs++
		}
	}
	if configs != 1 {
		t.Errorf("a case-variant change produced %d config files, want 1", configs)
	}
	if got := readBack(t, f.file); got != proposed {
		t.Errorf("the case-variant change did not write the file: %q", got)
	}
}

// A change preserves the target's persistent file attributes — hidden and
// read-only included — the way it preserves the DACL, and replaces a read-only
// target rather than failing on it.
func TestApplyPreservesFileAttributes(t *testing.T) {
	f := newChangeFixture(t, nil)
	const want = windows.FILE_ATTRIBUTE_HIDDEN | windows.FILE_ATTRIBUTE_READONLY
	if err := setFileAttributes(f.file, want); err != nil {
		t.Skipf("cannot set attributes here: %v", err)
	}
	p := f.prepare(t, proposed)
	result[proto.ApplyFileChangeResult](t, f.apply(t, p))
	if got := readBack(t, f.file); got != proposed {
		t.Fatalf("apply did not write a read-only target: %q", got)
	}
	got, err := getFileAttributes(f.file)
	if err != nil {
		t.Fatal(err)
	}
	for name, bit := range map[string]uint32{
		"hidden":    windows.FILE_ATTRIBUTE_HIDDEN,
		"read-only": windows.FILE_ATTRIBUTE_READONLY,
	} {
		if got&bit == 0 {
			t.Errorf("the %s attribute was lost across the change (attrs=0x%x)", name, got)
		}
	}
}

// TestServiceThrowawayOnARealMachine exercises the service path against the
// real Service Control Manager without touching any system service: it creates
// its own throwaway service, queries it, proves the policy allow-list and the
// compiled-in deny list gate a restart, and deletes the service. Creating a
// service needs Administrator, so it runs only under KEYHOLE_WINDOWS_ACCEPTANCE
// and skips (rather than fails) when it cannot reach the SCM. It never starts
// or restarts a real service: a dummy binary cannot become Running, so a full
// restart round-trip is a manual acceptance step.
func TestServiceThrowawayOnARealMachine(t *testing.T) {
	if os.Getenv("KEYHOLE_WINDOWS_ACCEPTANCE") != "1" {
		t.Skip("set KEYHOLE_WINDOWS_ACCEPTANCE=1 to run the service acceptance test (needs Administrator)")
	}
	m, err := mgr.Connect()
	if err != nil {
		t.Skipf("cannot reach the Service Control Manager (run as Administrator): %v", err)
	}
	defer m.Disconnect()
	const name = "KeyholeSlice5Throwaway"
	if s, err := m.OpenService(name); err == nil { // clean up a stale run
		_ = s.Delete()
		s.Close()
	}
	s, err := m.CreateService(name, `C:\Windows\System32\cmd.exe`, mgr.Config{
		DisplayName: "Keyhole Slice 5 Throwaway", StartType: mgr.StartManual}, "/c", "exit")
	if err != nil {
		t.Fatalf("create throwaway service: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.Control(svc.Stop)
		_ = s.Delete()
		s.Close()
	})

	f := newChangeFixture(t, nil)
	f.pol.ServiceAllow = []string{name}

	res := result[proto.ServiceResult](t, f.call(t, proto.OpServiceQuery, proto.ServiceQueryArgs{Name: name}))
	if res.State != proto.ServiceStopped {
		t.Errorf("throwaway service query state = %q, want stopped", res.State)
	}

	// The compiled-in deny list wins over the policy even when it names the service.
	f.pol.ServiceAllow = append(f.pol.ServiceAllow, "keyhole-agent")
	wantError(t, f.call(t, proto.OpServiceRestart, proto.ServiceRestartArgs{Name: "keyhole-agent"}), proto.ErrChangeDenied)
	// A service the policy does not list is refused before the SCM is touched.
	wantError(t, f.call(t, proto.OpServiceRestart, proto.ServiceRestartArgs{Name: "Spooler"}), proto.ErrNotAllowed)
}

func daclString(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL(%s): %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("Control(%s): %v", path, err)
	}
	out := "protected=" + strconv.FormatBool(control&windows.SE_DACL_PROTECTED != 0)
	if dacl != nil {
		// SECURITY_DESCRIPTOR.String includes owner/group fields even though
		// this query asked only for the DACL. AI is Windows's bookkeeping bit
		// for an unprotected, inherited ACL; the protected flag above captures
		// the security-relevant distinction.
		sddl := sd.String()
		if i := strings.Index(sddl, "D:"); i >= 0 {
			sddl = strings.TrimPrefix(sddl[i:], "D:AI")
			if !strings.HasPrefix(sddl, "D:") {
				sddl = "D:" + sddl
			}
		}
		out += "|" + sddl
	}
	return out
}
