package main

import (
	"strings"
	"testing"
)

// cmd.exe does not read the backslash-escaped quotes os/exec produces for
// CommandLineToArgvW, so the self-delete command line is built by hand. After
// /s /c, cmd.exe strips exactly the outer pair of quotes and runs the rest.
func TestSelfDeleteCommandLineIsQuotedForCmd(t *testing.T) {
	const (
		comspec = `C:\Windows\system32\cmd.exe`
		exe     = `C:\Program Files\Keyhole\keyhole-agent-temp.exe`
		dir     = `C:\Program Files\Keyhole`
	)
	line, err := selfDeleteCommandLine(comspec, exe, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := `"C:\Windows\system32\cmd.exe" /d /s /c "ping -n 3 127.0.0.1 >nul & ` +
		`del /f /q "C:\Program Files\Keyhole\keyhole-agent-temp.exe" & rmdir "C:\Program Files\Keyhole""`
	if line != want {
		t.Fatalf("command line\n got %s\nwant %s", line, want)
	}
	if strings.Contains(line, `\"`) {
		t.Fatalf("cmd.exe would take \\\" literally: %s", line)
	}
	// What cmd.exe runs: the text after /c with its first and last quote removed.
	body := line[strings.Index(line, "/c ")+3:]
	body = body[1 : len(body)-1]
	for _, want := range []string{`del /f /q "` + exe + `"`, `rmdir "` + dir + `"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("cmd.exe would run %q, which lacks %q", body, want)
		}
	}

	t.Run("a path cmd.exe cannot quote is refused", func(t *testing.T) {
		for _, bad := range []string{`C:\Program Files\100%\keyhole-agent-temp.exe`, `C:\Program Files\a"b\x.exe`} {
			if _, err := selfDeleteCommandLine(comspec, bad, dir); err == nil {
				t.Errorf("quoted %q for cmd.exe", bad)
			}
		}
	})
}
