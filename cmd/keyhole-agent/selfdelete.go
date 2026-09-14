package main

import (
	"fmt"
	"strings"
)

// selfDeleteDelay gives this process time to exit before the helper deletes
// its image. Three pings is about two seconds, which is the traditional
// amount and is comfortably longer than a service stop.
const selfDeleteDelay = "3"

// selfDeleteCommandLine is the whole command line for the detached cmd.exe
// that deletes the temporary binary and its directory once this process has
// exited. It is built by hand because os/exec quotes for CommandLineToArgvW,
// escaping embedded quotes as \", which cmd.exe takes literally: del would be
// handed a path that does not parse, and nothing would notice, because the
// process itself started fine.
//
// With /s /c, cmd.exe removes the first and last quote and runs what is
// between them, so each path keeps its own quotes. cmd.exe expands %VAR% even
// inside quotes and ends a quoted string at the next quote, so a path holding
// either is refused and the caller falls back to deleting at reboot.
func selfDeleteCommandLine(comspec, exe, dir string) (string, error) {
	for _, p := range []string{comspec, exe, dir} {
		if p == "" || strings.ContainsAny(p, "\"%\r\n") {
			return "", fmt.Errorf("cannot quote %q for cmd.exe", p)
		}
	}
	return fmt.Sprintf(`"%s" /d /s /c "ping -n %s 127.0.0.1 >nul & del /f /q "%s" & rmdir "%s""`,
		comspec, selfDeleteDelay, exe, dir), nil
}
