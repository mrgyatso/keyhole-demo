package main

import (
	"strings"
	"testing"
)

// A temporary install is meant to leave the machine as it found it, and that
// includes the helper downloaded to start it. Each copy-paste command removes
// it once the helper exits, whether or not the helper succeeded.
func TestTemporaryCommandsRemoveTheDownloadedHelper(t *testing.T) {
	cmds := temporaryCommands("https://keyhole.test", "khe_acme_secret")
	if len(cmds) == 0 {
		t.Fatal("no temporary install commands")
	}
	for _, c := range cmds {
		switch {
		case strings.Contains(c.cmd, "$env:TEMP"):
			if !strings.HasSuffix(c.cmd, "; Remove-Item -Force $f") {
				t.Errorf("%s leaves the helper in %%TEMP%%:\n%s", c.label, c.cmd)
			}
		default:
			if !strings.HasSuffix(c.cmd, "; rm -f /tmp/keyhole-agent") {
				t.Errorf("%s leaves the helper in /tmp:\n%s", c.label, c.cmd)
			}
		}
	}
}
