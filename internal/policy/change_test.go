package policy

import (
	"strings"
	"testing"
)

func TestChangeDeniedCoversHighRiskTargets(t *testing.T) {
	cases := map[string][]string{
		"windows": {
			`C:\Windows\System32\config\SAM`,
			`C:\Windows\System32\drivers\etc\hosts`,
			`C:\Windows\System32\Tasks\Keyhole`,
			`C:\Boot\BCD`,
			`C:\ProgramData\Keyhole\agent.json`,
			`C:\ProgramData\Vendor\agent.exe`,
			`C:\ProgramData\Vendor\fix.ps1`,
			`C:\Users\tech\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.txt`,
			`C:\Windows\INF\setupapi.dev.log`,
			`C:\ProgramData\Microsoft\Windows Defender\config.json`,
		},
		"linux": {
			"/etc/passwd", "/etc/shadow", "/etc/sudoers.d/90-tech", "/etc/ssh/sshd_config",
			"/etc/systemd/system/vendor.service", "/etc/cron.d/backup", "/boot/grub/grub.cfg",
			"/usr/bin/vendor", "/var/lib/keyhole/agent.json", "/opt/vendor/lib.so",
			"/etc/profile.d/vendor.sh", "/etc/ld.so.preload",
		},
		"darwin": {
			"/System/Library/LaunchDaemons/x.plist", "/Library/LaunchDaemons/com.vendor.plist",
			"/private/etc/sudoers", "/private/etc/ssh/sshd_config", "/usr/bin/vendor",
			"/Library/Application Support/Keyhole/agent.json", "/System/Volumes/Data/private/etc/pam.d/sudo",
			"/Library/Logs/Vendor/fix.sh",
		},
	}
	for goos, paths := range cases {
		for _, p := range paths {
			id, denied := ChangeDenied(goos, p)
			if !denied {
				t.Errorf("%s: %s is not change-denied", goos, p)
				continue
			}
			if !strings.HasPrefix(id, "change-deny-") {
				t.Errorf("%s: %s denied by %q", goos, p, id)
			}
		}
	}
}

func TestChangeDeniedLeavesOrdinaryRemediationTargetsAlone(t *testing.T) {
	cases := map[string][]string{
		"windows": {
			`C:\ProgramData\Vendor\config.json`,
			`C:\ProgramData\Vendor\Logs\app.log`,
			`C:\inetpub\wwwroot\web.config`,
			`C:\Program Files\Vendor\settings.xml`,
		},
		"linux":  {"/var/opt/vendor/config.yaml", "/etc/vendor/agent.conf", "/srv/app/settings.ini"},
		"darwin": {"/Library/Logs/Vendor/app.log", "/Library/Preferences/com.vendor.plist"},
	}
	for goos, paths := range cases {
		for _, p := range paths {
			if id, denied := ChangeDenied(goos, p); denied {
				t.Errorf("%s: %s refused by %s; it is an ordinary remediation target", goos, p, id)
			}
		}
	}
}

// The Keyhole change-deny globs ("**/Keyhole/**" and the Windows
// ProgramData/Program Files patterns) match whole path segments: a sibling
// directory that merely starts with "Keyhole", such as the one used for live
// acceptance tests, must not match, while a nested, differently-cased path
// under the real directory still does.
func TestChangeDeniedKeyholeGlobsMatchWholeSegments(t *testing.T) {
	notDenied := map[string][]string{
		"windows": {
			`C:\ProgramData\KeyholeTest\Logs\change-acceptance.txt`,
			`C:\Program Files\KeyholeTools\x.txt`,
		},
		"linux": {"/var/lib/keyhole-test/x"},
	}
	for goos, paths := range notDenied {
		for _, p := range paths {
			if id, denied := ChangeDenied(goos, p); denied {
				t.Errorf("%s: %s refused by %s; it is only a sibling of Keyhole's own path", goos, p, id)
			}
		}
	}

	denied := map[string][]string{
		"windows": {
			`C:\ProgramData\Keyhole\device.creds`,
			`C:\ProgramData\keyhole\temp\x\device.creds`,
		},
		"linux": {"/var/lib/keyhole/x"},
	}
	for goos, paths := range denied {
		for _, p := range paths {
			if _, ok := ChangeDenied(goos, p); !ok {
				t.Errorf("%s: %s should be change-denied as Keyhole's own path", goos, p)
			}
		}
	}
}

// A change capability is narrower than a read capability, never wider: every
// hard-denied path is also change-denied in the places the spec names.
func TestChangeDenyFailsClosedOnMalformedPaths(t *testing.T) {
	for goos, p := range map[string]string{
		"windows": `relative\path`,
		"linux":   "relative/path",
		"darwin":  "../escape",
	} {
		id, denied := ChangeDenied(goos, p)
		if !denied || id != changeDenyMalformed {
			t.Errorf("%s: %q -> %q, %v; want the malformed rule", goos, p, id, denied)
		}
	}
}

func TestChangeDenyIsCaseInsensitiveWhereTheFilesystemIs(t *testing.T) {
	if _, denied := ChangeDenied("windows", `C:\WINDOWS\system32\DRIVERS\etc\HOSTS`); !denied {
		t.Error("windows change deny is case sensitive")
	}
	if _, denied := ChangeDenied("linux", "/ETC/PASSWD"); denied {
		t.Error("linux change deny folded case")
	}
}

func TestServiceDenyAndAllow(t *testing.T) {
	for goos, names := range map[string][]string{
		"windows": {"Keyhole", "keyhole-agent", "SamSs", "WinDefend", "TermService", "EventLog", "sshd"},
		"linux":   {"keyhole-agent", "systemd-journald", "sshd", "auditd", "firewalld"},
		"darwin":  {"dev.keyhole.agent", "com.apple.mDNSResponder"},
	} {
		for _, n := range names {
			if id, denied := ServiceDenied(goos, n); !denied {
				t.Errorf("%s: service %q is not denied (%q)", goos, n, id)
			}
		}
	}
	for goos, names := range map[string][]string{
		"windows": {"VendorService", "Spooler", "wuauserv", "MSSQLSERVER"},
		"linux":   {"vendor", "nginx", "mssql-server"},
		"darwin":  {"com.vendor.agent"},
	} {
		for _, n := range names {
			if id, denied := ServiceDenied(goos, n); denied {
				t.Errorf("%s: service %q denied by %s", goos, n, id)
			}
		}
	}
	if !ServiceAllowed([]string{"VendorService"}, "vendorservice") {
		t.Error("policy service allow is case sensitive")
	}
	if ServiceAllowed(nil, "VendorService") || ServiceAllowed([]string{"VendorService"}, "") {
		t.Error("an empty allow list or an empty name allowed a restart")
	}
}

func TestCheckServiceName(t *testing.T) {
	for _, ok := range []string{"VendorService", "vendor-agent", "mssql-server.service", "com.vendor.agent"} {
		if err := CheckServiceName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "vendor service", `C:\Windows\System32\svc.exe`, "vendor;stop", "vendor|x",
		"vendor$(x)", "vendor\x00", "vendor\n", strings.Repeat("a", maxServiceNameLen+1), "vendör"} {
		if err := CheckServiceName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
