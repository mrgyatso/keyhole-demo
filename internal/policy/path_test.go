package policy

import (
	"errors"
	"testing"
)

func TestCheckPathShapeWindows(t *testing.T) {
	ok := []string{
		`C:\`,
		`C:\Windows\Logs`,
		`C:\Windows\Logs\`,
		`c:\windows\logs\CBS\CBS.log`,
		`D:\Data\app.log`,
		`C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log\ERRORLOG`,
		`C:\ProgramData\ScreenConnect Client (1234abcd)\x.log`,
		`C:\logs\nightly-backup~1-of-3.log`, // longer than any 8.3 name
		`C:\x\ABCDEF~12.LOG`,                // 13 characters: a 9-character base cannot be 8.3
		`C:\Windows\Logs\CONFIG.txt`,        // starts with CON, is not CON
		`C:\x\COM10.log`,                    // only COM0-9 are devices
		`C:\x\nul-report.txt`,
		`C:\x\.hidden`,
		`C:\x\a..b.log`,
	}
	for _, p := range ok {
		if err := CheckPathShape("windows", p); err != nil {
			t.Errorf("CheckPathShape(%q) = %v, want nil", p, err)
		}
	}

	bad := []string{
		``,
		`Windows\Logs`,
		`\Windows\Logs`,
		`C:Windows\Logs`,
		`C:`,
		`1:\x`,
		`CC:\x`,
		// traversal and empty segments
		`C:\Windows\..\Windows\System32\config\SAM`,
		`C:\Windows\Logs\..`,
		`C:\Windows\.\Logs`,
		`C:\Windows\\Logs`,
		`C:\Windows\Logs\\`,
		// device, namespace and UNC forms
		`\\?\C:\Windows\Logs`,
		`\\.\C:\Windows`,
		`\\.\PhysicalDrive0`,
		`//?/C:/Windows`,
		`\\server\share\x.log`,
		`\??\C:\Windows`,
		`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM`,
		// forward slashes
		`C:/Windows/Logs`,
		`C:\Windows/Logs`,
		// alternate data streams
		`C:\Windows\Logs\x.log:secret`,
		`C:\Windows\Logs\x.log::$DATA`,
		`C:\Windows\Logs:stream\x.log`,
		// reserved device names, any case, with or without extension, any segment
		`C:\x\CON`, `C:\x\con`, `C:\x\NUL.txt`, `C:\x\nul.tar.gz`, `C:\x\NUL .txt`,
		`C:\x\COM1`, `C:\x\com9.log`, `C:\x\COM0`, `C:\x\LPT1`, `C:\x\lpt0.txt`,
		`C:\x\AUX`, `C:\x\PRN.log`, `C:\x\CONIN$`, `C:\x\conout$`, `C:\x\CONOUT$.txt`,
		`C:\x\COM¹`, `C:\x\LPT³.txt`, `C:\NUL\x.log`,
		// 8.3 short names
		`C:\PROGRA~1\x.log`, `C:\Users\bob\DOCUME~1`, `C:\x\ABCDE~12.LOG`, `C:\x\backup~1.log`,
		// trailing dots and spaces
		`C:\x\file.`, `C:\x\file `, `C:\x.\y`, `C:\x\...`, `C:\x \y`,
		// wildcard and other characters Windows forbids
		`C:\x\a*b`, `C:\x\a?b`, `C:\x\a<b`, `C:\x\a>b`, `C:\x\a"b`, `C:\x\a|b`,
		// control characters and invalid UTF-8
		"C:\\x\\a\x00b", "C:\\x\\a\nb", "C:\\x\\a\x7fb", "C:\\x\\a\xffb",
	}
	for _, p := range bad {
		err := CheckPathShape("windows", p)
		var pe *UnsafePathError
		if !errors.As(err, &pe) {
			t.Errorf("CheckPathShape(%q) = %v, want *UnsafePathError", p, err)
			continue
		}
		if pe.Reason == "" {
			t.Errorf("CheckPathShape(%q): empty reason", p)
		}
	}
}

func TestCheckPathShapeUnix(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		ok := []string{
			`/`,
			`/var/log`,
			`/var/log/`,
			`/var/log/syslog.1`,
			`/var/log/a:b`,     // colons are ordinary on Unix
			`/var/log/back\sl`, // so are backslashes
			`/var/log/...`,
			`/var/log/x~1`,
			`/var/log/CON`,
			`/var/log/file.`,
			`/var/log/a b `,
		}
		for _, p := range ok {
			if err := CheckPathShape(goos, p); err != nil {
				t.Errorf("%s: CheckPathShape(%q) = %v, want nil", goos, p, err)
			}
		}
		bad := []string{
			``,
			`var/log`,
			`./var`,
			`~/x`,
			`/var/../etc/shadow`,
			`/var/log/..`,
			`/var/./log`,
			`/var//log`,
			`/var/log//`,
			"/var/log/a\x00b",
			"/var/log/a\nb",
			"/var/log/a\xffb",
		}
		for _, p := range bad {
			var pe *UnsafePathError
			if err := CheckPathShape(goos, p); !errors.As(err, &pe) {
				t.Errorf("%s: CheckPathShape(%q) = %v, want *UnsafePathError", goos, p, err)
			}
		}
	}
}
