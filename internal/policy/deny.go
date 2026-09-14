package policy

import (
	"fmt"
	"path"
	"strings"
)

// The hard-deny list is compiled into the agent and evaluated on canonical
// paths. It always wins: no allow rule, including one for C:\ or /, can
// reach a path it covers. Sources: research/07-scope-redaction-cost.md
// section 1 and the plan's "Hard deny" column.
//
// Pattern language: a pattern is a path in the OS's own syntax whose
// segments are path.Match globs, plus "**", which matches any number of
// segments (including none). A pattern denies every path it matches and
// everything below it, so "/proc" and "/proc/**" deny the same set. On
// Windows and macOS matching is case-insensitive. Windows patterns use "?:"
// for the drive so they hold on every volume.

// denyMalformed is reported for a path that does not parse. HardDenied fails
// closed: a path it cannot read is a path it refuses.
const denyMalformed = "deny-malformed-path"

type rawDeny struct {
	id       string
	patterns []string
}

func deny(id string, patterns ...string) rawDeny { return rawDeny{id, patterns} }

// commonDeny applies on every OS. Patterns are written with "/" and
// converted for Windows.
var commonDeny = []rawDeny{
	deny("deny-ssh", "**/.ssh/**"),
	deny("deny-cloud-creds", "**/.aws/**", "**/.azure/**", "**/.kube/**", "**/.docker/config.json",
		"**/.git-credentials", "**/.netrc", "**/_netrc", "**/.pgpass", "**/pgpass.conf"),
	deny("deny-gnupg", "**/.gnupg/**"),
	deny("deny-ssh-keys", "**/id_rsa*", "**/id_ed25519*", "**/id_ecdsa*", "**/id_dsa*"),
	deny("deny-password-db", "**/*.kdbx", "**/*.kdb"),
	deny("deny-key-files", "**/*.pfx", "**/*.p12", "**/*.pem", "**/*.key", "**/*.ppk",
		"**/*.jks", "**/*.keystore", "**/*.keytab"),
	deny("deny-memory-dumps", "**/*.dmp", "**/*.hdmp", "**/*.mdmp"),
}

var windowsDeny = []rawDeny{
	deny("deny-win-hives", `?:\Windows\System32\config\**`, `?:\Windows\repair\**`), // SAM, SECURITY, SYSTEM, SOFTWARE, RegBack
	deny("deny-win-user-hives", `**\NTUSER.DAT*`, `**\UsrClass.dat*`),
	deny("deny-win-ntds", `?:\Windows\NTDS\**`, `**\ntds.dit`),
	deny("deny-win-dpapi", `?:\Windows\System32\Microsoft\Protect\**`, `**\AppData\Roaming\Microsoft\Protect\**`),
	deny("deny-win-vault",
		`**\AppData\Local\Microsoft\Vault\**`, `**\AppData\Roaming\Microsoft\Vault\**`,
		`**\AppData\Local\Microsoft\Credentials\**`, `**\AppData\Roaming\Microsoft\Credentials\**`,
		`?:\ProgramData\Microsoft\Vault\**`),
	deny("deny-win-crypto", `?:\ProgramData\Microsoft\Crypto\**`,
		`**\AppData\Roaming\Microsoft\Crypto\**`, `**\AppData\Roaming\Microsoft\SystemCertificates\**`),
	deny("deny-win-ssh-host-keys", `?:\ProgramData\ssh\*_key`),
	// Keyhole's own data: the device credential, state, temporary sessions,
	// receipts and change store. Reading it would let a session persist or
	// impersonate the endpoint (security invariant 5).
	deny("deny-win-keyhole", `?:\ProgramData\Keyhole\**`),
	deny("deny-win-pagefile", `?:\pagefile.sys`, `?:\hiberfil.sys`, `?:\swapfile.sys`),
	deny("deny-win-minidump", `?:\Windows\Minidump\**`, `?:\Windows\LiveKernelReports\**`),
	deny("deny-win-vss", `?:\System Volume Information\**`),
	deny("deny-win-ntfs-meta", `?:\$MFT`, `?:\$MFTMirr`, `?:\$LogFile`, `?:\$Volume`, `?:\$AttrDef`,
		`?:\$Bitmap`, `?:\$Boot`, `?:\$BadClus`, `?:\$Secure`, `?:\$UpCase`, `?:\$Extend\**`),
	deny("deny-win-recycle-bin", `?:\$Recycle.Bin\**`),
	deny("deny-win-unattend", `**\unattend*.xml`, `**\autounattend*.xml`, `**\sysprep\**`, `**\sysprep.inf`),
	deny("deny-win-security-evtx", `?:\Windows\System32\winevt\Logs\Security.evtx`),
	deny("deny-win-user-data",
		`?:\Users\*\Documents\**`, `?:\Users\*\Desktop\**`, `?:\Users\*\Downloads\**`,
		`?:\Users\*\Pictures\**`, `?:\Users\*\Videos\**`, `?:\Users\*\Music\**`,
		`?:\Users\*\OneDrive*\**`, `?:\Users\*\Favorites\**`, `?:\Users\*\Contacts\**`),
	deny("deny-win-outlook", `**\*.pst`, `**\*.ost`,
		`**\AppData\Local\Microsoft\Outlook\**`, `**\AppData\Roaming\Microsoft\Outlook\**`),
	deny("deny-win-browser",
		`**\AppData\Local\Google\Chrome\User Data\**`, `**\AppData\Local\Microsoft\Edge\User Data\**`,
		`**\AppData\Local\BraveSoftware\Brave-Browser\User Data\**`,
		`**\AppData\Roaming\Mozilla\Firefox\Profiles\**`, `**\AppData\Local\Mozilla\Firefox\Profiles\**`),
}

var linuxDeny = []rawDeny{
	deny("deny-linux-shadow", "/etc/shadow*", "/etc/gshadow*"),
	deny("deny-linux-sudoers", "/etc/sudoers", "/etc/sudoers.d/**"),
	deny("deny-linux-ssh-host-keys", "/etc/ssh/*_key"),
	deny("deny-linux-tls-private", "/etc/ssl/private/**", "/etc/pki/tls/private/**", "/etc/pki/CA/private/**"),
	deny("deny-linux-root-home", "/root/**"),
	deny("deny-linux-kernel-fs", "/proc/**", "/sys/**", "/dev/**"),
	deny("deny-linux-sss", "/var/lib/sss/**"),
	deny("deny-linux-network-secrets", "/etc/NetworkManager/system-connections/**", "/etc/wpa_supplicant/**",
		"/etc/ppp/*-secrets", "/etc/ipsec.secrets", "/etc/ipsec.d/private/**"),
	deny("deny-linux-misc-secrets", "/etc/security/opasswd", "/etc/mysql/debian.cnf",
		"/etc/samba/private/**", "/var/lib/samba/private/**"),
	deny("deny-linux-run-secrets", "/run/secrets/**", "/var/run/secrets/**", "/run/credentials/**"),
	deny("deny-linux-crash", "/var/crash/**", "/var/lib/systemd/coredump/**"),
	deny("deny-linux-swap", "/swapfile", "/swap.img"),
	deny("deny-linux-keyrings", "/home/*/.local/share/keyrings/**"),
	deny("deny-linux-user-data",
		"/home/*/Documents/**", "/home/*/Desktop/**", "/home/*/Downloads/**",
		"/home/*/Pictures/**", "/home/*/Videos/**", "/home/*/Music/**", "/home/*/.thunderbird/**"),
	deny("deny-linux-browser", "/home/*/.mozilla/**", "/home/*/snap/firefox/**",
		"/home/*/.config/google-chrome/**", "/home/*/.config/chromium/**", "/home/*/.config/microsoft-edge/**"),
	deny("deny-linux-keyhole", "/var/lib/keyhole/**", "/etc/keyhole/**"), // Keyhole's own data (invariant 5)
}

// darwinDeny lists macOS paths in both their /private and their symlinked
// (/etc, /var) spelling; compileDeny adds the /System/Volumes/Data firmlink
// spelling of every absolute pattern.
var darwinDeny = []rawDeny{
	deny("deny-mac-keyhole", "/Library/Application Support/Keyhole/**"), // Keyhole's own data (invariant 5)
	deny("deny-mac-keychains", "/Library/Keychains/**", "/Users/*/Library/Keychains/**",
		"/private/var/db/SystemKey", "/var/db/SystemKey"),
	deny("deny-mac-accounts", "/private/var/db/dslocal/**", "/var/db/dslocal/**",
		"/private/etc/master.passwd", "/etc/master.passwd"),
	deny("deny-mac-ssh-host-keys", "/private/etc/ssh/*_key", "/etc/ssh/*_key"),
	deny("deny-mac-root-home", "/private/var/root/**", "/var/root/**"),
	deny("deny-mac-devfs", "/dev/**"),
	deny("deny-mac-vm", "/private/var/vm/**", "/var/vm/**", "/System/Volumes/VM/**"),
	deny("deny-mac-user-data",
		"/Users/*/Documents/**", "/Users/*/Desktop/**", "/Users/*/Downloads/**",
		"/Users/*/Pictures/**", "/Users/*/Movies/**", "/Users/*/Music/**",
		"/Users/*/Library/Mail/**", "/Users/*/Library/Messages/**", "/Users/*/Library/Mobile Documents/**"),
	deny("deny-mac-browser",
		"/Users/*/Library/Application Support/Google/Chrome/**",
		"/Users/*/Library/Application Support/Microsoft Edge/**",
		"/Users/*/Library/Application Support/Firefox/**",
		"/Users/*/Library/Safari/**", "/Users/*/Library/Cookies/**"),
}

type denyRule struct {
	id       string
	patterns [][]string // split and, where the OS folds case, folded
}

var denyTables = map[string][]denyRule{
	"windows": compileDeny("windows", windowsDeny),
	"linux":   compileDeny("linux", linuxDeny),
	"darwin":  compileDeny("darwin", darwinDeny),
}

// otherDeny covers any other GOOS with the common rules in Unix syntax.
var otherDeny = compileDeny("unix", nil)

// HardDenied reports whether the compiled-in deny list covers canonicalPath,
// and the stable ID of the first rule that does (for the audit log). A path
// that does not parse is refused with deny-malformed-path.
func HardDenied(goos, canonicalPath string) (ruleID string, denied bool) {
	segs, reason := split(goos, canonicalPath)
	if reason != "" {
		return denyMalformed, true
	}
	if foldsCase(goos) {
		segs = foldAll(segs)
	}
	table, ok := denyTables[goos]
	if !ok {
		table = otherDeny
	}
	for _, r := range table {
		for _, p := range r.patterns {
			if matchPrefix(p, segs) {
				return r.id, true
			}
		}
	}
	return "", false
}

// compileDeny turns the OS rules plus the common rules into matchers. It
// panics on a malformed pattern or a duplicate ID, so a bad table fails
// every test run rather than silently matching nothing.
func compileDeny(goos string, osRules []rawDeny) []denyRule {
	var out []denyRule
	seen := map[string]bool{}
	add := func(r rawDeny, common bool) {
		if r.id == "" || seen[r.id] {
			panic(fmt.Sprintf("policy: deny rule id %q empty or duplicated", r.id))
		}
		seen[r.id] = true
		dr := denyRule{id: r.id}
		for _, p := range r.patterns {
			if common && goos == "windows" {
				p = strings.ReplaceAll(p, "/", `\`)
			}
			dr.patterns = append(dr.patterns, compilePattern(goos, p))
			if goos == "darwin" && strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "/dev/") {
				dr.patterns = append(dr.patterns, compilePattern(goos, "/System/Volumes/Data"+p))
			}
		}
		out = append(out, dr)
	}
	for _, r := range osRules {
		add(r, false)
	}
	for _, r := range commonDeny {
		add(r, true)
	}
	return out
}

func compilePattern(goos, p string) []string {
	var segs []string
	switch {
	case goos == "windows":
		segs = strings.Split(p, `\`)
		if segs[0] != "**" && segs[0] != "?:" {
			panic(fmt.Sprintf("policy: windows deny pattern %q must start with ?: or **", p))
		}
	case strings.HasPrefix(p, "/"):
		segs = strings.Split(p[1:], "/")
	default:
		segs = strings.Split(p, "/")
		if segs[0] != "**" {
			panic(fmt.Sprintf("policy: deny pattern %q must be absolute or start with **", p))
		}
	}
	for _, s := range segs {
		if _, err := path.Match(s, ""); s == "" || err != nil {
			panic(fmt.Sprintf("policy: deny pattern %q has a bad segment %q", p, s))
		}
	}
	if foldsCase(goos) {
		segs = foldAll(segs)
	}
	return segs
}
