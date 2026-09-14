package policy

import (
	"fmt"
	"strconv"
	"strings"
)

// The change-deny list is the hard-deny list's counterpart for structured
// remediation: paths that may be readable inside an approved scope but that no
// Change capability may rewrite. It is compiled into the agent, evaluated on
// canonical paths, and always wins, so a grant for C:\ still cannot rewrite a
// service binary. It covers the spec's high-risk targets — boot configuration,
// security databases, authentication material, service definitions, startup
// locations, executables, and Keyhole's own installation and data — and, like
// the hard-deny list, fails closed on a path it cannot parse.
//
// Full write authority over these targets is a separate break-glass capability
// (Slice 6), not something a normal change grant can reach.

const changeDenyMalformed = "change-deny-malformed-path"

// changeCommonDeny applies on every OS. Patterns are written with "/" and
// converted for Windows.
var changeCommonDeny = []rawDeny{
	deny("change-deny-executables",
		"**/*.exe", "**/*.dll", "**/*.sys", "**/*.msi", "**/*.msp", "**/*.com", "**/*.scr",
		"**/*.cpl", "**/*.ocx", "**/*.drv", "**/*.efi", "**/*.so", "**/*.so.*", "**/*.dylib", "**/*.ko"),
	deny("change-deny-scripts",
		"**/*.ps1", "**/*.psm1", "**/*.psd1", "**/*.bat", "**/*.cmd", "**/*.vbs", "**/*.vbe",
		"**/*.js", "**/*.jse", "**/*.wsf", "**/*.wsh", "**/*.hta", "**/*.sh", "**/*.bash",
		"**/*.zsh", "**/*.py", "**/*.pl", "**/*.rb", "**/*.jar", "**/*.lnk", "**/*.scf", "**/*.url"),
	// Keyhole's own installation, data directory and binaries. Rewriting them
	// would let a session persist or impersonate the endpoint.
	deny("change-deny-keyhole", "**/Keyhole/**", "**/keyhole/**", "**/keyhole-agent*", "**/keyhole-relay*"),
}

var changeWindowsDeny = []rawDeny{
	deny("change-deny-win-boot", `?:\Boot\**`, `?:\Windows\Boot\**`, `?:\EFI\**`,
		`?:\bootmgr`, `?:\BOOTNXT`, `?:\boot.ini`, `?:\ntldr`, `?:\Windows\bootstat.dat`),
	deny("change-deny-win-security", `?:\Windows\System32\config\**`, `?:\Windows\repair\**`,
		`?:\Windows\NTDS\**`, `?:\Windows\security\**`, `?:\Windows\System32\GroupPolicy\**`,
		`?:\Windows\System32\GroupPolicyUsers\**`, `?:\ProgramData\Microsoft\Windows Defender\**`),
	deny("change-deny-win-auth", `?:\Windows\System32\Microsoft\Protect\**`,
		`?:\ProgramData\Microsoft\Crypto\**`, `?:\ProgramData\Microsoft\Vault\**`, `?:\ProgramData\ssh\**`,
		`**\AppData\Roaming\Microsoft\Crypto\**`, `**\AppData\Roaming\Microsoft\SystemCertificates\**`, `**\.ssh\**`),
	// Service definitions and the files Windows loads them from, hosts and
	// the other resolver files under drivers\etc included.
	deny("change-deny-win-services", `?:\Windows\System32\drivers\**`, `?:\Windows\INF\**`,
		`?:\Windows\System32\wbem\**`, `?:\Windows\System32\CatRoot\**`, `?:\Windows\System32\CatRoot2\**`,
		`?:\Windows\WinSxS\**`, `?:\Windows\servicing\**`, `?:\Windows\System32\spool\drivers\**`),
	deny("change-deny-win-startup", `**\Start Menu\Programs\Startup\**`, `?:\Windows\System32\Tasks\**`,
		`?:\Windows\Tasks\**`, `?:\Windows\System32\GroupPolicy\Machine\Scripts\**`),
	deny("change-deny-win-keyhole", `?:\ProgramData\Keyhole\**`, `?:\Program Files\Keyhole\**`,
		`?:\Program Files (x86)\Keyhole\**`),
}

var changeLinuxDeny = []rawDeny{
	deny("change-deny-linux-boot", "/boot/**", "/etc/grub.d/**", "/etc/default/grub",
		"/etc/fstab", "/etc/crypttab", "/etc/mdadm/**"),
	deny("change-deny-linux-auth", "/etc/passwd*", "/etc/group*", "/etc/shadow*", "/etc/gshadow*",
		"/etc/sudoers", "/etc/sudoers.d/**", "/etc/pam.d/**", "/etc/security/**", "/etc/ssh/**",
		"/etc/polkit-1/**", "/etc/krb5.keytab", "/etc/krb5.conf", "/etc/pki/**", "/etc/ssl/**",
		"/etc/ca-certificates/**", "/usr/share/ca-certificates/**"),
	deny("change-deny-linux-services", "/etc/systemd/**", "/lib/systemd/**", "/usr/lib/systemd/**",
		"/etc/init.d/**", "/etc/init/**", "/etc/rc.local", "/etc/rc0.d/**", "/etc/rc1.d/**",
		"/etc/rc2.d/**", "/etc/rc3.d/**", "/etc/rc4.d/**", "/etc/rc5.d/**", "/etc/rc6.d/**", "/etc/rcS.d/**"),
	deny("change-deny-linux-startup", "/etc/crontab", "/etc/cron.d/**", "/etc/cron.daily/**",
		"/etc/cron.hourly/**", "/etc/cron.monthly/**", "/etc/cron.weekly/**", "/var/spool/cron/**",
		"/etc/profile", "/etc/profile.d/**", "/etc/bash.bashrc", "/etc/environment",
		"/etc/ld.so.conf", "/etc/ld.so.conf.d/**", "/etc/ld.so.preload"),
	deny("change-deny-linux-binaries", "/bin/**", "/sbin/**", "/usr/bin/**", "/usr/sbin/**",
		"/usr/local/bin/**", "/usr/local/sbin/**", "/usr/lib/**", "/usr/lib64/**", "/lib/**",
		"/lib64/**", "/usr/libexec/**"),
	deny("change-deny-linux-keyhole", "/var/lib/keyhole/**", "/etc/keyhole/**"),
}

// changeDarwinDeny lists macOS paths in both their /private and their
// symlinked (/etc, /var) spelling; compileChangeDeny adds the
// /System/Volumes/Data firmlink spelling of every absolute pattern.
var changeDarwinDeny = []rawDeny{
	deny("change-deny-mac-system", "/System/**", "/bin/**", "/sbin/**", "/usr/bin/**",
		"/usr/sbin/**", "/usr/lib/**", "/usr/libexec/**", "/usr/local/bin/**", "/usr/local/sbin/**"),
	deny("change-deny-mac-launch", "/Library/LaunchDaemons/**", "/Library/LaunchAgents/**",
		"/Users/*/Library/LaunchAgents/**", "/private/etc/periodic/**", "/etc/periodic/**",
		"/private/etc/crontab", "/etc/crontab", "/private/var/at/**", "/var/at/**"),
	deny("change-deny-mac-auth", "/private/etc/pam.d/**", "/etc/pam.d/**", "/private/etc/sudoers",
		"/etc/sudoers", "/private/etc/sudoers.d/**", "/etc/sudoers.d/**", "/private/etc/ssh/**",
		"/etc/ssh/**", "/private/var/db/dslocal/**", "/var/db/dslocal/**", "/Library/Keychains/**",
		"/private/etc/master.passwd", "/etc/master.passwd", "/private/etc/passwd", "/etc/passwd"),
	deny("change-deny-mac-keyhole", "/Library/Application Support/Keyhole/**"),
}

var changeDenyTables = map[string][]denyRule{
	"windows": compileChangeDeny("windows", changeWindowsDeny),
	"linux":   compileChangeDeny("linux", changeLinuxDeny),
	"darwin":  compileChangeDeny("darwin", changeDarwinDeny),
}

// changeOtherDeny covers any other GOOS with the common rules in Unix syntax.
var changeOtherDeny = compileChangeDeny("unix", nil)

// ChangeDenied reports whether canonicalPath is a high-risk target that no
// change capability may write, and the stable ID of the first rule that says
// so. It is asked in addition to HardDenied, never instead of it, and it is
// asked again on the final path of the handle a change actually opens.
func ChangeDenied(goos, canonicalPath string) (ruleID string, denied bool) {
	segs, reason := split(goos, canonicalPath)
	if reason != "" {
		return changeDenyMalformed, true
	}
	if foldsCase(goos) {
		segs = foldAll(segs)
	}
	table, ok := changeDenyTables[goos]
	if !ok {
		table = changeOtherDeny
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

// compileChangeDeny mirrors compileDeny for the change table. It panics on a
// malformed pattern or a duplicate ID, so a bad table fails every test run.
func compileChangeDeny(goos string, osRules []rawDeny) []denyRule {
	var out []denyRule
	seen := map[string]bool{}
	add := func(r rawDeny, common bool) {
		if r.id == "" || seen[r.id] {
			panic(fmt.Sprintf("policy: change deny rule id %q empty or duplicated", r.id))
		}
		seen[r.id] = true
		dr := denyRule{id: r.id}
		for _, p := range r.patterns {
			if common && goos == "windows" {
				p = strings.ReplaceAll(p, "/", `\`)
			}
			dr.patterns = append(dr.patterns, compilePattern(goos, p))
			if goos == "darwin" && strings.HasPrefix(p, "/") {
				dr.patterns = append(dr.patterns, compilePattern(goos, "/System/Volumes/Data"+p))
			}
		}
		out = append(out, dr)
	}
	for _, r := range osRules {
		add(r, false)
	}
	for _, r := range changeCommonDeny {
		add(r, true)
	}
	return out
}

// Service names. A restart names a service, never a path or a command line, so
// the shape check is strict: printable ASCII without separators, quotes or
// shell metacharacters, and short enough for every platform's registry.

const maxServiceNameLen = 128

// CheckServiceName rejects a service name on its shape alone.
func CheckServiceName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("service name is required")
	case len(name) > maxServiceNameLen:
		return fmt.Errorf("service name %s is longer than %d characters", strconv.Quote(name), maxServiceNameLen)
	}
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("service name contains a control character")
		case r > 0x7e:
			return fmt.Errorf("service name %s is not printable ASCII", strconv.Quote(name))
		case strings.ContainsRune(`/\:*?"<>|;&$'`+"`", r), r == ' ':
			return fmt.Errorf("service name %s contains %q, which a service name may not", strconv.Quote(name), r)
		}
	}
	return nil
}

// serviceDenyRule refuses a service whatever the client policy says.
type serviceDenyRule struct {
	id       string
	names    []string // exact, case-folded
	prefixes []string // case-folded
}

// serviceDeny is compiled into the agent. Keyhole's own service can never be
// restarted through Keyhole (invariant 5), and neither can the services that
// hold the machine's identity, its security posture, or the remote access a
// technician is sitting on.
var serviceDeny = map[string][]serviceDenyRule{
	"windows": {
		{id: "service-deny-keyhole", prefixes: []string{"keyhole"}},
		{id: "service-deny-win-identity", names: []string{"samss", "ntds", "kdc", "netlogon", "lsm", "keyiso", "vaultsvc", "protectedstorage"}},
		{id: "service-deny-win-security", names: []string{"windefend", "sense", "wdnissvc", "securityhealthservice", "wscsvc", "mpssvc", "bfe", "gpsvc", "cryptsvc", "trustedinstaller", "eventlog", "sgrmbroker"}},
		{id: "service-deny-win-core", names: []string{"rpcss", "dcomlaunch", "plugplay", "power", "profsvc", "sessionenv"}},
		{id: "service-deny-win-remote", names: []string{"termservice", "umrdpservice", "winrm", "sshd", "remoteaccess"}},
	},
	"linux": {
		{id: "service-deny-keyhole", prefixes: []string{"keyhole"}},
		{id: "service-deny-linux-init", prefixes: []string{"systemd"}, names: []string{"dbus", "polkit", "init"}},
		{id: "service-deny-linux-security", names: []string{"auditd", "sssd", "firewalld", "ufw", "nftables", "iptables", "apparmor", "selinux"}},
		{id: "service-deny-linux-remote", names: []string{"ssh", "sshd", "ssh.service", "sshd.service"}},
	},
	"darwin": {
		{id: "service-deny-keyhole", prefixes: []string{"keyhole", "dev.keyhole"}},
		{id: "service-deny-mac-system", prefixes: []string{"com.apple."}},
	},
}

// ServiceDenied reports whether the agent refuses to restart name whatever the
// client policy says, and the rule that refuses it.
func ServiceDenied(goos, name string) (ruleID string, denied bool) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return "service-deny-empty", true
	}
	rules, ok := serviceDeny[goos]
	if !ok {
		rules = serviceDeny["linux"]
	}
	for _, r := range rules {
		for _, n := range r.names {
			if key == n {
				return r.id, true
			}
		}
		for _, p := range r.prefixes {
			if strings.HasPrefix(key, p) {
				return r.id, true
			}
		}
	}
	return "", false
}

// ServiceAllowed reports whether the client policy lists name. Comparison
// folds case on every OS: service names are case-insensitive on Windows, and
// an accidental case difference must not silently widen or narrow the list.
func ServiceAllowed(allow []string, name string) bool {
	key := strings.ToLower(strings.TrimSpace(name))
	for _, a := range allow {
		if strings.ToLower(strings.TrimSpace(a)) == key && key != "" {
			return true
		}
	}
	return false
}
