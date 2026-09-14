package policy

import "testing"

type denyCase struct{ goos, path, want string } // want "" means not denied

var denyCases = []denyCase{
	// Windows: registry hives, NTDS, DPAPI, vaults, machine and user keys.
	{"windows", `C:\Windows\System32\config\SAM`, "deny-win-hives"},
	{"windows", `c:\windows\system32\CONFIG\sam`, "deny-win-hives"},
	{"windows", `C:\Windows\System32\config\RegBack\SYSTEM`, "deny-win-hives"},
	{"windows", `C:\Windows\System32\config`, "deny-win-hives"},
	{"windows", `D:\Windows\System32\config\SECURITY`, "deny-win-hives"},
	{"windows", `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\x`, "deny-win-hives"},
	{"windows", `C:\Users\bob\NTUSER.DAT`, "deny-win-user-hives"},
	{"windows", `C:\Users\bob\ntuser.dat.LOG1`, "deny-win-user-hives"},
	{"windows", `C:\Users\bob\AppData\Local\Microsoft\Windows\UsrClass.dat`, "deny-win-user-hives"},
	{"windows", `C:\Windows\NTDS\ntds.dit`, "deny-win-ntds"},
	{"windows", `E:\NTDS\ntds.dit`, "deny-win-ntds"},
	{"windows", `C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\abc`, "deny-win-dpapi"},
	{"windows", `C:\Users\bob\AppData\Roaming\Microsoft\Protect\S-1-5-21-1\key`, "deny-win-dpapi"},
	{"windows", `C:\Users\bob\AppData\Local\Microsoft\Vault\x.vcrd`, "deny-win-vault"},
	{"windows", `C:\Users\bob\AppData\Roaming\Microsoft\Credentials\ABC`, "deny-win-vault"},
	{"windows", `C:\ProgramData\Microsoft\Vault\x`, "deny-win-vault"},
	{"windows", `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\k`, "deny-win-crypto"},
	{"windows", `C:\Users\bob\AppData\Roaming\Microsoft\Crypto\RSA\S-1\k`, "deny-win-crypto"},
	{"windows", `C:\Users\bob\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\x`, "deny-win-crypto"},
	{"windows", `C:\ProgramData\ssh\ssh_host_ed25519_key`, "deny-win-ssh-host-keys"},
	// Windows: memory, snapshots, NTFS metadata, recycle bin.
	{"windows", `C:\pagefile.sys`, "deny-win-pagefile"},
	{"windows", `D:\pagefile.sys`, "deny-win-pagefile"},
	{"windows", `C:\hiberfil.sys`, "deny-win-pagefile"},
	{"windows", `C:\swapfile.sys`, "deny-win-pagefile"},
	{"windows", `C:\Windows\Minidump\notes.txt`, "deny-win-minidump"},
	{"windows", `C:\Windows\MEMORY.DMP`, "deny-memory-dumps"},
	{"windows", `C:\ProgramData\app\crash.DMP`, "deny-memory-dumps"},
	{"windows", `C:\System Volume Information\tracking.log`, "deny-win-vss"},
	{"windows", `C:\$MFT`, "deny-win-ntfs-meta"},
	{"windows", `C:\$Extend\$UsnJrnl`, "deny-win-ntfs-meta"},
	{"windows", `C:\$Recycle.Bin\S-1-5-21\$R1.docx`, "deny-win-recycle-bin"},
	// Windows: unattend, sysprep, raw Security.evtx.
	{"windows", `C:\Windows\Panther\unattend.xml`, "deny-win-unattend"},
	{"windows", `C:\Windows\Panther\UnattendGC\Unattend.xml`, "deny-win-unattend"},
	{"windows", `C:\Windows\Panther\unattend-original.xml`, "deny-win-unattend"},
	{"windows", `C:\autounattend.xml`, "deny-win-unattend"},
	{"windows", `C:\Windows\System32\Sysprep\Panther\setupact.log`, "deny-win-unattend"},
	{"windows", `C:\sysprep.inf`, "deny-win-unattend"},
	{"windows", `C:\Windows\System32\winevt\Logs\Security.evtx`, "deny-win-security-evtx"},
	// Windows: user-profile data.
	{"windows", `C:\Users\bob\Documents\q3.xlsx`, "deny-win-user-data"},
	{"windows", `C:\Users\bob\Desktop`, "deny-win-user-data"},
	{"windows", `C:\Users\bob\Downloads\setup.exe`, "deny-win-user-data"},
	{"windows", `C:\Users\bob\Pictures\a.png`, "deny-win-user-data"},
	{"windows", `C:\Users\bob\Videos\a.mp4`, "deny-win-user-data"},
	{"windows", `C:\Users\bob\Music\a.mp3`, "deny-win-user-data"},
	{"windows", `C:\Users\bob\OneDrive - Contoso\x.docx`, "deny-win-user-data"},
	{"windows", `C:\Users\Public\Documents\x`, "deny-win-user-data"},
	{"windows", `C:\Users\bob\AppData\Local\Microsoft\Outlook\bob.ost`, "deny-win-outlook"},
	{"windows", `D:\Archive\mail.PST`, "deny-win-outlook"},
	{"windows", `C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data`, "deny-win-browser"},
	{"windows", `C:\Users\bob\AppData\Local\Microsoft\Edge\User Data\Default\Cookies`, "deny-win-browser"},
	{"windows", `C:\Users\bob\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\logins.json`, "deny-win-browser"},
	// Every OS: credentials and key material, here in Windows syntax.
	{"windows", `C:\Users\bob\.ssh\config`, "deny-ssh"},
	{"windows", `C:\Users\bob\.SSH`, "deny-ssh"},
	{"windows", `C:\Users\bob\.aws\credentials`, "deny-cloud-creds"},
	{"windows", `C:\Users\bob\.azure\msal_token_cache.json`, "deny-cloud-creds"},
	{"windows", `C:\Users\bob\.kube\config`, "deny-cloud-creds"},
	{"windows", `C:\Users\bob\.docker\config.json`, "deny-cloud-creds"},
	{"windows", `C:\Users\bob\.git-credentials`, "deny-cloud-creds"},
	{"windows", `C:\Users\bob\_netrc`, "deny-cloud-creds"},
	{"windows", `C:\Users\bob\AppData\Roaming\postgresql\pgpass.conf`, "deny-cloud-creds"},
	{"windows", `C:\Users\bob\.gnupg\pubring.kbx`, "deny-gnupg"},
	{"windows", `C:\keys\id_ed25519.pub`, "deny-ssh-keys"},
	{"windows", `C:\keys\ID_RSA`, "deny-ssh-keys"},
	{"windows", `C:\certs\server.PFX`, "deny-key-files"},
	{"windows", `C:\certs\client.p12`, "deny-key-files"},
	{"windows", `C:\inetpub\ssl\site.pem`, "deny-key-files"},
	{"windows", `C:\app\tls.key`, "deny-key-files"},
	{"windows", `C:\putty\me.ppk`, "deny-key-files"},
	{"windows", `C:\java\trust.jks`, "deny-key-files"},
	{"windows", `C:\java\app.keystore`, "deny-key-files"},
	{"windows", `C:\krb\svc.keytab`, "deny-key-files"},
	{"windows", `C:\x\vault.kdbx`, "deny-password-db"},
	{"windows", `C:\x\old.KDB`, "deny-password-db"},

	// Windows paths that must stay reachable, including near-miss names.
	{"windows", `C:\`, ""},
	{"windows", `C:\Windows`, ""},
	{"windows", `C:\Windows\Logs\CBS\CBS.log`, ""},
	{"windows", `C:\Windows\System32\LogFiles\HTTPERR\httperr1.log`, ""},
	{"windows", `C:\ProgramData\Veeam\Backup\Svc.VeeamBackup.log`, ""},
	{"windows", `C:\Windows\System32\configuration\x.log`, ""},
	{"windows", `C:\Windows\NTDSX\x.log`, ""},
	{"windows", `C:\Windows\System32\winevt\Logs\System.evtx`, ""},
	{"windows", `C:\Users\bob`, ""},
	{"windows", `C:\Users\bob\AppData\Local\Temp\setup.log`, ""},
	{"windows", `C:\Users\bob\Documents2\x.log`, ""},
	{"windows", `C:\Users\bob\AppData\Roaming\Microsoft\ProtectX\x`, ""},
	{"windows", `C:\x\my.pem.txt`, ""},
	{"windows", `C:\x\pagefile.sys`, ""},

	// Linux.
	{"linux", `/etc/shadow`, "deny-linux-shadow"},
	{"linux", `/etc/shadow-`, "deny-linux-shadow"},
	{"linux", `/etc/gshadow`, "deny-linux-shadow"},
	{"linux", `/etc/gshadow-`, "deny-linux-shadow"},
	{"linux", `/etc/sudoers`, "deny-linux-sudoers"},
	{"linux", `/etc/sudoers.d/90-cloud-init-users`, "deny-linux-sudoers"},
	{"linux", `/etc/ssh/ssh_host_rsa_key`, "deny-linux-ssh-host-keys"},
	{"linux", `/etc/ssl/private/ssl-cert-snakeoil.key`, "deny-linux-tls-private"},
	{"linux", `/etc/pki/tls/private/x`, "deny-linux-tls-private"},
	{"linux", `/root`, "deny-linux-root-home"},
	{"linux", `/root/.bash_history`, "deny-linux-root-home"},
	{"linux", `/proc`, "deny-linux-kernel-fs"},
	{"linux", `/proc/1/environ`, "deny-linux-kernel-fs"},
	{"linux", `/sys/kernel/debug`, "deny-linux-kernel-fs"},
	{"linux", `/dev/sda`, "deny-linux-kernel-fs"},
	{"linux", `/var/lib/sss/db/cache_default.ldb`, "deny-linux-sss"},
	{"linux", `/etc/NetworkManager/system-connections/wifi.nmconnection`, "deny-linux-network-secrets"},
	{"linux", `/etc/wpa_supplicant/wpa_supplicant.conf`, "deny-linux-network-secrets"},
	{"linux", `/etc/ppp/chap-secrets`, "deny-linux-network-secrets"},
	{"linux", `/etc/ipsec.secrets`, "deny-linux-network-secrets"},
	{"linux", `/etc/security/opasswd`, "deny-linux-misc-secrets"},
	{"linux", `/etc/mysql/debian.cnf`, "deny-linux-misc-secrets"},
	{"linux", `/run/secrets/db_password`, "deny-linux-run-secrets"},
	{"linux", `/var/run/secrets/kubernetes.io/serviceaccount/token`, "deny-linux-run-secrets"},
	{"linux", `/run/credentials/x.service/y`, "deny-linux-run-secrets"},
	{"linux", `/var/crash/_usr_bin_x.1000.crash`, "deny-linux-crash"},
	{"linux", `/var/lib/systemd/coredump/core.x`, "deny-linux-crash"},
	{"linux", `/swapfile`, "deny-linux-swap"},
	{"linux", `/home/bob/Documents/x.odt`, "deny-linux-user-data"},
	{"linux", `/home/bob/.mozilla/firefox/x.default/logins.json`, "deny-linux-browser"},
	{"linux", `/home/bob/.config/google-chrome/Default/Login Data`, "deny-linux-browser"},
	{"linux", `/home/bob/.ssh/authorized_keys`, "deny-ssh"},
	{"linux", `/home/bob/.aws/config`, "deny-cloud-creds"},
	{"linux", `/home/bob/.netrc`, "deny-cloud-creds"},
	{"linux", `/home/bob/.pgpass`, "deny-cloud-creds"},
	{"linux", `/home/bob/.gnupg/pubring.kbx`, "deny-gnupg"},
	{"linux", `/opt/app/id_ecdsa`, "deny-ssh-keys"},
	{"linux", `/opt/app/id_dsa`, "deny-ssh-keys"},
	{"linux", `/etc/krb5.keytab`, "deny-key-files"},
	{"linux", `/etc/nginx/tls/site.key`, "deny-key-files"},
	{"linux", `/srv/pw.kdbx`, "deny-password-db"},

	{"linux", `/`, ""},
	{"linux", `/etc`, ""},
	{"linux", `/etc/passwd`, ""},
	{"linux", `/etc/nginx/nginx.conf`, ""},
	{"linux", `/var/log/auth.log`, ""},
	{"linux", `/etc/ssh/ssh_host_rsa_key.pub`, ""},
	{"linux", `/etc/ssh/sshd_config`, ""},
	{"linux", `/procx/1`, ""},
	{"linux", `/rootfs/x`, ""},
	{"linux", `/etc/ssl/privatex/y`, ""},
	{"linux", `/etc/Shadow`, ""}, // Linux is case-sensitive: a different file
	{"linux", `/home/bob`, ""},
	{"linux", `/home/bob/app.log`, ""},

	// macOS. The default volume is case-insensitive, so matching is too.
	{"darwin", `/Library/Keychains/System.keychain`, "deny-mac-keychains"},
	{"darwin", `/library/keychains/System.keychain`, "deny-mac-keychains"},
	{"darwin", `/Users/bob/Library/Keychains/login.keychain-db`, "deny-mac-keychains"},
	{"darwin", `/private/var/db/SystemKey`, "deny-mac-keychains"},
	{"darwin", `/private/var/db/dslocal/nodes/Default/users/bob.plist`, "deny-mac-accounts"},
	{"darwin", `/var/db/dslocal/nodes/Default`, "deny-mac-accounts"},
	{"darwin", `/private/etc/master.passwd`, "deny-mac-accounts"},
	{"darwin", `/etc/master.passwd`, "deny-mac-accounts"},
	{"darwin", `/private/etc/ssh/ssh_host_ed25519_key`, "deny-mac-ssh-host-keys"},
	{"darwin", `/etc/ssh/ssh_host_rsa_key`, "deny-mac-ssh-host-keys"},
	{"darwin", `/private/var/root/.zsh_history`, "deny-mac-root-home"},
	{"darwin", `/var/root`, "deny-mac-root-home"},
	{"darwin", `/dev/disk0`, "deny-mac-devfs"},
	{"darwin", `/private/var/vm/sleepimage`, "deny-mac-vm"},
	{"darwin", `/Users/bob/Documents/x`, "deny-mac-user-data"},
	{"darwin", `/System/Volumes/Data/Users/bob/Documents/x`, "deny-mac-user-data"}, // firmlink alias
	{"darwin", `/System/Volumes/Data/Library/Keychains/System.keychain`, "deny-mac-keychains"},
	{"darwin", `/Users/bob/Desktop`, "deny-mac-user-data"},
	{"darwin", `/Users/bob/Library/Mail/V10/x`, "deny-mac-user-data"},
	{"darwin", `/Users/bob/Library/Messages/chat.db`, "deny-mac-user-data"},
	{"darwin", `/Users/bob/Library/Application Support/Google/Chrome/Default/Cookies`, "deny-mac-browser"},
	{"darwin", `/Users/bob/Library/Application Support/Firefox/Profiles/x/logins.json`, "deny-mac-browser"},
	{"darwin", `/Users/bob/Library/Safari/History.db`, "deny-mac-browser"},
	{"darwin", `/Users/bob/.ssh/id_ed25519`, "deny-ssh"},
	{"darwin", `/Users/bob/.SSH/id_ed25519`, "deny-ssh"},
	{"darwin", `/Users/bob/.kube/config`, "deny-cloud-creds"},
	{"darwin", `/opt/certs/x.P12`, "deny-key-files"},

	{"darwin", `/`, ""},
	{"darwin", `/private/var/log/system.log`, ""},
	{"darwin", `/Library/Logs/DiagnosticReports/x.ips`, ""},
	{"darwin", `/Library/KeychainsX/x`, ""},
	{"darwin", `/Users/bob/Library/Logs/x.log`, ""},
}

func TestHardDenied(t *testing.T) {
	for _, c := range denyCases {
		id, denied := HardDenied(c.goos, c.path)
		if denied != (c.want != "") || id != c.want {
			t.Errorf("HardDenied(%s, %q) = %q, %v; want %q", c.goos, c.path, id, denied, c.want)
		}
	}
}

// Security invariant 5: Keyhole's own credential, state, temporary sessions,
// receipts and change store are never readable through Keyhole, whatever the
// client policy allows.
func TestHardDeniedCoversKeyholesOwnData(t *testing.T) {
	cases := []denyCase{
		{"windows", `C:\ProgramData\Keyhole\device.creds`, "deny-win-keyhole"},
		{"windows", `c:\programdata\KEYHOLE\agent.json`, "deny-win-keyhole"},
		{"windows", `C:\ProgramData\Keyhole`, "deny-win-keyhole"},
		{"windows", `D:\ProgramData\Keyhole\device.creds`, "deny-win-keyhole"},
		{"windows", `C:\ProgramData\Keyhole\temp\s_abc\device.creds`, "deny-win-keyhole"},
		{"windows", `C:\ProgramData\Keyhole\receipts\keyhole-dev_x.json`, "deny-win-keyhole"},
		{"windows", `C:\ProgramData\Keyhole\change\rollback\r1.bak`, "deny-win-keyhole"},
		{"windows", `C:\ProgramData\KeyholeVendor\Logs\a.log`, ""},
		// "Keyhole" is one path segment; a sibling directory whose name merely
		// starts with it, such as the one used for live acceptance tests,
		// must not match.
		{"windows", `C:\ProgramData\KeyholeTest\Logs\change-acceptance.txt`, ""},
		{"windows", `C:\ProgramData\keyhole\temp\x\device.creds`, "deny-win-keyhole"},
		{"linux", "/var/lib/keyhole/device.creds", "deny-linux-keyhole"},
		{"linux", "/var/lib/keyhole", "deny-linux-keyhole"},
		{"linux", "/var/lib/keyhole/x", "deny-linux-keyhole"},
		{"linux", "/etc/keyhole/agent.json", "deny-linux-keyhole"},
		{"linux", "/var/lib/keyholes/x", ""},
		{"linux", "/var/lib/keyhole-test/x", ""},
		{"darwin", "/Library/Application Support/Keyhole/device.creds", "deny-mac-keyhole"},
		{"darwin", "/library/application support/keyhole/agent.json", "deny-mac-keyhole"},
		{"darwin", "/System/Volumes/Data/Library/Application Support/Keyhole/device.creds", "deny-mac-keyhole"},
	}
	for _, c := range cases {
		id, denied := HardDenied(c.goos, c.path)
		if denied != (c.want != "") || id != c.want {
			t.Errorf("HardDenied(%s, %q) = %q, %v; want %q", c.goos, c.path, id, denied, c.want)
		}
	}
}

func TestHardDeniedFailsClosedOnMalformedPaths(t *testing.T) {
	for _, c := range []struct{ goos, path string }{
		{"windows", `relative\path`},
		{"windows", `C:\Windows\..\x`},
		{"linux", "relative/path"},
		{"linux", "/var/../etc/shadow"},
		{"darwin", ""},
	} {
		if id, denied := HardDenied(c.goos, c.path); !denied || id == "" {
			t.Errorf("HardDenied(%s, %q) = %q, %v; want a refusal", c.goos, c.path, id, denied)
		}
	}
}
