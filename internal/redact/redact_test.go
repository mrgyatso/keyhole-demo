package redact

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/zricethezav/gitleaks/v8/report"
)

var (
	sharedOnce sync.Once
	shared     *Redactor
	sharedErr  error
)

// redactor returns one Redactor for the whole test binary; building one
// takes a noticeable fraction of a second.
func redactor(tb testing.TB) *Redactor {
	tb.Helper()
	sharedOnce.Do(func() { shared, sharedErr = New() })
	if sharedErr != nil {
		tb.Fatal(sharedErr)
	}
	return shared
}

// Fake credentials, assembled at run time so the source holds no literal
// secret. They have the shape and entropy of real ones.
var (
	awsKeyID  = "AKIA" + "QZ7RT4WX6VB2NM3K"
	awsSecret = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCYzK9qLm2Tt"
	ghToken   = "ghp_" + "R8mKz2Qp7Lw4Xn9Tb6Vc3Hd5Jf1Gs0Ya8Ue2"
	pemBody   = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n" +
		"VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK\n" +
		"LxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo\n"
	pemBlock = "-----BEGIN RSA " + "PRIVATE KEY-----\n" + pemBody + "-----END RSA " + "PRIVATE KEY-----"
)

func TestRedactsKnownSecrets(t *testing.T) {
	r := redactor(t)
	cases := []struct {
		name   string
		in     string
		secret string // must not survive
		rule   string // must be among the rules reported
		keep   []string
	}{
		{
			name:   "aws access key id",
			in:     "2024-01-15 10:23:45 INFO using credentials aws_access_key_id=" + awsKeyID + " region=us-east-1",
			secret: awsKeyID, rule: "aws-access-token", keep: []string{"region=us-east-1", "2024-01-15 10:23:45 INFO"},
		},
		{
			name:   "github token",
			in:     "git clone https://x-access-token:" + ghToken + "@github.com/contoso/app.git",
			secret: ghToken, rule: "github-pat", keep: []string{"git clone https://", "@github.com/contoso/app.git"},
		},
		{
			name:   "private key block",
			in:     "config dump follows\n" + pemBlock + "\nend of dump\n",
			secret: "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun", rule: "private-key",
			keep: []string{"config dump follows\n", "\nend of dump\n"},
		},
		{
			name:   "ado.net connection string",
			in:     `Server=sql01;Database=Payroll;User Id=svc_payroll;Password=Winter2024!;Encrypt=True`,
			secret: "Winter2024!", rule: RuleConnString, keep: []string{"Server=sql01;Database=Payroll;User Id=svc_payroll;Password=", ";Encrypt=True"},
		},
		{
			name:   "odbc braced pwd",
			in:     `Driver={ODBC Driver 18 for SQL Server};Server=sql01;Uid=sa;Pwd={p@ss;w0rd};`,
			secret: "p@ss;w0rd", rule: RuleConnString, keep: []string{"Uid=sa;Pwd={", "};"},
		},
		{
			name:   "connection string inside web.config attribute",
			in:     `<add name="Db" connectionString="Data Source=.;Initial Catalog=App;User ID=app;Password=Tr0ub4dor3" providerName="System.Data.SqlClient" />`,
			secret: "Tr0ub4dor3", rule: RuleConnString, keep: []string{`providerName="System.Data.SqlClient"`},
		},
		{
			name:   "password contains false",
			in:     `Server=sql01;User Id=app;Password=Falsetto99;`,
			secret: "Falsetto99", rule: RuleConnString,
		},
		{
			name:   "xml element",
			in:     "<smtp>\n  <user>relay</user>\n  <password>Hunter2!</password>\n</smtp>",
			secret: "Hunter2!", rule: RuleXMLPassword, keep: []string{"<user>relay</user>", "<password>", "</password>"},
		},
		{
			name:   "unattend value",
			in:     "<AdministratorPassword>\n  <Value>UABhAHMAcwB3AG8AcgBkAA==</Value>\n  <PlainText>false</PlainText>\n</AdministratorPassword>",
			secret: "UABhAHMAcwB3AG8AcgBkAA==", rule: RuleXMLPassword, keep: []string{"<PlainText>false</PlainText>"},
		},
		{
			name:   "web.config appSettings",
			in:     `<appSettings><add key="SmtpPassword" value="Sm7p-Pa55!" /><add key="SmtpHost" value="mail.contoso.com" /></appSettings>`,
			secret: "Sm7p-Pa55!", rule: RuleAppSetting, keep: []string{`value="mail.contoso.com"`},
		},
		{
			name:   "json",
			in:     `{"username": "svc_backup", "password": "correct horse battery staple", "port": 22}`,
			secret: "correct horse battery staple", rule: RuleJSONPassword, keep: []string{`"username": "svc_backup"`, `"port": 22`},
		},
		{
			name:   "yaml",
			in:     "database:\n  host: db01\n  password: s3cr3t-value\n  port: 5432\r\n",
			secret: "s3cr3t-value", rule: RuleYAMLPassword, keep: []string{"host: db01", "port: 5432"},
		},
		{
			name:   "gitleaks allow marker is ignored",
			in:     `Password=Hunter2Hunter2; // gitleaks:allow`,
			secret: "Hunter2Hunter2", rule: RuleConnString,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, n, rules := r.Redact(tc.in)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("secret survived:\n%s", out)
			}
			if n < 1 {
				t.Errorf("count = %d, want >= 1", n)
			}
			if !slices.Contains(rules, tc.rule) {
				t.Errorf("rules = %v, want %s", rules, tc.rule)
			}
			if !strings.Contains(out, "[REDACTED:") {
				t.Errorf("no placeholder in output:\n%s", out)
			}
			for _, k := range tc.keep {
				if !strings.Contains(out, k) {
					t.Errorf("lost surrounding text %q:\n%s", k, out)
				}
			}
		})
	}
}

func TestMultipleSecretsOnOneLine(t *testing.T) {
	r := redactor(t)
	in := "export AWS_ACCESS_KEY_ID=" + awsKeyID + " AWS_SECRET_ACCESS_KEY=" + awsSecret + " GITHUB_TOKEN=" + ghToken + " REGION=eu-west-1"
	out, n, rules := r.Redact(in)
	for _, s := range []string{awsKeyID, awsSecret, ghToken} {
		if strings.Contains(out, s) {
			t.Errorf("secret %q survived:\n%s", s, out)
		}
	}
	if n < 3 {
		t.Errorf("count = %d, want >= 3 (rules %v)", n, rules)
	}
	if !strings.HasPrefix(out, "export AWS_ACCESS_KEY_ID=[REDACTED:") || !strings.HasSuffix(out, " REGION=eu-west-1") {
		t.Errorf("structure lost:\n%s", out)
	}
}

func TestSecretsAcrossLinesKeepPositions(t *testing.T) {
	r := redactor(t)
	var b strings.Builder
	for i := range 50 {
		fmt.Fprintf(&b, "2024-01-15 10:%02d:00 INFO line %d nothing to see\n", i, i)
		if i%10 == 3 {
			fmt.Fprintf(&b, "2024-01-15 10:%02d:30 DEBUG conn=Server=db%d;Password=Pw-%d-Secret!;\n", i, i, i)
		}
	}
	in := b.String()
	out, n, _ := r.Redact(in)
	if n != 5 {
		t.Errorf("count = %d, want 5", n)
	}
	if strings.Contains(out, "-Secret!") {
		t.Fatalf("secret survived:\n%s", out)
	}
	// Everything but the secrets is byte-for-byte intact.
	want := in
	for i := 3; i < 50; i += 10 {
		want = strings.Replace(want, fmt.Sprintf("Pw-%d-Secret!", i), Placeholder(RuleConnString), 1)
	}
	if out != want {
		t.Errorf("output differs from expected replacement:\n got: %q\nwant: %q", out, want)
	}
}

// Realistic Windows server log text that contains no secrets. None of it
// may change.
var benignWindowsLogs = map[string]string{
	"cbs": `2024-01-15 10:23:45, Info                  CBS    TI: --- Initializing Trusted Installer ---
2024-01-15 10:23:45, Info                  CBS    TI: Last boot time: 2024-01-15 08:01:12.500
2024-01-15 10:23:45, Info                  CBS    Lock: New lock added: CCbsPublicSessionClassFactory, level: 30, total lock:4
2024-01-15 10:23:46, Info                  CBS    Session: 31095642_2839540117 initialized by client WindowsUpdateAgent, external staging directory: (null), external registry directory: (null)
2024-01-15 10:23:46, Info                  CBS    Appl: detect Parent, Package: Package_for_RollupFix~31bf3856ad364e35~amd64~~20348.2227.1.10, Parent: Microsoft-Windows-ServerDatacenterEdition~31bf3856ad364e35~amd64~~10.0.20348.1, Disposition = Detect, VersionComp: EQ, ServiceComp: GE, BuildComp: GE, DistributionComp: GE, RevisionComp: GE, Exist: present
2024-01-15 10:23:47, Info                  CBS    Exec: Processing complete, session(Corruption Repairing): 31095642_2839540117 [HRESULT = 0x00000000 - S_OK]
2024-01-15 10:23:47, Info                  CSI    00000013 [SR] Beginning Verify and Repair transaction
2024-01-15 10:23:48, Info                  CBS    Mark store corruption flag because of package: Package_1234_for_KB5034439~31bf3856ad364e35~amd64~~20348.2227.1.0. Status: 0x80070002
2024-01-15 10:23:48, Info                  CSI    00000015 Hashes for file member [l:10]'cbscore.dll' do not match. Expected: {l:32 b:6eb1c8a4c1e0d9f44e4c3b2a1908f7e6d5c4b3a291807f6e5d4c3b2a19087f6e} Actual: {l:32 b:0a1b2c3d4e5f60718293a4b5c6d7e8f9001122334455667788990aabbccddeef}
2024-01-15 10:23:48, Info                  CBS    Loaded Servicing Stack v10.0.20348.2227 with Core: C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.20348.2227_none_7c42f3a1e3b9d5a1\cbscore.dll
2024-01-15 10:23:49, Info                  CSI    00000016 Component: {l:16 b:d2f1e0c9b8a7968574635241302f1e0d} publicKeyToken="31bf3856ad364e35" version="10.0.20348.2227" arch="amd64"
2024-01-15 10:23:49, Info                  CBS    Reboot mark set, key: {9E2A7B1C-5D3F-4E8A-B6C4-1F0D2E3A4B5C}
`,
	"iis": `#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2024-01-15 10:23:45
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
2024-01-15 10:23:45 10.0.0.5 GET /api/v1/orders page=2&sort=desc 443 CONTOSO\jsmith 203.0.113.9 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/120.0.0.0+Safari/537.36 https://portal.contoso.com/orders 200 0 0 15
2024-01-15 10:23:46 10.0.0.5 POST /Account/Login ReturnUrl=%2Fdashboard 443 - 203.0.113.9 Mozilla/5.0+(Windows+NT+10.0) https://portal.contoso.com/Account/Login 302 0 0 31
2024-01-15 10:23:47 10.0.0.5 GET /auth/callback state=af0ifjsldkj&session_state=4f2c9a1b 443 - 198.51.100.7 Mozilla/5.0 - 200 0 0 8
2024-01-15 10:23:48 10.0.0.5 GET /owa/auth/logon.aspx url=https%3a%2f%2fmail.contoso.com%2fowa%2f&reason=0 443 - 198.51.100.7 Mozilla/5.0 - 200 0 0 46
`,
	"security-4624": `An account was successfully logged on.

Subject:
	Security ID:		SYSTEM
	Account Name:		SRV01$
	Account Domain:		CONTOSO
	Logon ID:		0x3E7

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

New Logon:
	Security ID:		CONTOSO\jsmith
	Account Name:		jsmith
	Logon ID:		0x1A2B3C4D
	Logon GUID:		{5b6c1a2e-8f3d-4c7a-9e1b-2d4f6a8c0e12}

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0
`,
	"setupapi": `>>>  [Device Install (Hardware initiated) - PCI\VEN_8086&DEV_15F3&SUBSYS_00008086&REV_03\3&11583659&0&E0]
>>>  Section start 2024/01/15 10:23:45.123
     ump: Creating Install Process: DrvInst.exe 10:23:45.125
     dvi: {Build Driver List} 10:23:45.201
     dvi:      Searching for hardware ID(s):
     dvi:           pci\ven_8086&dev_15f3&subsys_00008086&rev_03
     dvi:      Class GUID of device changed to: {4d36e972-e325-11ce-bfc1-08002be10318}.
     sto: {Setup Import Driver Package: C:\Windows\System32\DriverStore\FileRepository\e2f68.inf_amd64_4b1ed9d3b4d1e2f1\e2f68.inf} 10:23:45.310
     inf:      Driver Store Key: HKLM\SYSTEM\DriverDatabase\DriverPackages\e2f68.inf_amd64_4b1ed9d3b4d1e2f1
     inf:      Published Inf Path: C:\Windows\INF\oem12.inf
<<<  Section end 2024/01/15 10:23:46.002
<<<  [Exit status: SUCCESS]
`,
	"windowsupdate": `2024/01/15 10:23:45.1234567 1234  5678  Agent           * START *  Finding updates CallerId = UpdateOrchestrator  Id = 12
2024/01/15 10:23:45.3456789 1234  5678  SLS             Get response for service 855E8A7C-ECB4-4CA3-B045-1DFA50104289 - forceExpire[False] asyncRefreshOnExpiry[True]
2024/01/15 10:23:45.5678901 1234  5678  Misc            Got WSUS Client/Server URL: https://wsus.contoso.local:8531/ClientWebService/client.asmx
2024/01/15 10:23:45.6789012 1234  5678  Agent           Update {6A2E8F1B-3C4D-4E5F-8A9B-0C1D2E3F4A5B}.200 is pruned out due to potential supersedence
2024/01/15 10:23:45.7890123 1234  5678  ComApi          * END * Search ClientId = UpdateOrchestrator, Updates found = 3, ServiceId = {9482F4B4-E343-43B6-B170-9A65BC822C77}
`,
	"sql-errorlog": `2024-01-15 10:23:45.12 Server      Microsoft SQL Server 2019 (RTM-CU22) (KB5027702) - 15.0.4322.2 (X64)
2024-01-15 10:23:45.34 Logon       Error: 18456, Severity: 14, State: 8.
2024-01-15 10:23:45.34 Logon       Login failed for user 'sa'. Reason: Password did not match that for the login provided. [CLIENT: 10.0.0.42]
2024-01-15 10:23:45.56 spid12s     The SQL Server Network Interface library successfully registered the Service Principal Name (SPN) [ MSSQLSvc/sql01.contoso.local:1433 ] for the SQL Server service.
2024-01-15 10:23:45.78 Server      Server local connection provider is ready to accept connection on [ \\.\pipe\sql\query ].
`,
	"netlogon": `01/15 10:23:45 [LOGON] [3456] CONTOSO: SamLogon: Transitive Network logon of CONTOSO\jsmith from WKS042 (via SRV01) Entered
01/15 10:23:45 [LOGON] [3456] CONTOSO: SamLogon: Transitive Network logon of CONTOSO\jsmith from WKS042 (via SRV01) Returns 0x0
01/15 10:23:46 [SESSION] [3456] CONTOSO: NlSessionSetup: Negotiated flags with server are 0x612fffff
`,
	"dhcp": `ID,Date,Time,Description,IP Address,Host Name,MAC Address,User Name, TransactionID, QResult,Probationtime, CorrelationID,Dhcid,VendorClass(Hex),VendorClass(ASCII),UserClass(Hex),UserClass(ASCII),RelayAgentInformation,DnsRegError.
10,01/15/24,10:23:45,Assign,192.168.1.50,WKS042.contoso.local,AABBCCDDEEFF,,1234567890,0,,,,0x4D53465420352E30,MSFT 5.0,,,,0
11,01/15/24,10:23:46,Renew,192.168.1.51,WKS043.contoso.local,AABBCCDDEE00,,1234567891,0,,,,0x4D53465420352E30,MSFT 5.0,,,,0
`,
	"policy": `[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 42
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
ClearTextPassword = 0
`,
}

func TestBenignWindowsLogsUnchanged(t *testing.T) {
	r := redactor(t)
	for name, text := range benignWindowsLogs {
		t.Run(name, func(t *testing.T) {
			out, n, rules := r.Redact(text)
			if n != 0 || out != text {
				t.Errorf("false positive: %d redactions by %v\n%s", n, rules, diffLines(text, out))
			}
		})
	}
}

func diffLines(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	var d strings.Builder
	for i := range min(len(al), len(bl)) {
		if al[i] != bl[i] {
			fmt.Fprintf(&d, "- %s\n+ %s\n", al[i], bl[i])
		}
	}
	return d.String()
}

// natsSeed creates an nkeys key pair with create and returns its encoded
// seed, e.g. "SUA…" for nkeys.CreateUser.
func natsSeed(t *testing.T, create func() (nkeys.KeyPair, error)) string {
	t.Helper()
	kp, err := create()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := kp.Seed()
	if err != nil {
		t.Fatal(err)
	}
	return string(seed)
}

func TestRedactsNatsNkeySeeds(t *testing.T) {
	r := redactor(t)
	cases := []struct {
		name   string
		create func() (nkeys.KeyPair, error)
	}{
		{"user seed", nkeys.CreateUser},
		{"account seed", nkeys.CreateAccount},
		{"operator seed", nkeys.CreateOperator},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seed := natsSeed(t, tc.create)
			in := "deploy note: rotate the fleet's nkey seed " + seed + " before Friday's cutover."
			out, n, rules := r.Redact(in)
			if strings.Contains(out, seed) {
				t.Fatalf("seed survived:\n%s", out)
			}
			if n < 1 {
				t.Errorf("count = %d, want >= 1", n)
			}
			if !slices.Contains(rules, RuleNatsNkeySeed) {
				t.Errorf("rules = %v, want %s", rules, RuleNatsNkeySeed)
			}
			for _, k := range []string{"deploy note: rotate the fleet's nkey seed ", " before Friday's cutover."} {
				if !strings.Contains(out, k) {
					t.Errorf("lost surrounding text %q:\n%s", k, out)
				}
			}
		})
	}
}

// TestRedactsNatsCredsFile builds a real NATS .creds file the way nsc and
// nats-server tooling do: a user JWT signed by an account key, decorated
// with jwt.FormatUserConfig alongside the user's own nkey seed. Both must
// be gone from the redacted output.
func TestRedactsNatsCredsFile(t *testing.T) {
	r := redactor(t)
	userKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := userKP.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	accountKP, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.NewUserClaims(pub).Encode(accountKP)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := userKP.Seed()
	if err != nil {
		t.Fatal(err)
	}
	creds, err := jwt.FormatUserConfig(token, seed)
	if err != nil {
		t.Fatal(err)
	}
	in := "attached: device.creds\n\n" + string(creds)

	out, n, rules := r.Redact(in)
	if strings.Contains(out, token) {
		t.Fatalf("jwt survived:\n%s", out)
	}
	if strings.Contains(out, string(seed)) {
		t.Fatalf("seed survived:\n%s", out)
	}
	if n < 2 {
		t.Errorf("count = %d, want >= 2 (rules %v)", n, rules)
	}
	if !slices.Contains(rules, RuleNatsNkeySeed) {
		t.Errorf("rules = %v, want %s", rules, RuleNatsNkeySeed)
	}
	if !slices.Contains(rules, "jwt") {
		t.Errorf("rules = %v, want jwt", rules)
	}
	for _, k := range []string{"attached: device.creds", "-----BEGIN NATS USER JWT-----", "-----BEGIN USER NKEY SEED-----"} {
		if !strings.Contains(out, k) {
			t.Errorf("lost surrounding structure %q:\n%s", k, out)
		}
	}
}

func TestNatsSeedNoFalsePositives(t *testing.T) {
	// A 58-char uppercase run that shares the seed alphabet but has
	// characters (0, 1, 8, 9) outside base32 [A-Z2-7], so it cannot be an
	// nkey seed no matter where it starts.
	notBase32 := "SUA" + strings.Repeat("0189", 15)[:55]
	if len(notBase32) != 58 {
		panic("test fixture: want 58 chars")
	}
	cases := map[string]string{
		"success word":         "2024-01-15 10:23:45 INFO operation completed: SUCCESS",
		"subscribe word":       "2024-01-15 10:23:45 DEBUG client SUBSCRIBE to subject orders.>",
		"uppercase hex hash":   "sha1sum: DA39A3EE5E6B4B0D3255BFEF95601890AFD80709 for empty.txt",
		"58 chars, not base32": "field dump: " + notBase32 + " end of record",
	}
	r := redactor(t)
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out, n, rules := r.Redact(in)
			if n != 0 || out != in {
				t.Errorf("false positive: %d redactions by %v\n%s", n, rules, diffLines(in, out))
			}
		})
	}
}

func TestApplyOverlapAndAdjacency(t *testing.T) {
	text := "0123456789abcdef"
	out, n, rules := apply(text, []span{
		{start: 2, end: 6, rule: "a"},
		{start: 4, end: 8, rule: "b"},  // overlaps a: merged into a's replacement
		{start: 8, end: 10, rule: "c"}, // adjacent to the merged span: separate
		{start: 12, end: 14, rule: "d"},
		{start: 12, end: 13, rule: "e"}, // inside d
	})
	want := "01[REDACTED:a][REDACTED:c]ab[REDACTED:d]ef"
	if out != want || n != 3 {
		t.Errorf("got %q (%d), want %q (3)", out, n, want)
	}
	if !slices.Equal(rules, []string{"a", "b", "c", "d", "e"}) {
		t.Errorf("rules = %v", rules)
	}
}

func TestLocateFallsBackToEveryOccurrence(t *testing.T) {
	r := redactor(t)
	text := "token one XYZSECRET and XYZSECRET again"
	// A finding whose reported position is wrong: the secret is still
	// redacted wherever it appears.
	spans := r.locate(text, 0, newlines(text), fakeFinding("some-rule", "nope", "XYZSECRET", 0, 1))
	out, n, _ := apply(text, spans)
	if strings.Contains(out, "XYZSECRET") || n != 2 {
		t.Errorf("got %q (%d)", out, n)
	}
}

func fakeFinding(rule, match, secret string, line, col int) report.Finding {
	return report.Finding{RuleID: rule, Match: match, Secret: secret, StartLine: line, StartColumn: col}
}

func TestEmptyAndClean(t *testing.T) {
	r := redactor(t)
	if out, n, rules := r.Redact(""); out != "" || n != 0 || rules != nil {
		t.Errorf("empty: %q %d %v", out, n, rules)
	}
	if out, n, _ := r.Redact("hello world\n"); out != "hello world\n" || n != 0 {
		t.Errorf("clean: %q %d", out, n)
	}
}

func TestConcurrentUse(t *testing.T) {
	r := redactor(t)
	in := benignWindowsLogs["cbs"] + "Password=Winter2024!;\n" + benignWindowsLogs["iis"] + "aws_access_key_id=" + awsKeyID + "\n"
	want, wantN, _ := r.Redact(in)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				out, n, _ := r.Redact(in)
				if out != want || n != wantN {
					t.Errorf("concurrent result differs: %d vs %d", n, wantN)
					return
				}
			}
		})
	}
	wg.Wait()
}

// benchLog builds about size bytes of Windows server log text with a secret
// every 200 lines or so, which is denser than real logs.
func benchLog(size int) string {
	var parts []string
	for _, k := range []string{"cbs", "iis", "security-4624", "setupapi", "windowsupdate", "sql-errorlog", "netlogon", "dhcp"} {
		parts = append(parts, benignWindowsLogs[k])
	}
	chunk := strings.Join(parts, "")
	var b strings.Builder
	b.Grow(size + len(chunk))
	for i := 0; b.Len() < size; i++ {
		b.WriteString(chunk)
		if i%2 == 0 {
			fmt.Fprintf(&b, "2024-01-15 10:23:45 WARN retrying with Server=db01;User Id=app;Password=Rotated-%d!;\n", i)
		}
	}
	return b.String()[:size]
}

func benchmarkRedact(b *testing.B, size int) {
	r := redactor(b)
	text := benchLog(size)
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for b.Loop() {
		r.Redact(text)
	}
}

func BenchmarkRedact1MiB(b *testing.B) { benchmarkRedact(b, 1<<20) }
func BenchmarkRedact2MiB(b *testing.B) { benchmarkRedact(b, 2<<20) }

func BenchmarkNew(b *testing.B) {
	for b.Loop() {
		if _, err := New(); err != nil {
			b.Fatal(err)
		}
	}
}
