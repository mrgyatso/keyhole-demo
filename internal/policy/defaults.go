// Package policy holds the shipped scope: the default allowlist every new
// client starts from, and (agent side) the hard-deny list and path matching
// that no client policy can override.
package policy

import (
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Default caps for a new client.
const (
	DefaultMaxReadBytes       = 2 << 20  // one read_file slice
	DefaultMaxFileBytes       = 50 << 20 // grep skips and hash_file refuses bigger files
	DefaultMaxListEntries     = 1000
	DefaultMaxMatches         = 500
	DefaultSessionBudgetBytes = 64 << 20 // total content one MCP session may receive
)

// DefaultAllow is the shipped allowlist, keyed by GOOS. It is aimed at
// "troubleshoot a server": logs and setup records, not user data. Sources:
// research/07-scope-redaction-cost.md and the plan's "Scoped by default".
func DefaultAllow() map[string][]proto.AllowRule {
	return map[string][]proto.AllowRule{
		"windows": {
			{ID: "win-logs", Path: `C:\Windows\Logs`}, // CBS, WindowsUpdate, DISM, MoSetup
			{ID: "win-panther", Path: `C:\Windows\Panther`},
			{ID: "win-setupapi", Path: `C:\Windows\INF`, Files: []string{"setupapi*.log"}},
			{ID: "win-debug", Path: `C:\Windows\debug`}, // netlogon.log, NetSetup.LOG
			{ID: "win-system32-logfiles", Path: `C:\Windows\System32\LogFiles`},
			{ID: "win-uso", Path: `C:\ProgramData\USOShared\Logs`},
			{ID: "iis-logs", Path: `C:\inetpub\logs\LogFiles`},
			{ID: "sql-errorlog", Path: `C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log`},
			{ID: "exchange-logging", Path: `C:\Program Files\Microsoft\Exchange Server\V15\Logging`},
			{ID: "veeam", Path: `C:\ProgramData\Veeam\Backup`, Files: []string{"*.log"}},
			{ID: "dhcp-audit", Path: `C:\Windows\System32\dhcp`, Files: []string{"DhcpSrvLog-*.log", "DhcpV6SrvLog-*.log"}},
			{ID: "dns-debug", Path: `C:\Windows\System32\dns`, Files: []string{"dns.log"}},
			{ID: "screenconnect", Path: `C:\ProgramData\ScreenConnect Client*`, Files: []string{"*.log", "*.txt"}},
			{ID: "vendor-logs", Path: `C:\ProgramData\*\Logs`, Files: []string{"*.log", "*.txt"}},
		},
		"linux": {
			{ID: "linux-var-log", Path: "/var/log"},
			{ID: "linux-etc", Path: "/etc"},
			{ID: "linux-mssql", Path: "/var/opt/mssql/log"},
		},
		"darwin": {
			{ID: "mac-var-log", Path: "/private/var/log"},
			{ID: "mac-library-logs", Path: "/Library/Logs"},
		},
	}
}

// DefaultClientPolicy is the policy a new client is created with.
func DefaultClientPolicy() model.ClientPolicy {
	return model.ClientPolicy{
		Version:            1,
		Allow:              DefaultAllow(),
		MaxReadBytes:       DefaultMaxReadBytes,
		MaxFileBytes:       DefaultMaxFileBytes,
		MaxListEntries:     DefaultMaxListEntries,
		MaxMatches:         DefaultMaxMatches,
		SessionBudgetBytes: DefaultSessionBudgetBytes,
		Redact:             true,
	}
}
