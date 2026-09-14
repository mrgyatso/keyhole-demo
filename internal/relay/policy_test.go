package relay

import (
	"testing"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

func TestValidatePolicy(t *testing.T) {
	if err := validatePolicy(policy.DefaultClientPolicy()); err != nil {
		t.Fatalf("the shipped default policy is invalid: %v", err)
	}
	with := func(goos string, rules ...proto.AllowRule) model.ClientPolicy {
		p := policy.DefaultClientPolicy()
		p.Allow = map[string][]proto.AllowRule{goos: rules}
		return p
	}
	rule := func(path string, files ...string) proto.AllowRule {
		return proto.AllowRule{ID: "r", Path: path, Files: files}
	}
	good := []model.ClientPolicy{
		with("windows", rule(`C:\`)),
		with("windows", rule(`c:\ProgramData\*\Logs`, "*.log", "setupapi*.log")),
		with("windows", rule(`D:\Program Files\App [x86]\logs`)),
		with("linux", rule("/")),
		with("darwin", rule("/Library/Logs/DiagnosticReports")),
		with("linux"),
	}
	for i, p := range good {
		if err := validatePolicy(p); err != nil {
			t.Errorf("good[%d]: %v", i, err)
		}
	}

	caps := func(edit func(*model.ClientPolicy)) model.ClientPolicy {
		p := policy.DefaultClientPolicy()
		edit(&p)
		return p
	}
	bad := map[string]model.ClientPolicy{
		"no id":                {Allow: map[string][]proto.AllowRule{"linux": {{Path: "/var/log"}}}},
		"duplicate id":         with("linux", rule("/var/log"), rule("/etc")),
		"unknown os":           with("plan9", rule("/sys/log")),
		"relative windows":     with("windows", rule(`Windows\Logs`)),
		"UNC":                  with("windows", rule(`\\server\share\logs`)),
		"device path":          with("windows", rule(`\\?\C:\Windows`)),
		"forward slashes":      with("windows", rule(`C:/Windows/Logs`)),
		"mixed slashes":        with("windows", rule(`C:\Windows/Logs`)),
		"dot-dot":              with("windows", rule(`C:\Windows\..\Users`)),
		"empty segment":        with("windows", rule(`C:\Windows\\Logs`)),
		"trailing separator":   with("windows", rule(`C:\Windows\Logs\`)),
		"alternate data":       with("windows", rule(`C:\Windows\Logs:stream`)),
		"drive only":           with("windows", rule(`C:`)),
		"relative linux":       with("linux", rule("var/log")),
		"linux dot":            with("linux", rule("/var/./log")),
		"linux empty segment":  with("linux", rule("/var//log")),
		"linux trailing slash": with("linux", rule("/var/log/")),
		"bad glob":             with("linux", rule("/var/[log")),
		"control character":    with("linux", rule("/var/log\n")),
		"files with separator": with("linux", rule("/var/log", "nginx/*.log")),
		"empty files glob":     with("linux", rule("/var/log", "")),
		"bad files glob":       with("linux", rule("/var/log", "[")),
		"zero read cap":        caps(func(p *model.ClientPolicy) { p.MaxReadBytes = 0 }),
		"read cap over payload": caps(func(p *model.ClientPolicy) {
			p.MaxReadBytes = 8 << 20
		}),
		"zero list cap":    caps(func(p *model.ClientPolicy) { p.MaxListEntries = 0 }),
		"zero matches":     caps(func(p *model.ClientPolicy) { p.MaxMatches = 0 }),
		"negative file":    caps(func(p *model.ClientPolicy) { p.MaxFileBytes = -1 }),
		"no budget":        caps(func(p *model.ClientPolicy) { p.SessionBudgetBytes = 0 }),
		"too many matches": caps(func(p *model.ClientPolicy) { p.MaxMatches = 1 << 20 }),
	}
	for name, p := range bad {
		if name == "no id" {
			p.MaxReadBytes, p.MaxFileBytes, p.MaxListEntries, p.MaxMatches, p.SessionBudgetBytes = 1, 1, 1, 1, 1
		}
		if err := validatePolicy(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
