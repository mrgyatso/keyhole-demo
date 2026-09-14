package redact

import (
	"fmt"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// Keyhole's own rule IDs. They cover secrets the gitleaks defaults miss
// because they have no recognisable prefix and often little entropy: the
// passwords in Windows server configs and in the logs that echo them.
const (
	RuleConnString   = "keyhole-connection-string-password" // Password=…; / Pwd=…; and key=value settings
	RuleXMLPassword  = "keyhole-xml-password"               // <password>…</password>, including unattend <Value>
	RuleAppSetting   = "keyhole-appsettings-password"       // web.config <add key="…Password" value="…" />
	RuleUserSetting  = "keyhole-usersettings-password"      // .NET <setting name="…Password"><value>…</value>
	RuleJSONPassword = "keyhole-json-password"              // "password": "…"
	RuleYAMLPassword = "keyhole-yaml-password"              // password: …
	RuleNatsNkeySeed = "keyhole-nats-nkey-seed"             // NATS nkey seed (SU.../SA.../SO... etc.), e.g. in a .creds file
)

// The rules are written to be windowable (see analyze.go): the key comes
// before anything that can match a newline, and whitespace between tags is
// bounded, so each rule scans only the lines around its keywords.
const (
	passwordWord = `(?:password|passwd|pwd)`
	passwordKey  = `[\w.:-]{0,64}(?:password|passwd|pwd|secret)`
	settingKey   = `["'][^"'\r\n]{0,128}(?:password|passwd|pwd|secret|api[_.-]?key|token)["']`
)

func extraRules() []config.Rule {
	notSecret := &config.Allowlist{
		Description: "empty values, placeholders, flags, paths and earlier redactions",
		Regexes: []*regexp.Regexp{
			regexp.MustCompile(`^\s*$`),
			regexp.MustCompile(`(?i)^(?:none|nil|null|undefined|empty|n/a|[0-9])$`),
			regexp.MustCompile(`^(?:/[\w.-]*)+/?$`), // PWD=/root in an environment dump
			regexp.MustCompile(`^\[REDACTED:[\w.-]+\]$`),
		},
	}
	allow := []*config.Allowlist{notSecret}
	pw := []string{"password", "passwd", "pwd"}
	pwSecret := []string{"password", "passwd", "pwd", "secret"}
	setting := []string{"password", "passwd", "pwd", "secret", "apikey", "api_key", "api-key", "api.key", "token"}

	return []config.Rule{
		{
			RuleID:      RuleConnString,
			Description: "Password in a connection string or key=value setting (ADO.NET, ODBC, OLE DB, INI).",
			// Password/Pwd (or any key ending in them), "=", then a quoted,
			// {braced} (ODBC) or bare value running to ";", a quote or the
			// end of the line.
			Regex: regexp.MustCompile(`(?i)(?:passw(?:or)?d|pwd)[ \t]*=[ \t]*` +
				`(?:"([^"\r\n]{1,256})"|'([^'\r\n]{1,256})'|\{([^}\r\n]{1,256})\}|([^;"'\r\n]{1,256}))`),
			Keywords:   pw,
			Allowlists: allow,
		},
		{
			RuleID:      RuleXMLPassword,
			Description: "Password element in XML, including unattend-style <Password><Value>…</Value>.",
			Regex: regexp.MustCompile(`(?i)<[\w.:-]{0,64}` + passwordWord + `\b[^<>\r\n]{0,256}>\s{0,64}` +
				`(?:<value>([^<\r\n]{1,512})</value>|([^<\r\n]{1,256}?)\s{0,64}</[\w.:-]{0,64}` + passwordWord + `\s{0,8}>)`),
			Keywords:   pw,
			Allowlists: allow,
		},
		{
			RuleID:      RuleAppSetting,
			Description: "Password, secret, API key or token in a .NET config appSettings entry.",
			Regex: regexp.MustCompile(`(?i)<add[ \t]+key[ \t]*=[ \t]*` + settingKey +
				`[ \t]+value[ \t]*=[ \t]*(?:"([^"\r\n]{1,512})"|'([^'\r\n]{1,512})')`),
			Keywords:   setting,
			Allowlists: allow,
		},
		{
			RuleID:      RuleUserSetting,
			Description: "Password, secret, API key or token in a .NET applicationSettings/userSettings entry.",
			Regex: regexp.MustCompile(`(?i)<setting[ \t]+name[ \t]*=[ \t]*` + settingKey +
				`[^<>\r\n]{0,256}>\s{0,64}<value>([^<\r\n]{1,512})</value>`),
			Keywords:   setting,
			Allowlists: allow,
		},
		{
			RuleID:      RuleJSONPassword,
			Description: "Password or secret field in JSON.",
			Regex:       regexp.MustCompile(`(?i)"` + passwordKey + `"\s{0,16}:\s{0,16}"((?:[^"\\\r\n]|\\.){1,512})"`),
			Keywords:    pwSecret,
			Allowlists:  allow,
		},
		{
			RuleID:      RuleYAMLPassword,
			Description: "Password or secret key in YAML, with a plain or quoted scalar value.",
			// Block scalars, anchors, aliases, tags and flow collections are
			// left alone; so is anything after a comment marker.
			Regex: regexp.MustCompile(`(?im)^[ \t]*(?:-[ \t]+)?` + passwordKey + `[ \t]*:[ \t]+` +
				`(?:"((?:[^"\\\r\n]|\\.){1,512})"|'([^'\r\n]{1,512})'|([^\s"'#&*!|>{\[,%@\x60][^\r\n#]{0,511}?))` +
				`[ \t]*(?:#[^\r\n]*)?\r?$`),
			Keywords:   pwSecret,
			Allowlists: allow,
		},
		{
			RuleID: RuleNatsNkeySeed,
			Description: "NATS nkey seed: the private key half of a user, account or operator " +
				"identity (as embedded in a .creds file alongside its user JWT).",
			// A seed is 58 base32 (RFC4648, no padding, upper-case only:
			// A-Z and 2-7) characters: 'S', a type letter (U user, A
			// account, O operator, N server, C cluster, X curve), then a
			// third character that the seed encoding always fixes to 'A'
			// for that type (confirmed by encoding thousands of random
			// raw seeds of each type: SUA…, SAA…, SOA…, SNA…, SCA…,
			// SXA…, never anything else), then 55 more base32 characters.
			// \b keeps this from matching inside a longer base32/base64
			// run, the same way gitleaks' own aws-access-token rule
			// anchors AKIA…/ASIA… over the identical [A-Z2-7] alphabet.
			Regex: regexp.MustCompile(`\b(S[UAONCX]A[A-Z2-7]{55})\b`),
			// The keywords are the seed's own fixed 3-character prefix
			// per type, lower-cased (addRule lower-cases them again, so
			// this is belt-and-braces): unlike "password"/"secret" style
			// keywords, a seed carries no descriptive label of its own,
			// so the only thing guaranteed to be nearby is the seed
			// itself. Anchoring on it keeps the rule windowable (see
			// analyze.go) instead of falling back to a whole-text scan.
			Keywords: []string{"sua", "saa", "soa", "sna", "sca", "sxa"},
		},
	}
}

// addRule registers r with cfg the way gitleaks' own config loader does:
// lower-cased keywords feed the prefilter, and the rule is validated.
func addRule(cfg *config.Config, r config.Rule) error {
	kws := make([]string, len(r.Keywords))
	for i, k := range r.Keywords {
		kws[i] = strings.ToLower(k)
	}
	r.Keywords = kws
	if err := r.Validate(); err != nil {
		return fmt.Errorf("redact: rule %s: %w", r.RuleID, err)
	}
	if _, dup := cfg.Rules[r.RuleID]; dup {
		return fmt.Errorf("redact: rule %s already exists", r.RuleID)
	}
	cfg.Rules[r.RuleID] = r
	cfg.OrderedRules = append(cfg.OrderedRules, r.RuleID)
	for _, k := range kws {
		cfg.Keywords[k] = struct{}{}
	}
	return nil
}

// brokenAllowRegex is in gitleaks' default global allowlist. Its alternation
// has no group, so it reads as "^true" OR "false" OR "null$" and lets
// through any secret that merely contains "false" (Password=Falsetto99;).
const brokenAllowRegex = `(?i)^true|false|null$`

// fixGlobalAllowlists swaps brokenAllowRegex for the anchored form it was
// meant to be. Allowlists compile their regexes once when validated, so a
// fixed allowlist is rebuilt rather than edited in place.
func fixGlobalAllowlists(cfg *config.Config) error {
	for i, a := range cfg.Allowlists {
		regexes := make([]*regexp.Regexp, len(a.Regexes))
		fixed := false
		for j, re := range a.Regexes {
			if re.String() == brokenAllowRegex {
				re, fixed = regexp.MustCompile(`(?i)^(?:true|false|null)$`), true
			}
			regexes[j] = re
		}
		if !fixed {
			continue
		}
		rebuilt := &config.Allowlist{
			Description:    a.Description,
			MatchCondition: a.MatchCondition,
			Commits:        a.Commits,
			Paths:          a.Paths,
			RegexTarget:    a.RegexTarget,
			Regexes:        regexes,
			StopWords:      a.StopWords,
		}
		if err := rebuilt.Validate(); err != nil {
			return fmt.Errorf("redact: rebuild global allowlist: %w", err)
		}
		cfg.Allowlists[i] = rebuilt
	}
	return nil
}
