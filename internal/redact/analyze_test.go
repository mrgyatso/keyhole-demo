package redact

import "testing"

func TestAnalyze(t *testing.T) {
	generic := `(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|key|passw(?:or)?d)(?:[ \t\w.-]{0,20})[\s'"]{0,3}` +
		`(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"\s;]|\\[nr]|$)`
	cases := []struct {
		name    string
		pattern string
		kws     []string
		ok      bool
		lines   int
	}{
		{"semi-generic", generic, []string{"access", "auth", "api", "key", "password", "passwd"}, true, 8},
		{"prefixed token", `\b(ghp_[0-9a-zA-Z]{36})(?:[\x60'"\s;]|\\[nr]|$)`, []string{"ghp_"}, true, 0},
		{"factored keyword", `(?i)(?:passw(?:or)?d|pwd)[ \t]*=[ \t]*([^;\r\n]{1,256})`, []string{"password", "passwd", "pwd"}, true, 0},
		{"alternation of windowable branches", `(?i)(?:<add key="[^"\r\n]*password"|<setting name="[^"\r\n]*password">\s{0,8}<value>)`, []string{"password"}, true, 8},
		{"pem block", `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`, []string{"-----begin"}, false, 0},
		{"newline before keyword", `(?i)\s(ghp_[0-9a-zA-Z]{36})`, []string{"ghp_"}, false, 0},
		{"unbounded newlines after keyword", `(?i)password\s*=\s*(\S+)`, []string{"password"}, false, 0},
		{"keyword not in pattern", `(?i)xyz([a-z]{10})`, []string{"abc"}, false, 0},
		{"no keywords", `(?i)xyz([a-z]{10})`, nil, false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, ok := analyze(c.pattern, c.kws)
			if ok != c.ok {
				t.Fatalf("windowable = %v, want %v", ok, c.ok)
			}
			if ok && r.lines != c.lines {
				t.Errorf("lines = %d, want %d", r.lines, c.lines)
			}
			if ok && r.lines > 0 && r.bytes >= unbounded {
				t.Errorf("bytes unbounded")
			}
		})
	}
}

func TestWindowability(t *testing.T) {
	r := redactor(t)
	windowed := map[string]bool{}
	for _, w := range r.win {
		windowed[w.id] = true
	}
	for _, id := range []string{"generic-api-key", "aws-access-token", "github-pat", "jwt", "slack-bot-token",
		RuleConnString, RuleXMLPassword, RuleAppSetting, RuleUserSetting, RuleJSONPassword, RuleYAMLPassword} {
		if !windowed[id] {
			t.Errorf("%s should be windowable", id)
		}
	}
	if windowed["private-key"] {
		t.Error("private-key spans many lines and must scan the whole text")
	}
	var whole []string
	for id := range r.whole.Config.Rules {
		whole = append(whole, id)
	}
	t.Logf("%d windowed rules; whole-text rules: %v", len(r.win), whole)
}
