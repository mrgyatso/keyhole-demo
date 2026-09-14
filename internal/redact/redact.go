// Package redact replaces secrets in text before it leaves the endpoint.
//
// It wraps the gitleaks v8 detector with its default rule set, plus a few
// rules for shapes the defaults miss in Windows server configs and logs
// (connection-string passwords, XML and .NET config password settings,
// JSON/YAML password fields). Every secret becomes "[REDACTED:<rule-id>]",
// so the reader still sees the structure around it.
//
// gitleaks runs every rule whose keyword appears anywhere in the text over
// the whole text, and in a megabyte of logs nearly every keyword appears.
// So for long text each rule that allows it scans only windows around its
// own keywords (analyze.go explains why that finds the same secrets), and
// the windows are spread over a few goroutines.
package redact

import (
	"fmt"
	"io"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
)

// Redactor finds and replaces secrets. It is safe for concurrent use: the
// gitleaks detectors only read their compiled configuration while
// scanning. Build one with New and share it; construction compiles a few
// hundred regular expressions.
type Redactor struct {
	full  *detect.Detector // every rule; short text
	whole *detect.Detector // rules that cannot be windowed; long text
	win   []winRule        // windowable rules, one detector each; long text
	trie  *ahocorasick.Trie
	byKW  [][]int // trie pattern index -> indexes into win
	rules map[string]config.Rule
}

type winRule struct {
	id    string
	det   *detect.Detector
	reach reach
}

const (
	// windowMin is the text length from which windowed scanning pays off.
	windowMin = 32 << 10
	// mergeGap joins windows of one rule that are this close, trading a
	// little rescanning for fewer detector calls.
	mergeGap = 512
	// parallelMin is the scan volume from which windows are spread over
	// several goroutines, at most maxWorkers.
	parallelMin = 128 << 10
	maxWorkers  = 4
)

var (
	// newMu serialises construction: gitleaks loads its default config
	// through viper's global instance.
	newMu       sync.Mutex
	silenceOnce sync.Once
)

// New builds a Redactor from the gitleaks default rules plus Keyhole's own.
func New() (*Redactor, error) {
	newMu.Lock()
	defer newMu.Unlock()

	// gitleaks logs through a package-level zerolog logger on stderr, and at
	// trace level it would print secrets. The agent logs through slog only.
	silenceOnce.Do(func() { logging.Logger = logging.Logger.Output(io.Discard) })

	base, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("redact: load gitleaks default config: %w", err)
	}
	cfg := base.Config
	if err := fixGlobalAllowlists(&cfg); err != nil {
		return nil, err
	}
	for _, r := range extraRules() {
		if err := addRule(&cfg, r); err != nil {
			return nil, err
		}
	}
	return build(cfg), nil
}

func build(cfg config.Config) *Redactor {
	r := &Redactor{full: newDetector(cfg), rules: cfg.Rules}
	ids := make([]string, 0, len(cfg.Rules))
	for id := range cfg.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var whole, kwList []string
	kwIndex := map[string]int{}
	for _, id := range ids {
		rule := cfg.Rules[id]
		// Path-gated rules never fire on text without a file path, and
		// composite rules need their parts in the same detector.
		var rc reach
		ok := rule.Regex != nil && rule.Path == nil && len(rule.RequiredRules) == 0
		if ok {
			rc, ok = analyze(rule.Regex.String(), rule.Keywords)
		}
		if !ok {
			whole = append(whole, id)
			for _, req := range rule.RequiredRules {
				whole = append(whole, req.RuleID)
			}
			continue
		}
		wi := len(r.win)
		r.win = append(r.win, winRule{id: id, det: newDetector(subset(cfg, id)), reach: rc})
		for _, k := range rule.Keywords {
			p, seen := kwIndex[k]
			if !seen {
				p = len(kwList)
				kwIndex[k] = p
				kwList = append(kwList, k)
				r.byKW = append(r.byKW, nil)
			}
			if l := r.byKW[p]; len(l) == 0 || l[len(l)-1] != wi {
				r.byKW[p] = append(l, wi)
			}
		}
	}
	r.whole = newDetector(subset(cfg, whole...))
	r.trie = ahocorasick.NewTrieBuilder().AddStrings(kwList).Build()
	return r
}

func newDetector(cfg config.Config) *detect.Detector {
	d := detect.NewDetector(cfg)
	// Scanned text is untrusted: a "gitleaks:allow" marker in a log line
	// must not switch redaction off for that line.
	d.IgnoreGitleaksAllow = true
	return d
}

// subset is cfg reduced to the rules ids, keeping the global allowlists.
func subset(cfg config.Config, ids ...string) config.Config {
	c := config.Config{Rules: map[string]config.Rule{}, Keywords: map[string]struct{}{}, Allowlists: cfg.Allowlists}
	for _, id := range ids {
		if _, dup := c.Rules[id]; dup {
			continue
		}
		rule := cfg.Rules[id]
		c.Rules[id] = rule
		c.OrderedRules = append(c.OrderedRules, id)
		for _, k := range rule.Keywords {
			c.Keywords[k] = struct{}{}
		}
	}
	return c
}

// Placeholder is what a secret found by rule becomes.
func Placeholder(rule string) string { return "[REDACTED:" + rule + "]" }

// Redact returns text with every secret replaced by its Placeholder, the
// number of replacements made, and the sorted distinct rule IDs that fired.
func (r *Redactor) Redact(text string) (out string, count int, rules []string) {
	if text == "" {
		return text, 0, nil
	}
	// Under (?i), k and s also match the Kelvin sign and the long s, which
	// the ASCII keyword scan that places windows would not see.
	if len(text) < windowMin || strings.ContainsRune(text, 'K') || strings.ContainsRune(text, 'ſ') {
		return r.redactWhole(text)
	}
	nl := newlines(text)
	return apply(text, r.scanWindows(text, nl))
}

// redactWhole scans the whole text with every rule, as gitleaks does.
func (r *Redactor) redactWhole(text string) (string, int, []string) {
	return apply(text, r.scan(r.full, text, 0, len(text), newlines(text)))
}

// task is one detector run over text[start:end].
type task struct {
	det        *detect.Detector
	start, end int
}

func (r *Redactor) scanWindows(text string, nl []int) []span {
	tasks := r.plan(text, nl)
	total := 0
	for _, t := range tasks {
		total += t.end - t.start
	}
	workers := 1
	if total >= parallelMin {
		workers = min(runtime.GOMAXPROCS(0), maxWorkers, len(tasks))
	}
	results := make([][]span, workers)
	var next atomic.Int64
	work := func(w int) {
		for {
			i := int(next.Add(1) - 1)
			if i >= len(tasks) {
				return
			}
			t := tasks[i]
			results[w] = append(results[w], r.scan(t.det, text, t.start, t.end, nl)...)
		}
	}
	if workers == 1 {
		work(0)
		return results[0]
	}
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() { work(w) })
	}
	wg.Wait()
	return slices.Concat(results...)
}

// plan lists the detector runs for long text: the non-windowable rules over
// the whole text, and each windowable rule over the lines around its own
// keywords.
func (r *Redactor) plan(text string, nl []int) []task {
	lines := make([][]int, len(r.win)) // per rule: keyword lines, ascending
	line := 0
	r.trie.Walk(asciiLower(text), func(end, _, pattern int64) bool {
		// Keywords hold no newline, so a keyword is on its end's line;
		// Walk reports ends in increasing order.
		for line < len(nl) && nl[line] < int(end) {
			line++
		}
		for _, wi := range r.byKW[pattern] {
			if ls := lines[wi]; len(ls) == 0 || ls[len(ls)-1] != line {
				lines[wi] = append(ls, line)
			}
		}
		return true
	})

	tasks := []task{{det: r.whole, start: 0, end: len(text)}}
	for wi, ls := range lines {
		if len(ls) == 0 {
			continue
		}
		rc := r.win[wi].reach
		cur := task{det: r.win[wi].det, start: -1}
		for _, l := range ls {
			start, end := lineStart(nl, l), lineEnd(nl, l, len(text))
			limit := end + rc.bytes
			if rc.bytes >= unbounded {
				limit = len(text)
			}
			for n := 0; n < rc.lines && end < len(text) && end < limit; n++ {
				end = lineEnd(nl, sort.SearchInts(nl, end), len(text))
			}
			if cur.start >= 0 && start <= cur.end+mergeGap {
				cur.end = max(cur.end, end)
				continue
			}
			if cur.start >= 0 {
				tasks = append(tasks, cur)
			}
			cur.start, cur.end = start, end
		}
		tasks = append(tasks, cur)
	}
	return tasks
}

// scan runs det over text[start:end] and returns the secrets' spans in text.
func (r *Redactor) scan(det *detect.Detector, text string, start, end int, nl []int) []span {
	findings := det.DetectString(text[start:end])
	if len(findings) == 0 {
		return nil
	}
	wnl := nl[sort.SearchInts(nl, start):sort.SearchInts(nl, end)]
	var out []span
	for _, f := range findings {
		out = append(out, r.locate(text, start, wnl, f)...)
	}
	return out
}

// span is a byte range of text to replace, and the rule that found it.
type span struct {
	start, end int
	rule       string
}

// locate turns a finding from a scan of text[base:] into the byte range of
// its secret in text. nl holds the offsets in text of the newlines inside
// the scanned range.
//
// gitleaks reports where the rule's match starts as a line number within
// the scanned range and a column (counted from the previous newline byte,
// so 1-based on the first line and off by one on the others); undo exactly
// that. If the match is not where it should be, fall back to every
// occurrence of the secret: redacting too much is the safe failure.
func (r *Redactor) locate(text string, base int, nl []int, f report.Finding) []span {
	if f.Secret == "" {
		return nil
	}
	start := base + f.StartColumn - 1
	if f.StartLine > 0 {
		if f.StartLine-1 >= len(nl) {
			return everywhere(text, f.Secret, f.RuleID)
		}
		start = nl[f.StartLine-1] + f.StartColumn - 1
	}
	// gitleaks trims newlines off the ends of a match without moving its
	// start, so a match that began with "\n" starts a little later.
	for start >= 0 && start < len(text) && text[start] == '\n' && !strings.HasPrefix(text[start:], f.Match) {
		start++
	}
	if start < 0 || start > len(text) || f.Match == "" || !strings.HasPrefix(text[start:], f.Match) {
		return everywhere(text, f.Secret, f.RuleID)
	}
	a, b := secretIn(r.rules[f.RuleID], f)
	return []span{{start: start + a, end: start + b, rule: f.RuleID}}
}

// secretIn returns the secret's range within f.Match by re-running the rule
// on the match, which is how gitleaks extracted the secret in the first
// place: the configured secret group, or else the first non-empty group.
func secretIn(rule config.Rule, f report.Finding) (int, int) {
	if f.Secret == f.Match {
		return 0, len(f.Match)
	}
	if rule.Regex != nil {
		if loc := rule.Regex.FindStringSubmatchIndex(f.Match); len(loc) >= 4 {
			group := func(g int) (int, int, bool) {
				a, b := loc[2*g], loc[2*g+1]
				return a, b, a >= 0 && a < b && f.Match[a:b] == f.Secret
			}
			if g := rule.SecretGroup; g > 0 && 2*g+1 < len(loc) {
				if a, b, ok := group(g); ok {
					return a, b
				}
			}
			for g := 1; 2*g+1 < len(loc); g++ {
				if a, b, ok := group(g); ok {
					return a, b
				}
			}
		}
	}
	// Values follow keys, so the last occurrence is the likelier one.
	if i := strings.LastIndex(f.Match, f.Secret); i >= 0 {
		return i, i + len(f.Secret)
	}
	return 0, len(f.Match)
}

// everywhere returns a span for each occurrence of secret in text.
func everywhere(text, secret, rule string) []span {
	var out []span
	for i := 0; ; {
		j := strings.Index(text[i:], secret)
		if j < 0 {
			return out
		}
		out = append(out, span{start: i + j, end: i + j + len(secret), rule: rule})
		i += j + len(secret)
	}
}

// apply replaces spans in text. Overlapping spans merge into one
// replacement, labelled with the rule whose span starts first (the longest,
// then a specific rule over a generic one, on a tie); adjacent spans stay
// separate replacements.
func apply(text string, spans []span) (string, int, []string) {
	if len(spans) == 0 {
		return text, 0, nil
	}
	sort.Slice(spans, func(i, j int) bool {
		a, b := spans[i], spans[j]
		if a.start != b.start {
			return a.start < b.start
		}
		if a.end != b.end {
			return a.end > b.end
		}
		if ga, gb := isGeneric(a.rule), isGeneric(b.rule); ga != gb {
			return gb
		}
		return a.rule < b.rule
	})
	spans = dropShadowedGeneric(spans)

	fired := map[string]struct{}{}
	var b strings.Builder
	b.Grow(len(text))
	count, last := 0, 0
	cur := spans[0]
	flush := func() {
		b.WriteString(text[last:cur.start])
		b.WriteString(Placeholder(cur.rule))
		last = cur.end
		count++
	}
	fired[cur.rule] = struct{}{}
	for _, s := range spans[1:] {
		fired[s.rule] = struct{}{}
		if s.start < cur.end {
			cur.end = max(cur.end, s.end)
			continue
		}
		flush()
		cur = s
	}
	flush()
	b.WriteString(text[last:])

	rules := make([]string, 0, len(fired))
	for id := range fired {
		rules = append(rules, id)
	}
	sort.Strings(rules)
	return b.String(), count, rules
}

// dropShadowedGeneric does across detectors what gitleaks does within one:
// a generic-rule finding inside a specific rule's finding is the same
// secret, credited to the specific rule. spans must be sorted by start.
func dropShadowedGeneric(spans []span) []span {
	out := spans[:0]
	specificEnd := -1 // furthest end of a specific span starting at or before the current one
	for _, s := range spans {
		if !isGeneric(s.rule) {
			specificEnd = max(specificEnd, s.end)
		} else if specificEnd >= s.end {
			continue
		}
		out = append(out, s)
	}
	return out
}

func isGeneric(rule string) bool { return strings.Contains(strings.ToLower(rule), "generic") }

// newlines returns the byte offset of every '\n' in text.
func newlines(text string) []int {
	var nl []int
	for i := 0; ; {
		j := strings.IndexByte(text[i:], '\n')
		if j < 0 {
			return nl
		}
		nl = append(nl, i+j)
		i += j + 1
	}
}

func lineStart(nl []int, l int) int {
	if l == 0 {
		return 0
	}
	return nl[l-1] + 1
}

// lineEnd is the offset just past line l's newline, or n for the last line.
func lineEnd(nl []int, l, n int) int {
	if l < len(nl) {
		return nl[l] + 1
	}
	return n
}

func asciiLower(s string) []byte {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return b
}
