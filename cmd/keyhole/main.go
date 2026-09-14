// Command keyhole is the MSP tech's admin CLI for Keyhole. It talks to the
// relay's admin API over Tailscale, and pushes enrollment tokens into
// NinjaOne organizations that are on an explicit allowlist.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminclient"
	"github.com/mrgyatso/keyhole/internal/ninja"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Exit codes.
const (
	exitOK          = 0
	exitError       = 1
	exitUsage       = 2
	exitChainBroken = 3 // audit verify found a break
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	a := &app{
		in:          os.Stdin,
		out:         os.Stdout,
		errw:        os.Stderr,
		getenv:      os.Getenv,
		interactive: isTerminal(os.Stdin),
		readSecret:  func() (string, error) { return readSecretFrom(os.Stdin) },
		editFile:    func(ctx context.Context, path string) error { return runEditor(ctx, path, os.Getenv) },
		now:         time.Now,
		st:          style{on: isTerminal(os.Stdout) && isTerminal(os.Stderr) && os.Getenv("NO_COLOR") == ""},
	}
	os.Exit(a.run(ctx, os.Args[1:]))
}

// app is one invocation's environment. Tests build their own.
type app struct {
	in          io.Reader
	out, errw   io.Writer
	getenv      func(string) string
	interactive bool                                         // stdin is a terminal, so prompting is allowed
	readSecret  func() (string, error)                       // reads a line without echo
	editFile    func(ctx context.Context, path string) error // opens path in the user's editor
	now         func() time.Time
	hc          *http.Client // nil means each client's default
	st          style
}

// command is one "keyhole <group> <verb>" entry.
type command struct {
	name string // "client add"
	args string // argument synopsis
	help string
	run  func(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error
}

func commands() []command {
	return []command{
		{"config set", "<key> [value]", "set relay_url, admin_token (prompted), actor, public_url, ninja.allowed_org_ids", cmdConfigSet},
		{"config show", "", "show the config, admin token masked", cmdConfigShow},
		{"client add", "<slug> --name NAME", "create a client with the default policy", cmdClientAdd},
		{"client list", "", "list clients", cmdClientList},
		{"client show", "<slug>", "show one client", cmdClientShow},
		{"client disable", "<slug> [--reason TEXT]", "kill switch: refuse every Claude call for the client", cmdClientDisable},
		{"client enable", "<slug>", "turn the kill switch off", cmdClientEnable},
		{"policy show", "<slug>", "show the client's scope (--json prints the editable document)", cmdPolicyShow},
		{"policy set", "<slug> --file FILE", "replace the client's policy with a JSON document (- for stdin)", cmdPolicySet},
		{"policy edit", "<slug>", "edit the client's policy in $EDITOR", cmdPolicyEdit},
		{"token mint", "<slug> [--ttl-days 90] [--max-uses N] [--note TEXT]", "mint an enrollment token and print install commands", cmdTokenMint},
		{"token list", "<slug>", "list enrollment tokens", cmdTokenList},
		{"token revoke", "<id>", "revoke an enrollment token", cmdTokenRevoke},
		{"device list", "<slug>", "list enrolled devices", cmdDeviceList},
		{"device revoke", "<id>", "revoke a device's credential", cmdDeviceRevoke},
		{"session mint", "<slug> --tech NAME [--ttl 12h] [--note TEXT]", "mint an MCP bearer and print the claude mcp add command", cmdSessionMint},
		{"session list", "<slug>", "list MCP sessions", cmdSessionList},
		{"session revoke", "<id>", "revoke an MCP session", cmdSessionRevoke},
		{"technician grant", "<subject> <slug>", "grant an identity-provider technician access to a client", cmdTechnicianGrant},
		{"technician clients", "<subject>", "list a technician's client ACLs", cmdTechnicianClients},
		{"technician revoke", "<subject> <slug>", "revoke a technician's client access", cmdTechnicianRevoke},
		{"technician passkey-link", "<subject>", "mint a one-time link that enrolls a passkey for a technician", cmdTechnicianPasskeyLink},
		{"technician passkeys", "<subject>", "list a technician's passkeys", cmdTechnicianPasskeys},
		{"technician passkey-revoke", "<credential-id> [--yes]", "revoke a technician's passkey", cmdTechnicianPasskeyRevoke},
		{"audit report", "<slug> [--from T] [--to T] [--format csv|jsonl|pdf] [-o FILE]", "export the client's audit log", cmdAuditReport},
		{"audit verify", "<slug>", "verify the client's audit hash chain", cmdAuditVerify},
		{"ninja orgs", "", "list NinjaOne organizations", cmdNinjaOrgs},
		{"ninja fields", "<org>", "show an organization's custom fields, secrets masked", cmdNinjaFields},
		{"ninja push", "<slug> --org ID [--ttl-days 90] [--enable]", "mint a token and write it to the org's keyholeEnrollToken field", cmdNinjaPush},
		{"version", "", "print the version", cmdVersion},
	}
}

// usageError is a bad invocation. run prints it with the command synopsis.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return usageError{fmt.Sprintf(format, args...)} }

// exitCode ends the run with a specific exit code. msg, if set, is printed.
type exitCode struct {
	code int
	msg  string
}

func (e exitCode) Error() string { return e.msg }

// errAborted is a declined confirmation.
var errAborted = errors.New("aborted; nothing was changed")

func (a *app) run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.usage(a.errw)
		return exitUsage
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		a.usage(a.out)
		return exitOK
	}
	cmd, rest, err := lookup(args)
	if err != nil {
		fmt.Fprintf(a.errw, "keyhole: %v\n", err)
		return exitUsage
	}
	fs := flag.NewFlagSet("keyhole "+cmd.name, flag.ContinueOnError)
	fs.SetOutput(a.errw)
	fs.Usage = func() {
		fmt.Fprintf(a.errw, "usage: keyhole %s %s\n\n  %s\n\n", cmd.name, cmd.args, cmd.help)
		fs.PrintDefaults()
	}
	err = cmd.run(a, ctx, fs, rest)
	var ue usageError
	var ee exitCode
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.As(err, &ue):
		fmt.Fprintf(a.errw, "keyhole %s: %s\nusage: keyhole %s %s\n", cmd.name, ue.msg, cmd.name, cmd.args)
		return exitUsage
	case errors.As(err, &ee):
		if ee.msg != "" {
			fmt.Fprintln(a.errw, ee.msg)
		}
		return ee.code
	}
	fmt.Fprintf(a.errw, "%s %v\n", a.st.red("keyhole:"), err)
	if hint := a.hint(err); hint != "" {
		fmt.Fprintln(a.errw, a.st.dim(hint))
	}
	return exitError
}

// lookup finds the command named by the first one or two words of args.
func lookup(args []string) (command, []string, error) {
	all := commands()
	if len(args) >= 2 {
		for _, c := range all {
			if c.name == args[0]+" "+args[1] {
				return c, args[2:], nil
			}
		}
	}
	for _, c := range all {
		if c.name == args[0] {
			return c, args[1:], nil
		}
	}
	var verbs []string
	for _, c := range all {
		if group, verb, ok := strings.Cut(c.name, " "); ok && group == args[0] {
			verbs = append(verbs, verb)
		}
	}
	if len(verbs) > 0 {
		if len(args) == 1 {
			return command{}, nil, fmt.Errorf("%s needs a subcommand: %s", args[0], strings.Join(verbs, ", "))
		}
		return command{}, nil, fmt.Errorf("unknown command %q (%s has: %s)", args[0]+" "+args[1], args[0], strings.Join(verbs, ", "))
	}
	return command{}, nil, fmt.Errorf("unknown command %q; run keyhole help", args[0])
}

func (a *app) usage(w io.Writer) {
	fmt.Fprintf(w, "%s: scoped, audited, read-only file access for Claude on client machines\n\n", a.st.bold("keyhole"))
	tw := newAligned(w)
	group := ""
	for _, c := range commands() {
		g, _, _ := strings.Cut(c.name, " ")
		if g != group && group != "" {
			fmt.Fprintln(tw)
		}
		group = g
		fmt.Fprintf(tw, "  keyhole %s %s\t%s\n", c.name, c.args, c.help)
	}
	_ = tw.Flush()
	path, _ := configPath(a.getenv)
	fmt.Fprintf(w, "\n%s\n%s\n%s\n",
		a.st.dim("flags:   --json for machine output; --yes skips the confirmation on disable and revoke"),
		a.st.dim("config:  "+path+" (KEYHOLE_CONFIG overrides; ninja.env sits beside it)"),
		a.st.dim("secrets: tokens and bearers are shown once, when minted, and never again"))
}

// parseArgs parses flags that may appear before, between or after
// positional arguments, and returns the positionals.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usageError{err.Error()}
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// exactArgs parses args and requires exactly the named positionals.
func exactArgs(fs *flag.FlagSet, args []string, names ...string) ([]string, error) {
	pos, err := parseArgs(fs, args)
	if err != nil {
		return nil, err
	}
	switch {
	case len(pos) < len(names):
		return nil, usagef("missing %s", strings.Join(names[len(pos):], " "))
	case len(pos) > len(names):
		return nil, usagef("unexpected argument %q", pos[len(names)])
	}
	return pos, nil
}

// config loads the config file and its path.
func (a *app) config() (Config, string, error) {
	path, err := configPath(a.getenv)
	if err != nil {
		return Config{}, "", err
	}
	c, err := loadConfig(path)
	return c, path, err
}

// admin returns an admin API client from the config.
func (a *app) admin() (*adminclient.Client, Config, error) {
	c, _, err := a.config()
	if err != nil {
		return nil, Config{}, err
	}
	switch {
	case c.RelayURL == "":
		return nil, c, errors.New("relay_url is not set. Run: keyhole config set relay_url http://relay.example.invalid:7802")
	case c.AdminToken == "":
		return nil, c, errors.New("admin_token is not set. Run: keyhole config set admin_token (it prompts; keyhole-relay init printed the token once)")
	}
	return adminclient.New(c.RelayURL, c.AdminToken, c.actor(a.getenv), a.hc), c, nil
}

// confirm asks a yes/no question. yes skips it. Without a terminal it
// refuses rather than guess.
func (a *app) confirm(yes bool, question string) error {
	if yes {
		return nil
	}
	if !a.interactive {
		return errors.New("refusing without confirmation: stdin is not a terminal. Re-run with --yes if you mean it")
	}
	fmt.Fprintf(a.errw, "%s [y/N] ", question)
	line, err := readLine(a.in)
	if err != nil && line == "" {
		fmt.Fprintln(a.errw)
		return errAborted
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return errAborted
}

// hint suggests a fix for common failures.
func (a *app) hint(err error) string {
	var ae *adminclient.Error
	var na *ninja.NotAllowedError
	var ue *url.Error
	switch {
	case errors.As(err, &ae) && (ae.Status == http.StatusUnauthorized || ae.Code == proto.ErrUnauthorized):
		return "The relay rejected the admin token. Check it with: keyhole config show. Set it with: keyhole config set admin_token"
	case errors.As(err, &na):
		return fmt.Sprintf("Keyhole writes only to NinjaOne organizations you have allowed deliberately. To allow this one:\n"+
			"  keyhole ninja orgs                                   # confirm %d is the org you mean\n"+
			"  keyhole config set ninja.allowed_org_ids %s", na.OrgID, allowedWith(na.Allowed, na.OrgID))
	case errors.As(err, &ue):
		var ne net.Error
		var oe *net.OpError
		if errors.As(err, &oe) || (errors.As(err, &ne) && ne.Timeout()) {
			return "Cannot reach " + ue.URL + ". Is Tailscale up (tailscale status), and is the relay running?"
		}
	}
	return ""
}

func allowedWith(ids []int, id int) string {
	s := make([]string, 0, len(ids)+1)
	for _, x := range ids {
		s = append(s, fmt.Sprint(x))
	}
	return strings.Join(append(s, fmt.Sprint(id)), ",")
}

// readLine reads one line from r a byte at a time, so it never consumes
// input past the newline.
func readLine(r io.Reader) (string, error) {
	var b []byte
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				break
			}
			b = append(b, buf[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(b) > 0 {
				break
			}
			return string(b), err
		}
	}
	return strings.TrimRight(string(b), "\r"), nil
}

// runEditor opens path in $VISUAL, $EDITOR or vi, attached to the terminal.
func runEditor(ctx context.Context, path string, getenv func(string) string) error {
	ed := getenv("VISUAL")
	if ed == "" {
		ed = getenv("EDITOR")
	}
	if ed == "" {
		ed = "vi"
	}
	parts := strings.Fields(ed)
	cmd := exec.CommandContext(ctx, parts[0], append(parts[1:], path)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor %q: %w", ed, err)
	}
	return nil
}
