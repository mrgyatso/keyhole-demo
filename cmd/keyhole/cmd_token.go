package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/model"
)

// maxTokenTTLDays caps enrollment token lifetime.
const maxTokenTTLDays = 365

func cmdTokenMint(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	ttl := fs.Int("ttl-days", 90, "days until the token expires; 1 by default with --ephemeral")
	maxUses := fs.Int("max-uses", 0, "enrollments allowed; 0 means unlimited")
	note := fs.String("note", "", "what the token is for, shown in token list and to the endpoint user")
	ephemeral := fs.Bool("ephemeral", false, "mint a one-use token for a temporary, self-removing install")
	deviceTTL := fs.Duration("device-ttl", 0, "how long the temporary install may live; default 1h, with --ephemeral")
	tech := fs.String("tech", "", "technician shown to the endpoint user before a temporary install")
	asJSON := fs.Bool("json", false, "print JSON, secret included")
	pos, err := exactArgs(fs, args, "<slug>")
	if err != nil {
		return err
	}
	slug, err := slugArg(pos[0])
	if err != nil {
		return err
	}
	// An unset --ttl-days means "the usual", which is a day for a temporary
	// install: the token is used now or not at all. An explicit 0 is still an
	// error, not a request for the default.
	ttlSet := false
	fs.Visit(func(f *flag.Flag) { ttlSet = ttlSet || f.Name == "ttl-days" })
	if *ephemeral && !ttlSet {
		*ttl = 1
	}
	if *ttl < 1 || *ttl > maxTokenTTLDays {
		return usagef("--ttl-days must be between 1 and %d", maxTokenTTLDays)
	}
	if *maxUses < 0 {
		return usagef("--max-uses must not be negative")
	}
	switch {
	case !*ephemeral && *deviceTTL != 0:
		return usagef("--device-ttl applies only with --ephemeral")
	case !*ephemeral && *tech != "":
		return usagef("--tech applies only with --ephemeral")
	case *ephemeral && *maxUses > 1:
		return usagef("--ephemeral enrolls exactly one device; --max-uses cannot be above 1")
	case *ephemeral && *deviceTTL != 0 && (*deviceTTL < time.Minute || *deviceTTL > model.MaxDeviceTTL):
		return usagef("--device-ttl must be between 1m and %s", model.MaxDeviceTTL)
	}
	ac, cfg, err := a.admin()
	if err != nil {
		return err
	}
	uses := *maxUses
	if *ephemeral && uses == 0 {
		// Say it outright rather than rely on the relay's default: a relay
		// that predates temporary installs ignores the ephemeral fields and
		// would otherwise mint an unlimited token.
		uses = 1
	}
	resp, err := ac.MintToken(ctx, slug, adminapi.MintTokenRequest{
		TTLDays: *ttl, MaxUses: uses, Note: *note,
		Ephemeral: *ephemeral, DeviceTTLMinutes: int(*deviceTTL / time.Minute), Technician: *tech,
	})
	if err != nil {
		return err
	}
	if *ephemeral && !resp.Token.Ephemeral {
		// The relay minted an ordinary enrollment token. Its secret is never
		// shown, and the token is revoked so nothing usable is left behind.
		if rerr := ac.RevokeToken(ctx, resp.Token.ID); rerr != nil {
			return fmt.Errorf("the relay does not support temporary installs and minted an ordinary token "+
				"instead; revoke it: keyhole token revoke %s (%v)", resp.Token.ID, rerr)
		}
		return fmt.Errorf("the relay does not support temporary installs; it minted an ordinary token "+
			"instead, which has been revoked (%s). Upgrade the relay first", resp.Token.ID)
	}
	if *asJSON {
		return writeJSON(a.out, resp)
	}
	a.printMintedToken(a.out, cfg.publicURL(), resp)
	return nil
}

func (a *app) printMintedToken(w io.Writer, publicURL string, resp adminapi.MintTokenResponse) {
	t := resp.Token
	uses := "reusable, no limit on enrollments"
	if t.MaxUses > 0 {
		uses = fmt.Sprintf("good for %d enrollment(s)", t.MaxUses)
	}
	kind := "Enrollment token"
	if t.Ephemeral {
		kind = "Temporary-install token"
	}
	fmt.Fprintf(w, "%s %s for %s: %s, expires %s (%s).\n", kind, t.ID, a.st.bold(t.Client), uses,
		stamp(t.ExpiresAt), until(a.now(), t.ExpiresAt))
	if t.Ephemeral {
		fmt.Fprintf(w, "The installed session lasts at most %s, then removes itself and revokes its credential.\n", t.DeviceTTL)
		if t.Technician != "" {
			fmt.Fprintf(w, "The endpoint user is shown technician %s", t.Technician)
			if t.Note != "" {
				fmt.Fprintf(w, " and reason %q", t.Note)
			}
			fmt.Fprintln(w, " before anything is installed.")
		}
	}
	fmt.Fprintf(w, "The secret is shown once and cannot be recovered. Copy it now:\n\n  %s\n\n", resp.Secret)
	commands := installCommands(publicURL, resp.Secret)
	if t.Ephemeral {
		commands = temporaryCommands(publicURL, resp.Secret)
	}
	for _, c := range commands {
		fmt.Fprintf(w, "%s\n  %s\n\n", a.st.bold(c.label), c.cmd)
	}
	fmt.Fprintln(w, a.st.dim("These pass the token only through the installer's environment, but the command itself lands in that"))
	if t.Ephemeral {
		fmt.Fprintln(w, a.st.dim("machine's shell history. The customer must consent at that machine's console before anything installs."))
	} else {
		fmt.Fprintln(w, a.st.dim("machine's shell history. For hand installs prefer --ttl-days 1 --max-uses 1."))
	}
	fmt.Fprintf(w, "Revoke it with: keyhole token revoke %s\n", t.ID)
}

type installCommand struct{ label, cmd string }

// installCommands are copy-paste installs that download the agent from the
// relay's public /dl/ and enroll it, passing the token in
// KEYHOLE_ENROLL_TOKEN so it never appears in the agent's arguments.
func installCommands(publicURL, secret string) []installCommand {
	win := fmt.Sprintf("[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; "+
		"$f = Join-Path $env:TEMP 'keyhole-agent.exe'; "+
		"Invoke-WebRequest -UseBasicParsing -Uri %s -OutFile $f; "+
		"$env:KEYHOLE_ENROLL_TOKEN = %s; & $f install --url %s; Remove-Item Env:\\KEYHOLE_ENROLL_TOKEN",
		psQuote(publicURL+"/dl/keyhole-agent-windows-amd64.exe"), psQuote(secret), psQuote(publicURL))
	unix := func(goos string) string {
		return fmt.Sprintf("a=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/'); "+
			"curl -fsSL -o /tmp/keyhole-agent %s\"$a\" && chmod 755 /tmp/keyhole-agent && "+
			"sudo env KEYHOLE_ENROLL_TOKEN=%s /tmp/keyhole-agent install --url %s",
			shQuote(publicURL+"/dl/keyhole-agent-"+goos+"-"), shQuote(secret), shQuote(publicURL))
	}
	return []installCommand{
		{"Windows (elevated PowerShell):", win},
		{"Linux (as a sudoer):", unix("linux")},
		{"macOS (as an admin):", unix("darwin")},
	}
}

// temporaryCommands are the copy-paste one-off installs for an ephemeral
// token. They download the helper and run it; the helper shows the customer
// what is being asked for and installs nothing until they consent.
func temporaryCommands(publicURL, secret string) []installCommand {
	win := fmt.Sprintf("[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; "+
		"$f = Join-Path $env:TEMP 'keyhole-agent.exe'; "+
		"Invoke-WebRequest -UseBasicParsing -Uri %s -OutFile $f; "+
		"$env:KEYHOLE_ENROLL_TOKEN = %s; & $f temporary --url %s; Remove-Item Env:\\KEYHOLE_ENROLL_TOKEN; "+
		"Remove-Item -Force $f",
		psQuote(publicURL+"/dl/keyhole-agent-windows-amd64.exe"), psQuote(secret), psQuote(publicURL))
	// The helper is removed however it exits: the session removes what it
	// installed, and the download must not be the one thing left behind.
	unix := func(goos string) string {
		return fmt.Sprintf("a=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/'); "+
			"curl -fsSL -o /tmp/keyhole-agent %s\"$a\" && chmod 755 /tmp/keyhole-agent && "+
			"sudo env KEYHOLE_ENROLL_TOKEN=%s /tmp/keyhole-agent temporary --url %s; rm -f /tmp/keyhole-agent",
			shQuote(publicURL+"/dl/keyhole-agent-"+goos+"-"), shQuote(secret), shQuote(publicURL))
	}
	return []installCommand{
		{"Windows (elevated PowerShell, at the customer's machine):", win},
		{"Linux (as a sudoer; runs in the foreground):", unix("linux")},
		{"macOS (as an admin; runs in the foreground):", unix("darwin")},
	}
}

// psQuote single-quotes s for PowerShell.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// shQuote single-quotes s for a POSIX shell.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func cmdTokenList(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := exactArgs(fs, args, "<slug>")
	if err != nil {
		return err
	}
	slug, err := slugArg(pos[0])
	if err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	toks, err := ac.ListTokens(ctx, slug)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.out, nonNilSlice(toks))
	}
	if len(toks) == 0 {
		fmt.Fprintf(a.out, "No enrollment tokens for %s. Mint one with: keyhole token mint %s\n", slug, slug)
		return nil
	}
	now := a.now()
	t := newTable(a.out, "id", "kind", "status", "uses", "expires", "note", "created")
	for _, tok := range toks {
		uses := fmt.Sprintf("%d (no limit)", tok.Uses)
		if tok.MaxUses > 0 {
			uses = fmt.Sprintf("%d of %d", tok.Uses, tok.MaxUses)
		}
		kind := "managed"
		if tok.Ephemeral {
			kind = "temporary " + tok.DeviceTTL.String()
		}
		t.row(tok.ID, kind, tokenStatus(tok, now), uses, stamp(tok.ExpiresAt)+" ("+until(now, tok.ExpiresAt)+")", tok.Note, stamp(tok.CreatedAt))
	}
	t.flush()
	return nil
}

func tokenStatus(t model.EnrollToken, now time.Time) string {
	switch err := t.Usable(now); {
	case err == nil:
		return "active"
	case errors.Is(err, model.ErrRevoked):
		return "revoked"
	case errors.Is(err, model.ErrExpired):
		return "expired"
	case errors.Is(err, model.ErrExhausted):
		return "used up"
	default:
		return err.Error()
	}
}

func cmdTokenRevoke(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	fs.BoolVar(yes, "y", false, "short for --yes")
	pos, err := exactArgs(fs, args, "<id>")
	if err != nil {
		return err
	}
	id, err := idArg(pos[0], model.PrefixToken, "token", "keyhole token list <slug>")
	if err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	if err := a.confirm(*yes, fmt.Sprintf("Revoke enrollment token %s? Installs that use it will fail; devices it already enrolled keep working.", id)); err != nil {
		return err
	}
	if err := ac.RevokeToken(ctx, id); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Revoked %s. New enrollments with it now fail with invalid_token; devices it enrolled are unaffected.\n", id)
	fmt.Fprintln(a.out, a.st.dim("If it was pushed to a NinjaOne org, push a fresh one: keyhole ninja push <slug> --org <id>"))
	return nil
}

// idArg checks an object ID argument. A pasted secret is refused before
// anything is sent, so it never reaches a URL or a server log.
func idArg(s, prefix, noun, listCmd string) (string, error) {
	for _, sp := range []string{model.SecretEnroll, model.SecretSession, model.SecretAdmin} {
		if strings.HasPrefix(s, sp+"_") {
			return "", usagef("that is a secret, not a %s ID; nothing was sent. IDs look like %s_…; list them with: %s", noun, prefix, listCmd)
		}
	}
	if !strings.HasPrefix(s, prefix+"_") {
		return "", usagef("%q is not a %s ID (%s_…); list them with: %s", s, noun, prefix, listCmd)
	}
	return s, nil
}
