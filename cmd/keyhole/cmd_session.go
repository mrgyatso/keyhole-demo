package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/model"
)

// maxSessionTTL caps how long an MCP bearer lives. Sessions are per task;
// mint a new one rather than keep one around.
const maxSessionTTL = 7 * 24 * time.Hour

func cmdSessionMint(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	tech := fs.String("tech", "", "who the session is for (default: your actor)")
	ttl := fs.Duration("ttl", 12*time.Hour, "lifetime, e.g. 2h or 12h (at most 168h)")
	note := fs.String("note", "", "why, e.g. a ticket number")
	asJSON := fs.Bool("json", false, "print JSON, bearer included")
	pos, err := exactArgs(fs, args, "<slug>")
	if err != nil {
		return err
	}
	slug, err := slugArg(pos[0])
	if err != nil {
		return err
	}
	if *ttl < time.Minute || *ttl > maxSessionTTL {
		return usagef("--ttl must be between 1m and %s", maxSessionTTL)
	}
	ac, cfg, err := a.admin()
	if err != nil {
		return err
	}
	if *tech == "" {
		*tech = cfg.actor(a.getenv)
	}
	minutes := int((*ttl + time.Minute - 1) / time.Minute)
	resp, err := ac.MintSession(ctx, slug, adminapi.MintSessionRequest{Tech: *tech, TTLMinutes: minutes, Note: *note})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.out, resp)
	}
	s := resp.Session
	add := resp.ClaudeAddCommand
	if add == "" {
		add = fmt.Sprintf("claude mcp add --transport http keyhole-%s %s --header %s",
			slug, resp.MCPURL, strconv.Quote("Authorization: Bearer "+resp.Bearer))
	}
	fmt.Fprintf(a.out, "MCP session %s for %s, tech %s: expires %s (%s).\n", s.ID, a.st.bold(slug), s.Tech,
		stamp(s.ExpiresAt), until(a.now(), s.ExpiresAt))
	fmt.Fprintf(a.out, "The bearer is shown once and cannot be recovered.\n\n")
	fmt.Fprintf(a.out, "%s\n\n  %s\n\n", a.st.bold("Add Keyhole to Claude Code:"), add)
	fmt.Fprintln(a.out, "Then run /mcp in Claude Code to check the connection.")
	fmt.Fprintln(a.out, a.st.dim("Claude Code keeps the bearer in its MCP config. When the work is done, revoke it and remove the server:"))
	fmt.Fprintf(a.out, "  keyhole session revoke %s\n  claude mcp remove keyhole-%s\n", s.ID, slug)
	return nil
}

func cmdSessionList(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
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
	list, err := ac.ListSessions(ctx, slug)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.out, nonNilSlice(list))
	}
	if len(list) == 0 {
		fmt.Fprintf(a.out, "No MCP sessions for %s. Mint one with: keyhole session mint %s --tech <name>\n", slug, slug)
		return nil
	}
	now := a.now()
	t := newTable(a.out, "id", "tech", "status", "expires", "note", "created")
	for _, s := range list {
		t.row(s.ID, s.Tech, sessionStatus(s, now), stamp(s.ExpiresAt)+" ("+until(now, s.ExpiresAt)+")", s.Note, stamp(s.CreatedAt))
	}
	t.flush()
	return nil
}

func sessionStatus(s model.Session, now time.Time) string {
	switch err := s.Valid(now); {
	case err == nil:
		return "active"
	case errors.Is(err, model.ErrRevoked):
		return "revoked"
	case errors.Is(err, model.ErrExpired):
		return "expired"
	default:
		return err.Error()
	}
}

func cmdSessionRevoke(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	fs.BoolVar(yes, "y", false, "short for --yes")
	pos, err := exactArgs(fs, args, "<id>")
	if err != nil {
		return err
	}
	id, err := idArg(pos[0], model.PrefixSession, "session", "keyhole session list <slug>")
	if err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	if err := a.confirm(*yes, fmt.Sprintf("Revoke MCP session %s? The next Claude call that uses it is refused.", id)); err != nil {
		return err
	}
	if err := ac.RevokeSession(ctx, id); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Revoked %s. Its bearer is refused from the next call on.\n", id)
	return nil
}
