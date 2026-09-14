package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"strings"

	"github.com/mrgyatso/keyhole/internal/model"
)

func cmdTechnicianGrant(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	pos, err := exactArgs(fs, args, "<subject> <slug>")
	if err != nil {
		return err
	}
	slug, err := slugArg(pos[1])
	if err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	if err := ac.GrantTechnicianClient(ctx, pos[0], slug); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Granted technician %s access to %s.\n", pos[0], slug)
	return nil
}

func cmdTechnicianClients(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := exactArgs(fs, args, "<subject>")
	if err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	clients, err := ac.TechnicianClients(ctx, pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.out, nonNilSlice(clients))
	}
	t := newTable(a.out, "slug", "name", "status")
	for _, client := range clients {
		status := "enabled"
		if client.Disabled {
			status = "disabled"
		}
		t.row(client.Slug, client.Name, status)
	}
	t.flush()
	return nil
}

func cmdTechnicianRevoke(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	pos, err := exactArgs(fs, args, "<subject> <slug>")
	if err != nil {
		return err
	}
	slug, err := slugArg(pos[1])
	if err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	if err := ac.RevokeTechnicianClient(ctx, pos[0], slug); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Revoked technician %s access to %s.\n", pos[0], slug)
	return nil
}

// cmdTechnicianPasskeyLink mints a one-time link that enrolls a passkey for
// the technician. The link is the secret: whoever opens it first gets a
// passkey that approves as the technician, so it is printed once and never
// again.
func cmdTechnicianPasskeyLink(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	asJSON := fs.Bool("json", false, "print JSON, link included")
	pos, err := exactArgs(fs, args, "<subject>")
	if err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	resp, err := ac.MintPasskeyLink(ctx, pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.out, resp)
	}
	fmt.Fprintf(a.out, "One-time passkey enrollment link for technician %s: expires %s (%s).\n", a.st.bold(resp.Technician),
		stamp(resp.ExpiresAt), until(a.now(), resp.ExpiresAt))
	fmt.Fprintf(a.out, "The link is a one-time secret, shown once: whoever opens it first enrolls a passkey that approves as %s.\n", resp.Technician)
	fmt.Fprintf(a.out, "Open it on the technician's own phone or computer, or send it to them over a private channel.\n\n  %s\n\n", resp.URL)
	fmt.Fprintln(a.out, a.st.dim("Check what was enrolled with: keyhole technician passkeys "+resp.Technician))
	return nil
}

func cmdTechnicianPasskeys(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := exactArgs(fs, args, "<subject>")
	if err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	list, err := ac.Passkeys(ctx, pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.out, nonNilSlice(list))
	}
	if len(list) == 0 {
		fmt.Fprintf(a.out, "No passkeys for %s. Mint an enrollment link with: keyhole technician passkey-link %s\n", pos[0], pos[0])
		return nil
	}
	now := a.now()
	t := newTable(a.out, "credential", "name", "status", "last used", "created")
	for _, p := range list {
		status, last := "active", ""
		if p.RevokedAt != nil {
			status = "revoked " + stamp(*p.RevokedAt)
		}
		if p.LastUsedAt != nil {
			last = ago(now, *p.LastUsedAt)
		}
		t.row(p.CredentialID, p.Name, status, last, stamp(p.CreatedAt))
	}
	t.flush()
	return nil
}

func cmdTechnicianPasskeyRevoke(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	fs.BoolVar(yes, "y", false, "short for --yes")
	pos, err := exactArgs(fs, args, "<credential-id>")
	if err != nil {
		return err
	}
	id, err := credentialArg(pos[0])
	if err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	if err := a.confirm(*yes, fmt.Sprintf("Revoke passkey %s? It can no longer sign in to the companion or approve anything.", id)); err != nil {
		return err
	}
	p, err := ac.RevokePasskey(ctx, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Revoked passkey %s (%s) of technician %s. It approves nothing from now on, and the companion signs out whoever signed in with it.\n",
		id, p.Name, p.Technician)
	return nil
}

// credentialArg checks a passkey credential ID argument: base64url, as
// `keyhole technician passkeys` lists it. A pasted secret or enrollment link
// is refused before anything is sent, and not echoed.
func credentialArg(s string) (string, error) {
	for _, sp := range []string{model.SecretPasskeyLink, model.SecretCompanion, model.SecretEnroll, model.SecretSession, model.SecretAdmin} {
		if strings.HasPrefix(s, sp+"_") || strings.Contains(s, "#"+sp+"_") {
			return "", usagef("that is a secret, not a passkey credential ID; nothing was sent. List credential IDs with: keyhole technician passkeys <subject>")
		}
	}
	if _, err := base64.RawURLEncoding.DecodeString(s); err != nil || s == "" {
		return "", usagef("%q is not a passkey credential ID (base64url); list them with: keyhole technician passkeys <subject>", s)
	}
	return s, nil
}
