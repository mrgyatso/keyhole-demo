package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/ninja"
)

// ninjaClient builds a NinjaOne client from ninja.env (or the environment)
// and the configured write allowlist.
func (a *app) ninjaClient(cfg Config, cfgPath string) (*ninja.Client, error) {
	envPath := ninjaEnvPath(cfgPath)
	creds, err := ninja.LoadCredentials(envPath, a.getenv)
	if err != nil {
		return nil, fmt.Errorf("%w\nSee docs/runbooks/ninjaone-setup.md to create the API client app and %s", err, envPath)
	}
	return ninja.New(creds, cfg.Ninja.AllowedOrgIDs, a.hc)
}

func cmdNinjaOrgs(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := exactArgs(fs, args); err != nil {
		return err
	}
	cfg, path, err := a.config()
	if err != nil {
		return err
	}
	nc, err := a.ninjaClient(cfg, path)
	if err != nil {
		return err
	}
	orgs, err := nc.Organizations(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		type org struct {
			ninja.Organization
			WritesAllowed bool `json:"writes_allowed"`
		}
		out := make([]org, len(orgs))
		for i, o := range orgs {
			out[i] = org{o, nc.Allowed(o.ID)}
		}
		return writeJSON(a.out, out)
	}
	t := newTable(a.out, "id", "name", "keyhole writes")
	for _, o := range orgs {
		w := ""
		if nc.Allowed(o.ID) {
			w = "allowed"
		}
		t.row(strconv.Itoa(o.ID), o.Name, w)
	}
	t.flush()
	fmt.Fprintln(a.out, "\n"+a.st.dim("keyhole ninja push writes only to ninja.allowed_org_ids ("+orgList(cfg.Ninja.AllowedOrgIDs)+
		"). Add one deliberately with: keyhole config set ninja.allowed_org_ids <ids>"))
	return nil
}

func cmdNinjaFields(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	asJSON := fs.Bool("json", false, "print JSON (values masked the same way)")
	pos, err := exactArgs(fs, args, "<org>")
	if err != nil {
		return err
	}
	orgID, err := orgArg(pos[0])
	if err != nil {
		return err
	}
	cfg, path, err := a.config()
	if err != nil {
		return err
	}
	nc, err := a.ninjaClient(cfg, path)
	if err != nil {
		return err
	}
	org, err := nc.Organization(ctx, orgID)
	if err != nil {
		return err
	}
	fields, err := nc.OrganizationCustomFields(ctx, orgID)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		if k != ninja.FieldDeploy && k != ninja.FieldEnrollToken {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	names = append([]string{ninja.FieldDeploy, ninja.FieldEnrollToken}, names...)
	view := make(map[string]string, len(names))
	for _, k := range names {
		view[k] = describeField(k, fields[k])
	}
	if *asJSON {
		return writeJSON(a.out, map[string]any{"org_id": org.ID, "org_name": org.Name, "fields": view})
	}
	fmt.Fprintf(a.out, "NinjaOne organization %d (%s)\n\n", org.ID, org.Name)
	t := newTable(a.out, "field", "value")
	for _, k := range names {
		t.row(k, view[k])
	}
	t.flush()
	fmt.Fprintln(a.out, "\n"+a.st.dim("Text values are shown as their length only, so no secret (Keyhole's or another vendor's) is printed."))
	return nil
}

// describeField renders a custom field value without revealing secrets:
// booleans and numbers as they are, text as its length, and the Keyhole
// token as set or not set.
func describeField(name string, raw json.RawMessage) string {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil || v == nil {
		return "not set"
	}
	switch x := v.(type) {
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case string:
		if x == "" {
			return "not set"
		}
		if name == ninja.FieldEnrollToken {
			return "set (" + maskSecret(x) + ")"
		}
		return fmt.Sprintf("text, %d chars", len(x))
	case []any:
		return fmt.Sprintf("list, %d items", len(x))
	}
	return "object"
}

func orgArg(s string) (int, error) {
	id, err := strconv.Atoi(s)
	if err != nil || id <= 0 {
		return 0, usagef("%q is not a NinjaOne organization ID; keyhole ninja orgs lists them", s)
	}
	return id, nil
}

func cmdNinjaPush(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	orgFlag := fs.String("org", "", "NinjaOne organization ID (required; must be in ninja.allowed_org_ids)")
	ttl := fs.Int("ttl-days", 90, "days until the token expires")
	enable := fs.Bool("enable", false, "also tick keyholeDeploy on the organization, which starts installs")
	asJSON := fs.Bool("json", false, "print JSON (never the secret)")
	pos, err := exactArgs(fs, args, "<slug>")
	if err != nil {
		return err
	}
	slug, err := slugArg(pos[0])
	if err != nil {
		return err
	}
	if *orgFlag == "" {
		return usagef("--org is required: the NinjaOne organization ID (keyhole ninja orgs lists them)")
	}
	orgID, err := orgArg(*orgFlag)
	if err != nil {
		return err
	}
	if *ttl < 1 || *ttl > maxTokenTTLDays {
		return usagef("--ttl-days must be between 1 and %d", maxTokenTTLDays)
	}
	cfg, path, err := a.config()
	if err != nil {
		return err
	}
	// The rail comes first: nothing is minted and nothing is sent for an
	// organization that is not on the allowlist.
	if !slices.Contains(cfg.Ninja.AllowedOrgIDs, orgID) {
		return &ninja.NotAllowedError{OrgID: orgID, Allowed: slices.Clone(cfg.Ninja.AllowedOrgIDs)}
	}
	nc, err := a.ninjaClient(cfg, path)
	if err != nil {
		return err
	}
	org, err := nc.Organization(ctx, orgID)
	if err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	client, err := ac.GetClient(ctx, slug)
	if err != nil {
		return err
	}

	note := "ninja org " + strconv.Itoa(orgID)
	mint, err := ac.MintToken(ctx, slug, adminapi.MintTokenRequest{TTLDays: *ttl, Note: note})
	if err != nil {
		return err
	}
	fields := map[string]any{ninja.FieldEnrollToken: mint.Secret}
	if *enable {
		fields[ninja.FieldDeploy] = true
	}
	if err := nc.UpdateOrganizationCustomFields(ctx, orgID, fields); err != nil {
		// Nobody holds this token, so do not leave it live.
		if rerr := ac.RevokeToken(ctx, mint.Token.ID); rerr != nil {
			return fmt.Errorf("%w\nThe token minted for this push could not be revoked (%v). Revoke it with: keyhole token revoke %s",
				err, rerr, mint.Token.ID)
		}
		return fmt.Errorf("%w\nThe token minted for this push (%s) has been revoked; nothing is left behind", err, mint.Token.ID)
	}

	now := a.now()
	var older []string
	if toks, err := ac.ListTokens(ctx, slug); err == nil {
		for _, t := range toks {
			if t.Note == note && t.ID != mint.Token.ID && t.Usable(now) == nil {
				older = append(older, t.ID)
			}
		}
	}
	if *asJSON {
		return writeJSON(a.out, struct {
			Client        string    `json:"client"`
			OrgID         int       `json:"org_id"`
			OrgName       string    `json:"org_name"`
			TokenID       string    `json:"token_id"`
			ExpiresAt     time.Time `json:"expires_at"`
			DeployEnabled bool      `json:"deploy_enabled"`
			OlderTokens   []string  `json:"older_tokens"`
		}{slug, orgID, org.Name, mint.Token.ID, mint.Token.ExpiresAt, *enable, nonNilSlice(older)})
	}
	a.printPush(slug, client, org, mint.Token, *enable, older)
	return nil
}

func (a *app) printPush(slug string, client adminapi.ClientInfo, org ninja.Organization, tok model.EnrollToken, enabled bool, older []string) {
	fmt.Fprintf(a.out, "Pushed a new enrollment token for %s into NinjaOne organization %d (%s).\n",
		a.st.bold(slug), org.ID, org.Name)
	deploy := "not ticked. Tick \"" + ninja.FieldDeploy + "\" on the organization in NinjaOne to start installing."
	if enabled {
		deploy = a.st.green("ticked") + ": the Keyhole automation runs on this org's devices at their next policy check."
	}
	kv(a.out,
		[2]string{"  token", fmt.Sprintf("%s, expires %s (%s)", tok.ID, stamp(tok.ExpiresAt), until(a.now(), tok.ExpiresAt))},
		[2]string{"  secret", "written only to the secure field " + ninja.FieldEnrollToken + "; not shown here"},
		[2]string{"  " + ninja.FieldDeploy, deploy},
	)
	if client.Disabled {
		fmt.Fprintln(a.out, a.st.yellow("warning:")+" "+slug+" is disabled. Devices will enroll, but every Claude call is refused until: keyhole client enable "+slug)
	}
	if len(older) > 0 {
		fmt.Fprintf(a.out, "Older tokens pushed to this org are still valid: %s.\nRevoke them once devices enroll with the new one: keyhole token revoke <id>\n",
			strings.Join(older, ", "))
	}
	fmt.Fprintf(a.out, "Watch devices arrive with: keyhole device list %s\n", slug)
}
