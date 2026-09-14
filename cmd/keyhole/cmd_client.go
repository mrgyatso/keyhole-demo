package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strconv"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/model"
)

// slugArg validates a client slug argument.
func slugArg(s string) (string, error) {
	if !model.ValidSlug(s) {
		return "", usagef("%q is not a client slug: use 2-32 of a-z, 0-9 and -, not starting with -", s)
	}
	return s, nil
}

func cmdClientAdd(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	name := fs.String("name", "", "display name (required)")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := exactArgs(fs, args, "<slug>")
	if err != nil {
		return err
	}
	slug, err := slugArg(pos[0])
	if err != nil {
		return err
	}
	if *name == "" {
		return usagef("--name is required")
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	ci, err := ac.CreateClient(ctx, adminapi.CreateClientRequest{Slug: slug, Name: *name})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.out, ci)
	}
	fmt.Fprintf(a.out, "Created client %s (%s) with the default policy.\n\n", a.st.bold(ci.Slug), ci.Name)
	a.next(
		"keyhole policy show "+slug, "review what Claude may read",
		"keyhole ninja push "+slug+" --org <ninja org id>", "enroll devices through NinjaOne",
		"keyhole token mint "+slug, "or enroll a machine by hand",
		"keyhole session mint "+slug+" --tech <you>", "give Claude Code access",
	)
	return nil
}

func cmdClientList(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := exactArgs(fs, args); err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	list, err := ac.ListClients(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.out, nonNilSlice(list))
	}
	if len(list) == 0 {
		fmt.Fprintln(a.out, "No clients yet. Add one with: keyhole client add <slug> --name NAME")
		return nil
	}
	renderClients(a.out, list)
	return nil
}

func renderClients(w io.Writer, list []adminapi.ClientInfo) {
	t := newTable(w, "slug", "name", "status", "devices", "online", "created")
	for _, c := range list {
		t.row(c.Slug, c.Name, clientStatus(c), strconv.Itoa(c.Devices), strconv.Itoa(c.Online), stamp(c.CreatedAt))
	}
	t.flush()
}

func clientStatus(c adminapi.ClientInfo) string {
	if c.Disabled {
		return "DISABLED"
	}
	return "enabled"
}

func cmdClientShow(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
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
	c, err := ac.GetClient(ctx, slug)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.out, c)
	}
	status := a.st.green("enabled")
	if c.Disabled {
		status = a.st.red("DISABLED") + " (kill switch on: every Claude call is refused)"
	}
	kv(a.out,
		[2]string{"slug", c.Slug},
		[2]string{"name", c.Name},
		[2]string{"status", status},
		[2]string{"devices", fmt.Sprintf("%d enrolled, %d online", c.Devices, c.Online)},
		[2]string{"nats account", c.AccountKey},
		[2]string{"created", stamp(c.CreatedAt)},
	)
	return nil
}

func cmdClientDisable(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	reason := fs.String("reason", "", "why, recorded in the audit log")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	fs.BoolVar(yes, "y", false, "short for --yes")
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
	q := fmt.Sprintf("Disable client %s? Every Claude call for it is refused until `keyhole client enable %s`.", slug, slug)
	if err := a.confirm(*yes, q); err != nil {
		return err
	}
	c, err := ac.DisableClient(ctx, slug, *reason)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.out, c)
	}
	fmt.Fprintf(a.out, "Client %s is %s: every Claude call for it is now refused.\n", slug, a.st.red("DISABLED"))
	fmt.Fprintf(a.out, "Devices stay enrolled and sessions stay valid, but nothing gets through. Undo with: keyhole client enable %s\n", slug)
	return nil
}

func cmdClientEnable(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
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
	c, err := ac.EnableClient(ctx, slug)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.out, c)
	}
	fmt.Fprintf(a.out, "Client %s is %s: Claude calls go through again, within its policy.\n", slug, a.st.green("enabled"))
	return nil
}

// next prints "Next:" hints as command/explanation pairs.
func (a *app) next(pairs ...string) {
	fmt.Fprintln(a.out, "Next:")
	tw := newAligned(a.out)
	for i := 0; i+1 < len(pairs); i += 2 {
		fmt.Fprintf(tw, "  %s\t%s\n", pairs[i], a.st.dim(pairs[i+1]))
	}
	_ = tw.Flush()
}

// nonNilSlice makes an empty list encode as [] rather than null.
func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
