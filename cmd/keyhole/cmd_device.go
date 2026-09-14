package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
)

func cmdDeviceList(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
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
	devs, err := ac.ListDevices(ctx, slug)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.out, nonNilSlice(devs))
	}
	if len(devs) == 0 {
		fmt.Fprintf(a.out, "No devices enrolled for %s yet. Enroll through NinjaOne (keyhole ninja push %s --org <id>) or by hand (keyhole token mint %s).\n",
			slug, slug, slug)
		return nil
	}
	renderDevices(a.out, devs, a.now())
	return nil
}

// renderDevices writes the device table: id, hostname, os, online, last
// seen, agent version.
func renderDevices(w io.Writer, devs []model.Device, now time.Time) {
	t := newTable(w, "id", "hostname", "os", "online", "last seen", "agent version")
	for _, d := range devs {
		online := "no"
		switch {
		case d.RevokedAt != nil:
			online = "revoked"
		case d.Online(now):
			online = "yes"
		}
		seen := "never"
		if d.LastSeen != nil {
			seen = ago(now, *d.LastSeen)
		}
		t.row(d.ID, d.Hostname, d.OS, online, seen, d.AgentVersion)
	}
	t.flush()
}

func cmdDeviceRevoke(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	fs.BoolVar(yes, "y", false, "short for --yes")
	pos, err := exactArgs(fs, args, "<id>")
	if err != nil {
		return err
	}
	id, err := idArg(pos[0], model.PrefixDevice, "device", "keyhole device list <slug>")
	if err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	if err := a.confirm(*yes, fmt.Sprintf("Revoke device %s? Its credential stops working and the machine must re-enroll to come back.", id)); err != nil {
		return err
	}
	if err := ac.RevokeDevice(ctx, id); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Revoked %s. NATS refuses its credential from now on, and Claude calls to it fail with device_revoked.\n", id)
	fmt.Fprintln(a.out, a.st.dim("The agent service is still installed on the machine. Remove it with Uninstall-Keyhole.ps1 from NinjaOne, or keyhole-agent uninstall."))
	return nil
}
