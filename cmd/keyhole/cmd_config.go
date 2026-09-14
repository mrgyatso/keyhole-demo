package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/mrgyatso/keyhole/internal/version"
)

func cmdConfigSet(a *app, _ context.Context, fs *flag.FlagSet, args []string) error {
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 || len(pos) > 2 {
		return usagef("want a key and a value")
	}
	key := pos[0]
	cfg, path, err := a.config()
	if err != nil {
		return err
	}

	var value string
	switch {
	case len(pos) == 2 && pos[1] != "-":
		value = pos[1]
		if key == "admin_token" {
			fmt.Fprintln(a.errw, a.st.yellow("note:")+" the admin token is now in your shell history. Next time run `keyhole config set admin_token` with no value; it prompts without echo.")
		}
	case key == "admin_token" || (len(pos) == 2 && pos[1] == "-"):
		if value, err = a.readSecretInput(key); err != nil {
			return fmt.Errorf("reading %s: %w", key, err)
		}
	default:
		return usagef("missing value for %s", key)
	}

	warning, err := cfg.set(key, value)
	if err != nil {
		return err
	}
	if err := saveConfig(path, cfg); err != nil {
		return err
	}
	shown := value
	if key == "admin_token" {
		shown = maskSecret(value)
	}
	if key == "ninja.allowed_org_ids" {
		shown = orgList(cfg.Ninja.AllowedOrgIDs)
	}
	fmt.Fprintf(a.out, "%s = %s  %s\n", key, shown, a.st.dim("("+path+")"))
	if warning != "" {
		fmt.Fprintln(a.errw, a.st.yellow("warning:")+" "+warning)
	}
	return nil
}

// readSecretInput prompts for a secret without echo on a terminal, or
// reads one line from piped stdin.
func (a *app) readSecretInput(label string) (string, error) {
	if !a.interactive {
		s, err := readLine(a.in)
		return strings.TrimSpace(s), err
	}
	fmt.Fprintf(a.errw, "%s (input hidden): ", label)
	s, err := a.readSecret()
	fmt.Fprintln(a.errw)
	return strings.TrimSpace(s), err
}

func cmdConfigShow(a *app, _ context.Context, fs *flag.FlagSet, args []string) error {
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := exactArgs(fs, args); err != nil {
		return err
	}
	cfg, path, err := a.config()
	if err != nil {
		return err
	}
	envPath := ninjaEnvPath(path)
	envState := describeEnvFile(envPath)
	actor := cfg.actor(a.getenv)
	if *asJSON {
		return writeJSON(a.out, struct {
			Path          string `json:"path"`
			RelayURL      string `json:"relay_url"`
			AdminToken    string `json:"admin_token"`
			Actor         string `json:"actor"`
			PublicURL     string `json:"public_url"`
			AllowedOrgIDs []int  `json:"allowed_org_ids"`
			NinjaEnv      string `json:"ninja_env"`
			NinjaEnvState string `json:"ninja_env_state"`
		}{path, cfg.RelayURL, maskSecret(cfg.AdminToken), actor, cfg.publicURL(), nonNil(cfg.Ninja.AllowedOrgIDs), envPath, envState})
	}
	if cfg.Actor == "" {
		actor += a.st.dim(" (from $USER)")
	}
	public := cfg.publicURL()
	if cfg.PublicURL == "" {
		public += a.st.dim(" (default)")
	}
	relay := cfg.RelayURL
	if relay == "" {
		relay = "(not set)"
	}
	allowed := orgList(cfg.Ninja.AllowedOrgIDs)
	if len(cfg.Ninja.AllowedOrgIDs) == 0 {
		allowed += a.st.dim(" (ninja push refuses every organization)")
	}
	kv(a.out,
		[2]string{"config", path},
		[2]string{"relay_url", relay},
		[2]string{"admin_token", maskSecret(cfg.AdminToken)},
		[2]string{"actor", actor},
		[2]string{"public_url", public},
		[2]string{"ninja.allowed_org_ids", allowed},
		[2]string{"ninja.env", envPath + " " + a.st.dim("("+envState+")")},
	)
	return nil
}

// describeEnvFile reports whether the NinjaOne credentials file exists and
// is private, without reading it.
func describeEnvFile(path string) string {
	fi, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "missing"
	case err != nil:
		return err.Error()
	case runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0:
		return fmt.Sprintf("mode %04o, too open: chmod 600 %s", fi.Mode().Perm(), path)
	}
	return fmt.Sprintf("present, mode %04o", fi.Mode().Perm())
}

func orgList(ids []int) string {
	if len(ids) == 0 {
		return "none"
	}
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = strconv.Itoa(id)
	}
	return strings.Join(s, ",")
}

func nonNil(ids []int) []int {
	if ids == nil {
		return []int{}
	}
	return ids
}

func cmdVersion(a *app, _ context.Context, fs *flag.FlagSet, args []string) error {
	if _, err := exactArgs(fs, args); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "keyhole %s\n", version.Version)
	return nil
}
