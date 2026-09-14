package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/mrgyatso/keyhole/internal/model"
)

// Config is the CLI's settings file. It holds the admin token, so it is
// written 0600 and refused if anyone else can read it.
type Config struct {
	RelayURL   string      `json:"relay_url,omitempty"`
	AdminToken string      `json:"admin_token,omitempty"`
	Actor      string      `json:"actor,omitempty"`
	PublicURL  string      `json:"public_url,omitempty"`
	Ninja      NinjaConfig `json:"ninja"`
}

// NinjaConfig holds the NinjaOne write rail.
type NinjaConfig struct {
	// AllowedOrgIDs are the only NinjaOne organizations `ninja push` writes to.
	AllowedOrgIDs []int `json:"allowed_org_ids"`
}

// defaultPublicURL is where agents enroll and download from.
const defaultPublicURL = "https://keyhole.example.invalid"

// configKeys are the keys `config set` accepts, in display order.
var configKeys = []string{"relay_url", "admin_token", "actor", "public_url", "ninja.allowed_org_ids"}

// configPath is $KEYHOLE_CONFIG, or ~/.config/keyhole/config.json.
func configPath(getenv func(string) string) (string, error) {
	if p := getenv("KEYHOLE_CONFIG"); p != "" {
		return p, nil
	}
	home := getenv("HOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot find the config file: %w (set KEYHOLE_CONFIG)", err)
		}
		home = h
	}
	return filepath.Join(home, ".config", "keyhole", "config.json"), nil
}

// ninjaEnvPath is the NinjaOne credentials file, next to the config file.
func ninjaEnvPath(cfgPath string) string { return filepath.Join(filepath.Dir(cfgPath), "ninja.env") }

// loadConfig reads the config file. A missing file is an empty config.
func loadConfig(path string) (Config, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return Config{}, fmt.Errorf("%s is readable by others (mode %04o) and holds the admin token. Run: chmod 600 %s",
			path, fi.Mode().Perm(), path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// saveConfig writes the config atomically with mode 0600, creating its
// directory with mode 0700.
func saveConfig(path string, c Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// actor is who admin changes are attributed to: the configured actor, else $USER.
func (c Config) actor(getenv func(string) string) string {
	if c.Actor != "" {
		return c.Actor
	}
	if u := getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

func (c Config) publicURL() string {
	if c.PublicURL != "" {
		return c.PublicURL
	}
	return defaultPublicURL
}

// set validates value and stores it under key. It returns a warning for
// values that are accepted but look wrong.
func (c *Config) set(key, value string) (warning string, err error) {
	value = strings.TrimSpace(value)
	switch key {
	case "relay_url":
		u, err := parseHTTPURL(value)
		if err != nil {
			return "", err
		}
		c.RelayURL = u
	case "public_url":
		u, err := parseHTTPURL(value)
		if err != nil {
			return "", err
		}
		c.PublicURL = u
	case "admin_token":
		if value == "" || strings.ContainsAny(value, " \t\r\n") {
			return "", errors.New("admin_token must be a single word")
		}
		c.AdminToken = value
		if !strings.HasPrefix(value, model.SecretAdmin+"_") {
			return fmt.Sprintf("admin tokens normally start with %q; check you pasted the right secret", model.SecretAdmin+"_"), nil
		}
	case "actor":
		if value == "" {
			return "", errors.New("actor must not be empty")
		}
		c.Actor = value
	case "ninja.allowed_org_ids":
		ids, err := parseOrgIDs(value)
		if err != nil {
			return "", err
		}
		c.Ninja.AllowedOrgIDs = ids
	default:
		return "", fmt.Errorf("unknown key %q (keys: %s)", key, strings.Join(configKeys, ", "))
	}
	return "", nil
}

func parseHTTPURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("%q is not an http(s) URL", raw)
	}
	if u.RawQuery != "" || u.User != nil {
		return "", fmt.Errorf("%q must not carry a query or credentials", raw)
	}
	return strings.TrimRight(raw, "/"), nil
}

// parseOrgIDs reads a comma- or space-separated list of NinjaOne
// organization IDs. "" and "none" clear the list.
func parseOrgIDs(s string) ([]int, error) {
	if s == "" || s == "none" {
		return []int{}, nil
	}
	var ids []int
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		id, err := strconv.Atoi(f)
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("%q is not a NinjaOne organization ID", f)
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// maskSecret shows a secret's prefix and last four characters only.
func maskSecret(s string) string {
	if s == "" {
		return "(not set)"
	}
	if len(s) < 16 {
		return "****"
	}
	prefix := ""
	if i := strings.IndexByte(s, '_'); i > 0 && i <= 4 {
		prefix = s[:i+1]
	}
	return prefix + "…" + s[len(s)-4:]
}
