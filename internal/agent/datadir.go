package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Files in the data dir.
const (
	AgentFile     = "agent.json"   // Enrollment, no secrets
	CredsFile     = "device.creds" // NATS user JWT and NKey seed
	LogFile       = "agent.log"    // service log where the OS does not collect stderr (Windows)
	GrantsFile    = "grants.json"  // access IDs this service is holding; no capability material
	machineIDFile = "machine-id"   // generated when the OS has no machine ID
	// ChangeSubdir holds structured remediation state (staged plans, rollback
	// copies and the write-ahead journal). It is a directory, not a file, and
	// inherits the data dir's owner-only ACL.
	ChangeSubdir = "change"
)

// ErrNotEnrolled means the data dir holds no enrollment.
var ErrNotEnrolled = errors.New("agent is not enrolled")

// Enrollment is agent.json, the outcome of enrolling. It holds no secret:
// the device credential lives in device.creds.
type Enrollment struct {
	RelayURL   string    `json:"relay_url"`
	DeviceID   string    `json:"device_id"`
	Client     string    `json:"client"`
	PublicKey  string    `json:"public_key"` // NATS user NKey public key ("U…")
	NATSURLs   []string  `json:"nats_urls"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// DataDir is the agent's private state directory. Everything in it is
// readable only by SYSTEM and Administrators (Windows) or root (0700).
type DataDir string

// File returns the path of name inside the data dir.
func (d DataDir) File(name string) string { return filepath.Join(string(d), name) }

// CredsPath is the NATS credentials file.
func (d DataDir) CredsPath() string { return d.File(CredsFile) }

// Ensure creates the data dir if needed and restricts it to its owner.
func (d DataDir) Ensure() error {
	if err := mkdirPrivate(string(d)); err != nil {
		return fmt.Errorf("agent: create data dir %s: %w", d, err)
	}
	return nil
}

// Load reads agent.json. It returns an error wrapping ErrNotEnrolled if
// agent.json or the credentials file is missing.
func (d DataDir) Load() (*Enrollment, error) {
	b, err := os.ReadFile(d.File(AgentFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("agent: %s: %w", d, ErrNotEnrolled)
	}
	if err != nil {
		return nil, fmt.Errorf("agent: read %s: %w", AgentFile, err)
	}
	var e Enrollment
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("agent: parse %s: %w", d.File(AgentFile), err)
	}
	if e.DeviceID == "" || len(e.NATSURLs) == 0 {
		return nil, fmt.Errorf("agent: %s has no device ID or NATS URLs: %w", d.File(AgentFile), ErrNotEnrolled)
	}
	if _, err := os.Stat(d.CredsPath()); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("agent: %s is missing: %w", d.CredsPath(), ErrNotEnrolled)
	}
	return &e, nil
}

func (d DataDir) save(e *Enrollment) error {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivate(d.File(AgentFile), append(b, '\n')); err != nil {
		return fmt.Errorf("agent: write %s: %w", AgentFile, err)
	}
	return nil
}

// Remove deletes the data dir and everything in it.
func (d DataDir) Remove() error {
	if err := os.RemoveAll(string(d)); err != nil {
		return fmt.Errorf("agent: remove data dir: %w", err)
	}
	return nil
}

// fallbackMachineID returns a random ID kept in the data dir, for machines
// whose OS has none (some containers). It survives re-enrollment, so the
// relay can still recognise the machine, but not a purge.
func (d DataDir) fallbackMachineID() (string, error) {
	p := d.File(machineIDFile)
	if b, err := os.ReadFile(p); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	id := "kh-" + hex.EncodeToString(raw)
	if err := writePrivate(p, []byte(id+"\n")); err != nil {
		return "", fmt.Errorf("agent: write %s: %w", machineIDFile, err)
	}
	return id, nil
}

// writePrivate replaces path atomically with data, readable only by its
// owner (and, on Windows, SYSTEM and Administrators).
func writePrivate(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*") // mode 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err = protectFile(f); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
