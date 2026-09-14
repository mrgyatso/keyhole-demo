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
	"time"

	"github.com/mrgyatso/keyhole/internal/version"
)

// Temporary installation (Slice 4). A temporary install is a whole session on
// disk: its own data directory under the temp root, a session file recording
// where in the lifecycle it is, and a terminating marker that survives a
// crash. Nothing here is a credential.

// Files a temporary session keeps in its own data dir, alongside agent.json
// and device.creds.
const (
	TempSessionFile = "session.json" // TempSession; no secrets
	terminatingFile = "terminating"  // present once cleanup has begun
)

// Temporary-session states. They are durable: a session file found in any
// state but TempDone on service start means the session was interrupted and
// must be finished, not resumed.
const (
	TempEnrolled = "enrolled" // credential issued, service not yet running
	TempRunning  = "running"  // serving requests until ExpiresAt
	TempExpiring = "expiring" // deadline reached or termination requested
	TempCleanup  = "cleanup"  // revoking, writing the receipt, removing itself
	TempDone     = "done"     // nothing left to undo
)

// How a session ended, recorded in the receipt.
const (
	EndExpired     = "expired"     // reached ExpiresAt
	EndTerminated  = "terminated"  // stopped by the user or the service manager
	EndInterrupted = "interrupted" // found unfinished on the next start
)

// TempSession is session.json: what the endpoint user consented to, and how
// far through the lifecycle this install is. It holds no credential, so it is
// safe to copy into the receipt.
type TempSession struct {
	ID           string    `json:"id"`
	State        string    `json:"state"`
	RelayURL     string    `json:"relay_url"`
	Client       string    `json:"client"`
	ClientName   string    `json:"client_name,omitempty"`
	Technician   string    `json:"technician,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	Operations   []string  `json:"operations,omitempty"`
	Paths        []string  `json:"paths,omitempty"`
	DeviceID     string    `json:"device_id"`
	Hostname     string    `json:"hostname,omitempty"`
	AgentVersion string    `json:"agent_version"`
	EnrolledAt   time.Time `json:"enrolled_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Receipt is the record left behind after a temporary install removes itself.
// It is the client's own evidence of what the MSP did on their machine, so it
// outlives the data directory — and it must never carry anything that could
// be used to get back in: no token, seed, JWT, credential path or capability.
type Receipt struct {
	Session      string    `json:"session"`
	DeviceID     string    `json:"device_id"`
	Client       string    `json:"client"`
	ClientName   string    `json:"client_name,omitempty"`
	Technician   string    `json:"technician,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	Relay        string    `json:"relay"`
	Hostname     string    `json:"hostname,omitempty"`
	AgentVersion string    `json:"agent_version"`
	Operations   []string  `json:"operations,omitempty"`
	Paths        []string  `json:"paths,omitempty"`
	EnrolledAt   time.Time `json:"enrolled_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	EndedAt      time.Time `json:"ended_at"`
	EndReason    string    `json:"end_reason"`
	Requests     int       `json:"requests_served"`
	Hashes       []string  `json:"response_hashes,omitempty"` // as mirrored locally, newest last
	Revoked      bool      `json:"credential_revoked"`        // the endpoint's own revoke reached the relay
	Note         string    `json:"note"`
}

// receiptNote says what a reader of the receipt should know without having to
// find this documentation.
const receiptNote = "Keyhole temporary session. The service, its credential and its data directory " +
	"were removed when the session ended. The MSP's copy of this activity is in its audit log. " +
	"This receipt contains no credential."

// MaxReceiptHashes bounds how many response hashes a receipt carries.
const MaxReceiptHashes = 256

// TempRoot is where temporary sessions live: a sibling of the managed data
// dir, never the managed data dir itself, so a temporary install can never
// touch a managed one's state.
func TempRoot() string { return filepath.Join(string(DefaultDataDir()), "temp") }

// ReceiptDir is where receipts are kept. It is deliberately outside every
// session directory, because it must survive the session removing itself.
func ReceiptDir() string { return filepath.Join(string(DefaultDataDir()), "receipts") }

// NewTempDataDir creates a private data directory for a new temporary
// session and returns it with the session ID that names it.
func NewTempDataDir() (DataDir, string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	id := "tmp" + hex.EncodeToString(raw)
	d := DataDir(filepath.Join(TempRoot(), id))
	if err := d.Ensure(); err != nil {
		return "", "", err
	}
	return d, id, nil
}

// TempSessions lists the session directories under the temp root, so an
// interrupted session can be found without knowing its ID.
func TempSessions() ([]DataDir, error) {
	entries, err := os.ReadDir(TempRoot())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agent: list temporary sessions: %w", err)
	}
	var out []DataDir
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		d := DataDir(filepath.Join(TempRoot(), e.Name()))
		if _, err := os.Stat(d.File(TempSessionFile)); err == nil {
			out = append(out, d)
		}
	}
	return out, nil
}

// ErrNoTempSession means the data dir holds no temporary session.
var ErrNoTempSession = errors.New("no temporary session")

// LoadTempSession reads session.json, or an error wrapping ErrNoTempSession.
func (d DataDir) LoadTempSession() (*TempSession, error) {
	b, err := os.ReadFile(d.File(TempSessionFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("agent: %s: %w", d, ErrNoTempSession)
	}
	if err != nil {
		return nil, fmt.Errorf("agent: read %s: %w", TempSessionFile, err)
	}
	var s TempSession
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("agent: parse %s: %w", d.File(TempSessionFile), err)
	}
	if s.State == "" || s.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("agent: %s is incomplete: %w", d.File(TempSessionFile), ErrNoTempSession)
	}
	return &s, nil
}

// SaveTempSession replaces session.json atomically.
func (d DataDir) SaveTempSession(s *TempSession) error {
	if s.AgentVersion == "" {
		s.AgentVersion = version.Version
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivate(d.File(TempSessionFile), append(b, '\n')); err != nil {
		return fmt.Errorf("agent: write %s: %w", TempSessionFile, err)
	}
	return nil
}

// MarkTerminating drops the marker that says cleanup has begun. It is a
// separate file from session.json on purpose: it is the one thing that must
// still be true after a crash mid-teardown, when a rewritten session file may
// not have survived. It is idempotent.
func (d DataDir) MarkTerminating() error {
	f, err := os.OpenFile(d.File(terminatingFile), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("agent: mark terminating: %w", err)
	}
	_, werr := f.WriteString(time.Now().UTC().Format(time.RFC3339) + "\n")
	return errors.Join(werr, f.Sync(), f.Close())
}

// Terminating reports whether cleanup had already begun.
func (d DataDir) Terminating() bool {
	_, err := os.Stat(d.File(terminatingFile))
	return err == nil
}

// Unfinished reports whether a session must be cleaned up rather than run:
// its deadline has passed, cleanup had begun, or it is not in a live state.
func (s TempSession) Unfinished(now time.Time) bool {
	switch s.State {
	case TempEnrolled, TempRunning:
		return !now.Before(s.ExpiresAt)
	default:
		return true
	}
}

// NewReceipt builds the record left behind for the client.
func (s TempSession) NewReceipt(endedAt time.Time, reason string, requests int, hashes []string, revoked bool) Receipt {
	if len(hashes) > MaxReceiptHashes {
		hashes = hashes[len(hashes)-MaxReceiptHashes:]
	}
	return Receipt{
		Session: s.ID, DeviceID: s.DeviceID, Client: s.Client, ClientName: s.ClientName,
		Technician: s.Technician, Reason: s.Reason, Relay: s.RelayURL, Hostname: s.Hostname,
		AgentVersion: s.AgentVersion, Operations: s.Operations, Paths: s.Paths,
		EnrolledAt: s.EnrolledAt, ExpiresAt: s.ExpiresAt, EndedAt: endedAt.UTC(), EndReason: reason,
		Requests: requests, Hashes: hashes, Revoked: revoked, Note: receiptNote,
	}
}

// WriteReceipt writes r into dir (creating it with the data dir's owner-only
// permissions) and returns the file it wrote. The name carries the device and
// the end time, so concurrent sessions never collide.
func WriteReceipt(dir string, r Receipt) (string, error) {
	if err := mkdirPrivate(dir); err != nil {
		return "", fmt.Errorf("agent: create receipt dir %s: %w", dir, err)
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	id := r.DeviceID
	if id == "" {
		id = r.Session
	}
	path := filepath.Join(dir, fmt.Sprintf("keyhole-%s-%s.json", id, r.EndedAt.UTC().Format("20060102T150405Z")))
	if err := writePrivate(path, append(b, '\n')); err != nil {
		return "", fmt.Errorf("agent: write receipt: %w", err)
	}
	return path, nil
}
