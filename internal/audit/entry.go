// Package audit is the per-client, append-only, hash-chained record of
// everything the AI read and every control-plane change. Anthropic's own
// audit exports exclude MCP tool activity, so this log is the record.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Entry kinds.
const (
	KindTool    = "tool"   // an MCP tool call, allowed or not
	KindAdmin   = "admin"  // a control-plane change: policy, kill switch, revoke, session or token mint
	KindEnroll  = "enroll" // a device enrolled
	KindConsent = "consent"
)

// Results.
const (
	ResultOK     = "ok"
	ResultDenied = "denied" // refused by scope, policy, kill switch or budget
	ResultError  = "error"
)

// Entry is one audit record. Field order is the canonical hashing order; do
// not reorder fields, and add new ones only at the end, before PrevHash.
type Entry struct {
	N            uint64          `json:"n"` // 1-based position in this client's chain
	Time         time.Time       `json:"time"`
	Kind         string          `json:"kind"`
	Client       string          `json:"client"`
	DeviceID     string          `json:"device_id,omitempty"`
	DeviceKey    string          `json:"device_key,omitempty"` // NATS user public key: the device credential fingerprint
	Hostname     string          `json:"hostname,omitempty"`
	AgentVersion string          `json:"agent_version,omitempty"`
	Tech         string          `json:"tech,omitempty"` // tech for tool calls, actor for admin changes
	SessionID    string          `json:"session_id,omitempty"`
	RequestID    string          `json:"request_id,omitempty"`
	Tool         string          `json:"tool"` // MCP tool name, or the admin action ("client.disable", "device.revoke", …)
	Args         json.RawMessage `json:"args,omitempty"`
	ResolvedPath string          `json:"resolved_path,omitempty"`
	RuleID       string          `json:"rule_id,omitempty"`
	Bytes        int64           `json:"bytes"`
	SHA256       string          `json:"sha256,omitempty"` // of the content returned to the AI
	Redactions   int             `json:"redactions"`
	Result       string          `json:"result"`
	ErrorCode    string          `json:"error_code,omitempty"`
	ErrorMessage string          `json:"error_message,omitempty"`
	AgentTime    *time.Time      `json:"agent_time,omitempty"`
	DurationMS   int64           `json:"duration_ms,omitempty"`
	// Change is the endpoint's proto.ChangeMeta for a structured remediation
	// call: plan ID and digest, the hashes before and after, the bytes
	// changed, the rollback copy, or the service restarted. It is omitted for
	// every other call, so entries written before Slice 5 hash unchanged.
	Change       json.RawMessage `json:"change,omitempty"`
	PrevHash     string          `json:"prev_hash"`
	Hash         string          `json:"hash,omitempty"`
	Sig          string          `json:"sig,omitempty"` // optional relay signature over Hash
}

// GenesisHash is the PrevHash of a client's first entry.
func GenesisHash(client string) string {
	sum := sha256.Sum256([]byte("keyhole/audit/v1/genesis/" + client))
	return hex.EncodeToString(sum[:])
}

// ComputeHash returns the hex SHA-256 of e's canonical JSON: e with Hash and
// Sig cleared, times in UTC, marshalled by encoding/json (which fixes field
// order and compacts Args).
func (e Entry) ComputeHash() (string, error) {
	e.Hash, e.Sig = "", ""
	e.Time = e.Time.UTC()
	if e.AgentTime != nil {
		t := e.AgentTime.UTC()
		e.AgentTime = &t
	}
	b, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("audit: canonical json: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Seal links e after prev (nil for a client's first entry): it sets N,
// PrevHash and Hash, and normalises times to UTC. Every Store uses it.
func Seal(e *Entry, prev *Entry) error {
	if e.Client == "" {
		return fmt.Errorf("audit: entry has no client")
	}
	e.Time = e.Time.UTC()
	if e.AgentTime != nil {
		t := e.AgentTime.UTC()
		e.AgentTime = &t
	}
	if prev == nil {
		e.N, e.PrevHash = 1, GenesisHash(e.Client)
	} else {
		if prev.Client != e.Client {
			return fmt.Errorf("audit: chaining %q after %q", e.Client, prev.Client)
		}
		e.N, e.PrevHash = prev.N+1, prev.Hash
	}
	h, err := e.ComputeHash()
	if err != nil {
		return err
	}
	e.Hash = h
	return nil
}
