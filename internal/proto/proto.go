// Package proto is the wire contract between the relay and the endpoint
// agent. Both sides import it, so a change here is a protocol change: keep
// changes additive, and bump Version for anything that is not.
//
// All payloads are JSON. A Request travels relay -> agent on a NATS
// request/reply subject; the agent answers with exactly one Response.
package proto

import (
	"encoding/json"
	"strings"
	"time"
)

// Version is carried in every Request and Response.
const Version = 1

// Timing shared by both sides.
const (
	HeartbeatInterval  = 30 * time.Second // agent publishes EvtHeartbeat this often
	OnlineWindow       = 90 * time.Second // relay treats a device as online if heard from within this
	DefaultRPCTimeout  = 30 * time.Second // relay-side wait for one Response
	MaxConsentDuration = time.Hour
	// ConsentTimeout bounds how long an access request may wait for the
	// endpoint user. A human needs minutes, so OpRequestAccess only acks and
	// the decision arrives later as an EvtConsent event. Both sides enforce
	// this independently: the endpoint denies with ReasonTimeout, and the
	// relay refuses a still-undecided request that has outlived it.
	ConsentTimeout = 5 * time.Minute
)

// Subjects. Every subject lives inside one client's own NATS account, so no
// subject carries a client identifier: the account boundary is the tenant
// boundary, and the relay reaches a client only through its connection in
// that client's account.
//
//	kh.d.<device>.rpc.<op>   relay -> agent, request/reply
//	kh.d.<device>.evt.<evt>  agent -> relay, fire-and-forget
//	kh.audit                 relay only; backs the per-client audit stream
const (
	subjectPrefix     = "kh.d."
	AllRPCWildcard    = "kh.d.*.rpc.>"
	AllEventsWildcard = "kh.d.*.evt.>"
	AuditSubject      = "kh.audit"
	AuditStream       = "KH_AUDIT"
)

// RPCSubject is the subject a device serves op on.
func RPCSubject(deviceID, op string) string { return subjectPrefix + deviceID + ".rpc." + op }

// RPCWildcard matches every op for one device; the device subscribes to it.
func RPCWildcard(deviceID string) string { return subjectPrefix + deviceID + ".rpc.>" }

// EventSubject is the subject a device publishes evt on.
func EventSubject(deviceID, evt string) string { return subjectPrefix + deviceID + ".evt." + evt }

// EventWildcard matches every event from one device.
func EventWildcard(deviceID string) string { return subjectPrefix + deviceID + ".evt.>" }

// DeviceFromSubject extracts <device> from a kh.d.<device>.… subject.
func DeviceFromSubject(subject string) (string, bool) {
	rest, ok := strings.CutPrefix(subject, subjectPrefix)
	if !ok {
		return "", false
	}
	id, _, ok := strings.Cut(rest, ".")
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

// Ops, used as the last token of an RPC subject and in Request.Op. File ops
// are read-only; the two control ops create and terminate consent authority.
const (
	OpPing          = "ping"
	OpListDir       = "list_dir"
	OpStat          = "stat"
	OpReadFile      = "read_file"
	OpSearchFiles   = "search_files"
	OpGrep          = "grep"
	OpHashFile      = "hash_file"
	OpRequestAccess = "request_access"
	OpEndAccess     = "end_access"
)

// Events, used as the last token of an event subject.
const (
	EvtHello     = "hello"   // on every (re)connect; payload Hello
	EvtHeartbeat = "hb"      // every HeartbeatInterval; payload Heartbeat
	EvtRevoke    = "revoke"  // endpoint gives up its own credential; payload Revoke
	EvtConsent   = "consent" // every endpoint consent transition; payload ConsentEvent
)

// Request is one call from the relay to an agent.
type Request struct {
	V          int             `json:"v"`
	ID         string          `json:"id"` // request ID; the audit entry carries the same value
	Op         string          `json:"op"`
	Args       json.RawMessage `json:"args,omitempty"`
	Policy     Policy          `json:"policy"`
	Caller     Caller          `json:"caller"`
	Deadline   time.Time       `json:"deadline"` // agent abandons the work after this
	Capability *Capability     `json:"capability,omitempty"`
}

// Capability is the endpoint-enforced authority created by local consent.
type Capability struct {
	GrantID       string        `json:"grant_id"`
	AccessID      string        `json:"access_id"`
	Nonce         string        `json:"nonce"`
	Client        string        `json:"client"`
	Device        string        `json:"device"`
	Technician    string        `json:"technician"`
	Operations    []string      `json:"operations"`
	Paths         []string      `json:"paths"`
	IssuedAt      time.Time     `json:"issued_at"`
	ExpiresAt     time.Time     `json:"expires_at"`
	IdleTimeout   time.Duration `json:"idle_timeout"`
	PolicyVersion int           `json:"policy_version"`
	// Unlock is the technician unlock that authorised this grant (Slice 6),
	// copied from ConsentRequest.Approval by the endpoint that minted it. It
	// is empty for a grant only the person at the machine approved.
	Unlock string `json:"unlock,omitempty"`
	// EndpointConsent says the person at the machine approved the grant as
	// well, because the client's policy asks for that.
	EndpointConsent bool `json:"endpoint_consent,omitempty"`
}

type ConsentRequest struct {
	// PlanDigest and Plan are set when the endpoint asks the local user to
	// review a prepared change: Plan is the proto.ChangePlan the UI renders
	// (diff included) and PlanDigest is what approval signs.
	PlanDigest    string          `json:"plan_digest,omitempty"`
	Plan          json.RawMessage `json:"plan,omitempty"`
	AccessID      string          `json:"access_id"`
	Client        string          `json:"client"`
	Device        string          `json:"device"`
	Technician    string          `json:"technician"`
	Purpose       string          `json:"purpose"`
	Operations    []string        `json:"operations"`
	Paths         []string        `json:"paths"`
	Duration      time.Duration   `json:"duration"`
	IdleTimeout   time.Duration   `json:"idle_timeout"`
	ExpiresAt     time.Time       `json:"expires_at"`
	PolicyVersion int             `json:"policy_version"`
	// Approval is the technician's signed unlock that authorises this access
	// request (Slice 6). With it a managed endpoint approves the request
	// itself, unless EndpointConsent asks the person at the machine as well.
	// Without it the request is the Slice 3 kind, for the person at the
	// machine alone.
	Approval        *TechnicianApproval `json:"approval,omitempty"`
	EndpointConsent bool                `json:"endpoint_consent,omitempty"`
}

type ConsentDecision struct {
	State string `json:"state"`
	// PlanDigest echoes the digest the approver signed when the request
	// carried a change plan. An approval whose digest does not match the plan
	// the endpoint holds is not an approval of that plan.
	PlanDigest string      `json:"plan_digest,omitempty"`
	Approver   string      `json:"approver"`
	Reason     string      `json:"reason,omitempty"`
	Operations []string    `json:"operations,omitempty"`
	Paths      []string    `json:"paths,omitempty"`
	Capability *Capability `json:"capability,omitempty"`
}

// Consent states. The endpoint reports them in ConsentDecision.State and
// ConsentEvent.State; the relay stores the same strings (see model).
const (
	ConsentAwaiting   = "awaiting_consent" // acked, shown to the endpoint user, undecided
	ConsentApproved   = "approved"
	ConsentNarrowed   = "narrowed" // approved with a subset of the requested scope
	ConsentDenied     = "denied"
	ConsentPaused     = "paused" // approved but temporarily unusable
	ConsentTerminated = "terminated"
)

// Consent reasons. They say why a grant was refused or stopped and are
// recorded in the audit entry for the transition.
const (
	ReasonTimeout    = "timeout"                // nobody decided within ConsentTimeout
	ReasonNoUser     = "no_user"                // no interactive session could be asked
	ReasonUser       = "user"                   // the endpoint user ended it
	ReasonLogoff     = "logoff"                 // the approving user signed out
	ReasonRestart    = "service_restart"        // the endpoint service restarted; live grants are gone
	ReasonUIGone     = "consent_ui_unavailable" // the consent application is not showing activity
	ReasonUIRestored = "consent_ui_restored"
	ReasonExpired    = "expired"    // the grant reached the end of its lifetime
	ReasonTechnician = "technician" // the technician ended it through the relay
)

// ConsentUpdate is one report from the local consent application about an
// access request it is showing: the decision first, then any later
// endpoint-initiated transition until the grant ends.
type ConsentUpdate struct {
	State           string   `json:"state"`
	Approver        string   `json:"approver,omitempty"`
	ApproverSession string   `json:"approver_session,omitempty"` // OS session the approver answered in
	Reason          string   `json:"reason,omitempty"`
	Operations      []string `json:"operations,omitempty"`
	Paths           []string `json:"paths,omitempty"`
	// Final says the adapter is not supervising this grant and will report
	// nothing further, so the endpoint must not read the end of the
	// conversation as the consent application having disappeared. A real
	// window that shows live activity never sets it; headless adapters do.
	Final bool `json:"final,omitempty"`
}

// ConsentEvent is published on EvtConsent for every consent transition the
// endpoint makes. It is how an asynchronous decision reaches the relay: the
// endpoint decides, the relay records, and access_status reads the record.
// Seq is per access request and lets the relay drop stale or duplicate
// deliveries.
type ConsentEvent struct {
	AccessID        string      `json:"access_id"`
	Client          string      `json:"client"`
	Device          string      `json:"device"`
	Technician      string      `json:"technician"`
	State           string      `json:"state"`
	Approver        string      `json:"approver,omitempty"`
	ApproverSession string      `json:"approver_session,omitempty"`
	Reason          string      `json:"reason,omitempty"`
	Operations      []string    `json:"operations,omitempty"`
	Paths           []string    `json:"paths,omitempty"`
	Capability      *Capability `json:"capability,omitempty"` // approved and narrowed only
	Seq             uint64      `json:"seq"`
	Time            time.Time   `json:"time"`
}

// ConsentActivity is one operation performed under a live grant, pushed to
// the local consent application so the endpoint user sees what is happening.
type ConsentActivity struct {
	AccessID  string    `json:"access_id"`
	Op        string    `json:"op"`
	Path      string    `json:"path,omitempty"`
	ErrorCode string    `json:"error_code,omitempty"`
	Bytes     int64     `json:"bytes"`
	Time      time.Time `json:"time"`
}

type EndAccessArgs struct {
	AccessID string `json:"access_id"`
	GrantID  string `json:"grant_id"`
	Nonce    string `json:"nonce"`
}

// Caller identifies who asked. The agent copies it into its local audit
// mirror (Windows Event Log / syslog); it grants nothing.
type Caller struct {
	Tech    string `json:"tech"`
	Session string `json:"session"`
}

// Policy is the effective scope for one call. The relay builds it from the
// client's policy for the device's OS and sends it with every request. The
// agent enforces it, and applies its compiled-in hard-deny list on top; no
// Policy can reach a hard-denied path.
type Policy struct {
	Version        int         `json:"version"`
	Allow          []AllowRule `json:"allow"`
	MaxReadBytes   int64       `json:"max_read_bytes"`   // cap on one read_file slice
	MaxFileBytes   int64       `json:"max_file_bytes"`   // grep skips and hash_file refuses larger files
	MaxListEntries int         `json:"max_list_entries"` // cap on list_dir and search_files results
	MaxMatches     int         `json:"max_matches"`      // cap on grep matches
	Redact         bool        `json:"redact"`           // redact secrets in returned text
	// ServiceAllow names the services service_restart may restart on this
	// client's devices. It is client policy, never technician input: an empty
	// list means no service may be restarted. The agent's compiled-in service
	// deny list still wins over it.
	ServiceAllow []string `json:"service_allow,omitempty"`
}

// AllowRule grants read access to a subtree.
//
// Path is an absolute path in the device OS's own syntax. Each segment may be
// a glob (path.Match syntax: *, ?, [...]) that matches exactly one path
// segment; matching is case-insensitive on Windows. A path is inside the rule
// when the rule's segments match its leading segments, so a rule grants the
// directory it names and everything below it.
//
// Files, when non-empty, restricts which files under the subtree are
// readable: a file's base name must match at least one of these globs.
// Directories under the subtree stay listable; listings omit files that fail
// the filter.
type AllowRule struct {
	ID    string   `json:"id"` // stable; recorded in the audit entry as the rule that matched
	Path  string   `json:"path"`
	Files []string `json:"files,omitempty"`
}

// Response is the agent's single reply to a Request.
type Response struct {
	V      int             `json:"v"`
	ID     string          `json:"id"` // echoes Request.ID
	OK     bool            `json:"ok"`
	Error  *Error          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"` // the op's *Result type when OK
	Meta   Meta            `json:"meta"`
}

// Meta is what the audit entry needs from the agent side of a call. It is
// filled for failures too, as far as the agent got.
//
// Bytes and SHA256 cover the exact Response.Result bytes (the agent builds
// Result with json.Marshal and hashes those bytes), which is precisely what
// the AI receives, after redaction. The relay recomputes both and refuses a
// mismatch.
type Meta struct {
	ResolvedPath   string    `json:"resolved_path,omitempty"`   // canonical path actually opened (final path of the handle)
	RuleID         string    `json:"rule_id,omitempty"`         // allow rule that matched
	Bytes          int64     `json:"bytes"`                     // len(Result)
	SHA256         string    `json:"sha256,omitempty"`          // hex SHA-256 of Result
	Redactions     int       `json:"redactions"`                // secrets replaced
	RedactionRules []string  `json:"redaction_rules,omitempty"` // distinct rule IDs that fired
	AgentTime      time.Time `json:"agent_time"`
	AgentVersion   string    `json:"agent_version"`
	DurationMS     int64     `json:"duration_ms"`
	// Change is filled by the structured remediation ops: what was changed,
	// from which hash to which, and where the rollback copy went. It is
	// metadata about the change, not content, and the relay copies it into the
	// audit entry.
	Change *ChangeMeta `json:"change,omitempty"`
}

// Error is a machine-readable failure.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Error codes returned by the agent.
const (
	ErrBadRequest  = "bad_request"    // malformed args, bad regex or glob, wrong protocol version
	ErrUnsupported = "unsupported_op" // op not implemented by this agent
	ErrUnsafePath  = "unsafe_path"    // traversal, ADS, device or \\?\ path, short name, escaping link or reparse point
	ErrNotAllowed  = "not_allowed"    // outside every allow rule, or filtered out by Files
	ErrHardDenied  = "hard_denied"    // on the compiled-in deny list
	ErrNotFound    = "not_found"
	ErrNotRegular  = "not_regular" // a file op on a directory, device or other non-regular file
	ErrTooLarge    = "too_large"   // over MaxFileBytes for an op that must read the whole file
	ErrIO          = "io_error"
	ErrTimeout     = "timeout"
	ErrInternal    = "internal"
	ErrBusy        = "busy" // too many requests in flight, or the agent is shutting down; retry later
)

// Error codes produced relay-side. They appear in audit entries and MCP tool
// errors, never in agent Responses.
const (
	ErrUnknownDevice   = "unknown_device" // device argument not found in the caller's client
	ErrAmbiguous       = "ambiguous_device"
	ErrDeviceOffline   = "device_offline"
	ErrDeviceRevoked   = "device_revoked"
	ErrClientDisabled  = "client_disabled" // kill switch is on
	ErrBudget          = "budget_exceeded" // session read budget spent
	ErrAuditFailed     = "audit_failed"    // could not write the audit entry, so nothing was returned
	ErrUnauthorized    = "unauthorized"
	ErrConsentRequired = "consent_required"
	ErrGrantInvalid    = "grant_invalid"
)

// File types in FileInfo.Type.
const (
	TypeFile    = "file"
	TypeDir     = "dir"
	TypeSymlink = "symlink"
	TypeOther   = "other"
)

// FileInfo describes one filesystem object.
type FileInfo struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"` // canonical absolute path
	Type    string    `json:"type"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// Limits the agent applies regardless of Policy.
const (
	DefaultSearchDepth = 8
	MaxSearchDepth     = 32
	GrepMaxLineBytes   = 1024 // a matching line is truncated to this many bytes
	GrepMaxFiles       = 5000 // files examined per grep call
)

// ListDirArgs lists one directory. Entries excluded by policy are counted in
// ListDirResult.Omitted, never named.
type ListDirArgs struct {
	Path  string `json:"path"`
	Limit int    `json:"limit,omitempty"` // 0 or > Policy.MaxListEntries means MaxListEntries
}

type ListDirResult struct {
	Path      string     `json:"path"`
	Entries   []FileInfo `json:"entries"`
	Omitted   int        `json:"omitted"` // hidden by the hard-deny list or a Files filter
	Truncated bool       `json:"truncated"`
}

type StatArgs struct {
	Path string `json:"path"`
}

type StatResult struct {
	FileInfo
	Mode string `json:"mode"` // os.FileMode string
}

// ReadFileArgs reads a slice of a text file.
//
// Offset >= 0 counts from the start of the file; Offset < 0 counts back from
// the end (a tail). Length 0 means "up to Policy.MaxReadBytes"; a larger
// Length is clamped to it. With no Offset and no Length on a file bigger than
// MaxReadBytes, the agent returns the last MaxReadBytes (tail by default,
// since these are mostly logs) and sets Truncated.
type ReadFileArgs struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset,omitempty"`
	Length int64  `json:"length,omitempty"`
}

type ReadFileResult struct {
	Path      string    `json:"path"`
	Size      int64     `json:"size"`   // whole file size
	Offset    int64     `json:"offset"` // absolute offset of the returned slice
	Length    int64     `json:"length"` // bytes read from disk, before redaction
	Content   string    `json:"content,omitempty"`
	Binary    bool      `json:"binary"`    // content sniffed as binary: Content is empty, metadata only
	Truncated bool      `json:"truncated"` // the file has bytes outside the returned slice
	ModTime   time.Time `json:"mod_time"`
}

// SearchFilesArgs finds files by base-name glob under a directory.
type SearchFilesArgs struct {
	Path     string `json:"path"`
	Pattern  string `json:"pattern"`             // path.Match glob on the base name, e.g. "*.log"
	MaxDepth int    `json:"max_depth,omitempty"` // 0 means DefaultSearchDepth; capped at MaxSearchDepth
	Limit    int    `json:"limit,omitempty"`     // 0 or > Policy.MaxListEntries means MaxListEntries
}

type SearchFilesResult struct {
	Matches   []FileInfo `json:"matches"`
	Scanned   int        `json:"scanned"` // directory entries examined
	Truncated bool       `json:"truncated"`
}

// GrepArgs searches file contents line by line with an RE2 regular
// expression. Path may be a file or a directory; for a directory, Glob
// filters files by base name and MaxDepth bounds the walk.
type GrepArgs struct {
	Path       string `json:"path"`
	Pattern    string `json:"pattern"`
	Glob       string `json:"glob,omitempty"`
	IgnoreCase bool   `json:"ignore_case,omitempty"`
	MaxMatches int    `json:"max_matches,omitempty"` // 0 or > Policy.MaxMatches means MaxMatches
	MaxDepth   int    `json:"max_depth,omitempty"`
}

type GrepMatch struct {
	Path string `json:"path"`
	Line int    `json:"line"` // 1-based
	Text string `json:"text"` // redacted, truncated to GrepMaxLineBytes
}

type GrepResult struct {
	Matches      []GrepMatch `json:"matches"`
	FilesScanned int         `json:"files_scanned"`
	FilesSkipped int         `json:"files_skipped"` // binary, too large, or unreadable
	Truncated    bool        `json:"truncated"`
}

type HashFileArgs struct {
	Path string `json:"path"`
}

type HashFileResult struct {
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	SHA256  string    `json:"sha256"`
	ModTime time.Time `json:"mod_time"`
}

type PingResult struct {
	DeviceID     string    `json:"device_id"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	Arch         string    `json:"arch"`
	AgentVersion string    `json:"agent_version"`
	Time         time.Time `json:"time"`
}

// Hello is published on EvtHello after every (re)connect.
type Hello struct {
	DeviceID     string    `json:"device_id"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	OSVersion    string    `json:"os_version"`
	Arch         string    `json:"arch"`
	AgentVersion string    `json:"agent_version"`
	Time         time.Time `json:"time"`
}

// Heartbeat is published on EvtHeartbeat every HeartbeatInterval.
type Heartbeat struct {
	DeviceID string    `json:"device_id"`
	Time     time.Time `json:"time"`
}

// Revoke is published on EvtRevoke when an endpoint gives up its own device
// credential: a temporary install that has expired, been terminated, or is
// finishing an interrupted session. The event subject names the device and a
// device may publish only its own subjects, so the subject is the
// authentication; DeviceID is a cross-check and a payload naming another
// device is ignored. The relay never depends on this event: the reconcile
// loop revokes an expired device whether or not the endpoint says so.
type Revoke struct {
	DeviceID string    `json:"device_id"`
	Reason   string    `json:"reason,omitempty"` // expired, terminated, interrupted
	Time     time.Time `json:"time"`
}

// Revoke reasons.
const (
	RevokeExpired     = "expired"
	RevokeTerminated  = "terminated"
	RevokeInterrupted = "interrupted"
)
