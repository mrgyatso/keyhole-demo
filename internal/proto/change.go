package proto

import "time"

// Structured remediation (Slice 5). These are the only ops that write, and
// none of them takes free-form content from the assistant without a review
// step: a change is prepared, shown as a diff, signed as a plan, and only then
// applied. Every one of them requires a capability whose Operations contain
// the op; unlike the read ops, a legacy client-bound request with no
// capability is refused.
const (
	OpPrepareFileChange  = "prepare_file_change"
	OpApplyFileChange    = "apply_file_change"
	OpRollbackFileChange = "rollback_file_change"
	OpServiceQuery       = "service_query"
	OpServiceRestart     = "service_restart"
)

// Error codes the change ops add.
const (
	ErrStalePlan    = "stale_plan"      // the target, or the plan, is not what was reviewed
	ErrChangeDenied = "change_denied"   // a high-risk target no change capability may touch
	ErrQuota        = "quota_exceeded"  // the device's change store, or this grant's ceiling, is spent
	ErrConflict     = "change_conflict" // another mutating op on this device is in flight
)

// Change modes. Text content is UTF-8 and gets a real diff; binary content is
// base64 and gets a size/hash summary.
const (
	ChangeModeText   = "text"
	ChangeModeBinary = "binary"
)

// Ceilings the agent applies to every change, whatever the policy says. They
// bound what one grant can rewrite, how much a review has to read, and how
// much disk the rollback copies may hold.
const (
	MaxChangeBytes          = 1 << 20          // proposed content, and the original, per file
	MaxChangeDiffBytes      = 64 << 10         // unified diff returned for review
	MaxChangeDiffLines      = 400              // diff lines returned for review
	MaxChangeFilesPerPlan   = 4                // files one plan may name
	MaxChangedBytesPerGrant = 8 << 20          // total bytes written under one grant
	MaxChangeOpsPerGrant    = 32               // mutating ops under one grant
	ChangePlanTTL           = 30 * time.Minute // a staged plan expires this long after prepare
	RollbackRetention       = 24 * time.Hour   // a rollback copy is usable this long after apply
	ChangeStoreQuotaBytes   = 64 << 20         // staged plans plus rollback copies, per device
)

// FileIdentity is the endpoint's proof that apply reopened the same file
// prepare inspected, independent of its path: the volume serial and file index
// on Windows, the device and inode elsewhere. A path that now names a
// different file fails the check even when its content hashes the same.
type FileIdentity struct {
	VolumeSerial uint64 `json:"volume_serial,omitempty"`
	FileIndex    uint64 `json:"file_index,omitempty"`
	Dev          uint64 `json:"dev,omitempty"`
	Ino          uint64 `json:"ino,omitempty"`
}

// Zero reports whether the endpoint could not establish an identity.
func (f FileIdentity) Zero() bool { return f == FileIdentity{} }

// FileSnapshot is what the file was when the plan was prepared.
type FileSnapshot struct {
	Path     string       `json:"path"` // canonical path, the final path of the open handle
	Size     int64        `json:"size"`
	SHA256   string       `json:"sha256"`
	ModTime  time.Time    `json:"mod_time"`
	Mode     string       `json:"mode"` // os.FileMode string; informational on Windows
	Identity FileIdentity `json:"identity"`
}

// PrepareFileChangeArgs proposes replacing one file's whole content. Exactly
// one of Content and ContentBase64 is given. ExpectSHA256, when set, is the
// caller's belief about the current file: a mismatch fails before anything is
// staged.
type PrepareFileChangeArgs struct {
	Path          string `json:"path"`
	Mode          string `json:"mode,omitempty"` // ChangeModeText (default) or ChangeModeBinary
	Content       string `json:"content,omitempty"`
	ContentBase64 string `json:"content_base64,omitempty"`
	ExpectSHA256  string `json:"expect_sha256,omitempty"`
	Reason        string `json:"reason,omitempty"` // shown in the consent UI next to the diff
}

// ChangePlan is the reviewable summary of a prepared change. It is what the
// consent UI renders and what the plan digest covers.
type ChangePlan struct {
	PlanID        string       `json:"plan_id"`
	PlanDigest    string       `json:"plan_digest"`
	Op            string       `json:"op"` // OpPrepareFileChange today; later primitives reuse the shape
	Mode          string       `json:"mode"`
	Reason        string       `json:"reason,omitempty"`
	Before        FileSnapshot `json:"before"`
	AfterSHA256   string       `json:"after_sha256"`
	AfterSize     int64        `json:"after_size"`
	Diff          string       `json:"diff,omitempty"` // bounded unified diff; empty for binary
	DiffLines     int          `json:"diff_lines"`
	DiffTruncated bool         `json:"diff_truncated"`
	Binary        bool         `json:"binary"`
	PreparedAt    time.Time    `json:"prepared_at"`
	ExpiresAt     time.Time    `json:"expires_at"`
}

// PrepareFileChangeResult is returned to the technician. It stages nothing on
// the target: the new content sits in the agent's own data directory until an
// apply names the plan and its digest.
type PrepareFileChangeResult struct {
	ChangePlan
	Approved bool   `json:"approved"`           // a local approver signed the digest
	Approver string `json:"approver,omitempty"` // who signed it
	// Review is "awaiting" when the machine has shown the plan to the person
	// there for review: apply_file_change is refused until they approve it.
	// Empty when the machine has no local review.
	Review string `json:"review,omitempty"`
}

// ApplyFileChangeArgs applies a staged plan. Both fields must match the plan
// the endpoint holds, and the digest must also match the one the gateway
// recorded on the grant.
type ApplyFileChangeArgs struct {
	PlanID     string `json:"plan_id"`
	PlanDigest string `json:"plan_digest"`
	// Approval is the technician's signed approval of exactly this apply
	// (Slice 6). Under a grant that came from a technician unlock the endpoint
	// refuses an apply without one with ErrApprovalRequired.
	Approval *TechnicianApproval `json:"approval,omitempty"`
}

type ApplyFileChangeResult struct {
	PlanID       string    `json:"plan_id"`
	PlanDigest   string    `json:"plan_digest"`
	Path         string    `json:"path"`
	BeforeSHA256 string    `json:"before_sha256"`
	AfterSHA256  string    `json:"after_sha256"`
	BytesWritten int64     `json:"bytes_written"`
	RollbackID   string    `json:"rollback_id"`
	RollbackPath string    `json:"rollback_path"`
	RollbackTill time.Time `json:"rollback_until"`
	AppliedAt    time.Time `json:"applied_at"`
	Replayed     bool      `json:"replayed"` // this request ID had already been applied
}

// RollbackFileChangeArgs restores the copy an apply saved. The endpoint
// refuses if the target no longer holds the content that apply wrote.
type RollbackFileChangeArgs struct {
	PlanID     string `json:"plan_id"`
	RollbackID string `json:"rollback_id"`
	// Approval is the technician's signed approval of exactly this rollback
	// (Slice 6), required as for ApplyFileChangeArgs.Approval.
	Approval *TechnicianApproval `json:"approval,omitempty"`
}

type RollbackFileChangeResult struct {
	PlanID       string    `json:"plan_id"`
	Path         string    `json:"path"`
	BeforeSHA256 string    `json:"before_sha256"` // what the target held when rollback ran
	AfterSHA256  string    `json:"after_sha256"`  // the restored content
	BytesWritten int64     `json:"bytes_written"`
	RestoredAt   time.Time `json:"restored_at"`
	Replayed     bool      `json:"replayed"`
}

// Service states, normalised across platforms.
const (
	ServiceRunning  = "running"
	ServiceStopped  = "stopped"
	ServiceStarting = "starting"
	ServiceStopping = "stopping"
	ServiceUnknown  = "unknown"
)

// ServiceQueryArgs names one service. Query is allowed for any service the
// policy lists; nothing else is readable through it.
type ServiceQueryArgs struct {
	Name string `json:"name"`
}

type ServiceResult struct {
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name,omitempty"`
	State       string    `json:"state"`
	StartType   string    `json:"start_type,omitempty"`
	PID         int       `json:"pid,omitempty"`
	StateBefore string    `json:"state_before,omitempty"` // restart only
	Restarted   bool      `json:"restarted,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
}

// ServiceRestartArgs restarts one service. The name must appear in
// Policy.ServiceAllow and must not be on the agent's compiled-in service deny
// list; there is no way to name an arbitrary service.
type ServiceRestartArgs struct {
	Name string `json:"name"`
}

// ChangeMeta is what a mutating op reports for the audit record, beside the
// Meta.Bytes/SHA256 contract over the Result bytes. The relay copies it into
// the audit entry unchanged.
type ChangeMeta struct {
	PlanID       string `json:"plan_id,omitempty"`
	PlanDigest   string `json:"plan_digest,omitempty"`
	Approver     string `json:"approver,omitempty"`    // who approved it: the technician's label, and the person at the machine when they reviewed it too
	ApprovalID   string `json:"approval_id,omitempty"` // the technician approval that released it (Slice 6)
	BeforeSHA256 string `json:"before_sha256,omitempty"`
	AfterSHA256  string `json:"after_sha256,omitempty"`
	BytesChanged int64  `json:"bytes_changed,omitempty"`
	RollbackPath string `json:"rollback_path,omitempty"`
	Service      string `json:"service,omitempty"`
	Replayed     bool   `json:"replayed,omitempty"`
}

// ChangeOperations is the set of ops a consent request may ask for. Anything
// else is refused before a device is contacted.
func ChangeOperations() []string {
	return []string{OpReadFile, OpListDir, OpStat, OpSearchFiles, OpGrep, OpHashFile,
		OpPrepareFileChange, OpApplyFileChange, OpRollbackFileChange, OpServiceQuery, OpServiceRestart, OpListPrinters}
}

// Mutating reports whether op writes to the endpoint. Mutating ops run one at
// a time per device and are idempotent by request ID.
func Mutating(op string) bool {
	switch op {
	case OpApplyFileChange, OpRollbackFileChange, OpServiceRestart:
		return true
	}
	return false
}

// ChangeOp reports whether op belongs to the structured remediation set, all
// of which require a capability.
func ChangeOp(op string) bool {
	switch op {
	case OpPrepareFileChange, OpApplyFileChange, OpRollbackFileChange, OpServiceQuery, OpServiceRestart:
		return true
	}
	return false
}
