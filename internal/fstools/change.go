package fstools

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Structured remediation. The change*.go files are the only files in this
// package that write, and they write only:
//
//   - under a capability whose Operations contain the op (a request with no
//     capability is refused, unlike a read during migration),
//   - to a path that passed the whole read pipeline (shape, hard deny, allow
//     rules, os.Root containment, final-path recheck) plus the change-deny
//     list, at prepare time and again at apply time,
//   - through a plan whose digest the caller quotes back and whose recorded
//     file identity and hash still match the file on disk,
//   - into a temporary file in the target's own directory, which then replaces
//     the target atomically, so a crash leaves the original or the new content
//     and never a half-written file.
//
// Everything else in fstools stays read-only; TestNoWriteCapability enforces
// that on every other file.

// Layout under the agent's data dir. The directory inherits the data dir's
// ACL (SYSTEM and Administrators on Windows, 0700 root elsewhere), which is
// the only protection the rollback copies get: they hold the same bytes as a
// file the technician was already authorized to read.
const (
	plansDir    = "plans"
	rollbackDir = "rollback"
	journalDir  = "journal"

	planSuffix     = ".json"
	contentSuffix  = ".content"
	rollbackSuffix = ".bak"

	// tempPrefix marks the same-directory temporary file an apply writes
	// through. Startup cleanup removes leftovers by this name.
	tempPrefix = ".keyhole-change-"
	tempSuffix = ".tmp"

	storeVersion = 1
)

// Plan states.
const (
	planStaged     = "staged"
	planApplied    = "applied"
	planRolledBack = "rolled_back"
)

// Local review states of a staged plan, when an approver is configured. A
// plan staged without one has no review state and is gated by the capability
// and the relay's recorded digest alone.
const (
	reviewAwaiting = "awaiting" // shown at the machine, not yet answered
	reviewApproved = "approved"
	reviewDenied   = "denied"
	reviewEnded    = "ended" // the review closed unanswered: expired, grant ended, or replaced
)

// Journal states. An intent is written and flushed before the first byte of
// the target's directory is touched; the result replaces it after the rename.
const (
	journalIntent = "intent"
	journalDone   = "done"
)

// ChangeApprover is the local consent application's plan review. The Windows
// consent UI (Slice 3) implements it. ReviewChange shows the diff to the
// person at the machine and returns at once, like an access request: the
// channel carries at most one decision, naming the digest the user signed, and
// is then closed. A channel closed with no decision means the review ended
// undecided (the grant ended, the plan expired, or a newer plan replaced it).
// An error means the review could not be started at all, for example because
// no consent window is open. ctx bounds the review; it must outlive the
// request that prepared the plan.
//
// When no approver is configured the endpoint stages plans without a local
// signature and the gates are the capability plus the digest the relay
// recorded on the grant.
type ChangeApprover interface {
	ReviewChange(context.Context, proto.ConsentRequest) (<-chan proto.ConsentDecision, error)
}

// planRecord is one staged plan on disk. It binds the plan to the grant that
// prepared it: another grant, even for the same technician and device, cannot
// apply it.
type planRecord struct {
	Version         int                `json:"version"`
	Plan            proto.ChangePlan   `json:"plan"`
	AccessID        string             `json:"access_id"`
	GrantID         string             `json:"grant_id"`
	Technician      string             `json:"technician"`
	Approved        bool               `json:"approved"`
	Approver        string             `json:"approver,omitempty"`    // the reviewer at the machine; once applied under a technician grant, see recordApproval
	ApprovalID      string             `json:"approval_id,omitempty"` // the technician approval that applied it, under a technician grant
	Review          string             `json:"review,omitempty"`      // local review state; empty when nobody at the machine reviews it
	State           string             `json:"state"`
	AppliedAt       time.Time          `json:"applied_at,omitzero"`
	RollbackID      string             `json:"rollback_id,omitempty"`
	AppliedIdentity proto.FileIdentity `json:"applied_identity,omitzero"`
	RollbackSHA     string             `json:"rollback_sha256,omitempty"`
	RollbackUntil   time.Time          `json:"rollback_until,omitzero"`
}

// journalRecord makes a mutating request idempotent by request ID and lets a
// crashed apply be reconciled from what is on disk.
type journalRecord struct {
	Version    int               `json:"version"`
	RequestID  string            `json:"request_id"`
	Op         string            `json:"op"`
	PlanID     string            `json:"plan_id"`
	State      string            `json:"state"`
	TempPath   string            `json:"temp_path,omitempty"`
	RollbackID string            `json:"rollback_id,omitempty"`
	Result     json.RawMessage   `json:"result,omitempty"`
	Change     *proto.ChangeMeta `json:"change,omitempty"`
	At         time.Time         `json:"at"`
}

// grantUse is what one grant has spent. It lives in memory beside the live
// grant cache, which an endpoint restart also clears.
type grantUse struct {
	ops   int
	bytes int64
}

// changeStore owns the on-disk plans, rollback copies and journal, and
// serialises mutating ops: one at a time per device.
type changeStore struct {
	dir      string
	approver ChangeApprover
	log      *slog.Logger

	mu     sync.Mutex // held for the whole of one mutating op, and while a review outcome is recorded
	gmu    sync.Mutex
	grants map[string]*grantUse

	reviewed func(planID string) // tests only: called once a review's outcome is recorded
}

func newChangeStore(dir string, approver ChangeApprover, log *slog.Logger) (*changeStore, error) {
	for _, sub := range []string{plansDir, rollbackDir, journalDir} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, fmt.Errorf("fstools: change store %s: %w", dir, err)
		}
	}
	return &changeStore{dir: dir, approver: approver, log: log, grants: map[string]*grantUse{}}, nil
}

func (s *changeStore) planPath(id string) string {
	return filepath.Join(s.dir, plansDir, id+planSuffix)
}
func (s *changeStore) contentPath(id string) string {
	return filepath.Join(s.dir, plansDir, id+contentSuffix)
}
func (s *changeStore) rollbackPath(id string) string {
	return filepath.Join(s.dir, rollbackDir, id+rollbackSuffix)
}
func (s *changeStore) journalPath(requestID string) string {
	return filepath.Join(s.dir, journalDir, requestID+planSuffix)
}

// savePlan replaces a plan record atomically, so a crash never leaves a
// half-written plan that apply could misread.
func (s *changeStore) savePlan(p *planRecord) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return writeFileSync(s.planPath(p.Plan.PlanID), b)
}

func (s *changeStore) loadPlan(id string) (*planRecord, error) {
	b, err := os.ReadFile(s.planPath(id))
	if err != nil {
		return nil, err
	}
	var p planRecord
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if p.Version != storeVersion || p.Plan.PlanID != id {
		return nil, fmt.Errorf("plan %s is not readable by this agent", id)
	}
	return &p, nil
}

func (s *changeStore) loadJournal(requestID string) (*journalRecord, error) {
	b, err := os.ReadFile(s.journalPath(requestID))
	if err != nil {
		return nil, err
	}
	var j journalRecord
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

func (s *changeStore) saveJournal(j *journalRecord) error {
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return writeFileSync(s.journalPath(j.RequestID), b)
}

// charge books ops and bytes against a grant's ceilings. It is the endpoint's
// own limit: the relay's budget is separate and covers content read.
func (s *changeStore) charge(key string, ops int, bytes int64) error {
	s.gmu.Lock()
	defer s.gmu.Unlock()
	u := s.grants[key]
	if u == nil {
		u = &grantUse{}
		s.grants[key] = u
	}
	switch {
	case u.ops+ops > proto.MaxChangeOpsPerGrant:
		return failf(proto.ErrQuota, "this access grant has used its %d change operations", proto.MaxChangeOpsPerGrant)
	case u.bytes+bytes > proto.MaxChangedBytesPerGrant:
		return failf(proto.ErrQuota, "this access grant may change %d bytes in total and has used %d", proto.MaxChangedBytesPerGrant, u.bytes)
	}
	u.ops, u.bytes = u.ops+ops, u.bytes+bytes
	return nil
}

// used returns the bytes the change store currently holds: staged plans and
// their content, plus rollback copies.
func (s *changeStore) used() int64 {
	var total int64
	for _, sub := range []string{plansDir, rollbackDir} {
		entries, err := os.ReadDir(filepath.Join(s.dir, sub))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() {
				total += fi.Size()
			}
		}
	}
	return total
}

// changeStoreQuota is proto.ChangeStoreQuotaBytes; it is a variable so a test
// can exhaust the store without writing 64 MiB.
var changeStoreQuota int64 = proto.ChangeStoreQuotaBytes

// reserve purges what has expired and then refuses a change that would take
// the store over its quota.
func (s *changeStore) reserve(now time.Time, want int64) error {
	s.purge(now)
	if used := s.used(); used+want > changeStoreQuota {
		return failf(proto.ErrQuota, "the change store holds %d bytes of its %d-byte quota; roll back or let older rollback copies expire",
			used, changeStoreQuota)
	}
	return nil
}

// purge drops plans past their TTL and rollback copies past their retention,
// bounding the store without a background task.
func (s *changeStore) purge(now time.Time) {
	entries, _ := os.ReadDir(filepath.Join(s.dir, plansDir))
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), planSuffix)
		if !ok {
			continue
		}
		p, err := s.loadPlan(id)
		if err != nil {
			s.remove(s.planPath(id), s.contentPath(id))
			continue
		}
		keep := p.Plan.ExpiresAt
		if !p.RollbackUntil.IsZero() && p.RollbackUntil.After(keep) {
			keep = p.RollbackUntil
		}
		if now.Before(keep) {
			continue
		}
		s.remove(s.planPath(id), s.contentPath(id))
		if p.RollbackID != "" {
			s.remove(s.rollbackPath(p.RollbackID))
		}
	}
	// A rollback copy whose plan is gone is unreachable; drop it once it is
	// older than the retention window.
	rolls, _ := os.ReadDir(filepath.Join(s.dir, rollbackDir))
	for _, e := range rolls {
		fi, err := e.Info()
		if err == nil && now.Sub(fi.ModTime()) > proto.RollbackRetention {
			s.remove(s.rollbackPath(strings.TrimSuffix(e.Name(), rollbackSuffix)))
		}
	}
}

func (s *changeStore) remove(paths ...string) {
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.log.Warn("fstools: could not remove change store file", "path", p, "err", err)
		}
	}
}

// CleanupChangeStore removes what a crash could have left behind: the
// same-directory temporary files named by uncommitted journal intents, any
// stray temporary file beside them, and plans and rollback copies that have
// expired. It is safe to remove an intent's temporary file at any time: after
// a successful replace the temporary name no longer exists, and before one it
// is garbage. The agent calls it at startup.
func CleanupChangeStore(dir string, log *slog.Logger) error {
	if dir == "" {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	s, err := newChangeStore(dir, nil, log)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(dir, journalDir))
	if err != nil {
		return fmt.Errorf("fstools: change journal: %w", err)
	}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), planSuffix)
		if !ok {
			continue
		}
		j, err := s.loadJournal(id)
		if err != nil {
			s.remove(s.journalPath(id))
			continue
		}
		if j.State == journalIntent && j.TempPath != "" {
			if err := os.Remove(j.TempPath); err == nil {
				log.Info("fstools: removed a change temporary file left by an interrupted apply",
					"request_id", j.RequestID, "plan_id", j.PlanID, "path", j.TempPath)
			}
		}
	}
	s.purge(time.Now())
	return nil
}

// changeID returns an unguessable, filename-safe identifier. Plan and rollback
// IDs travel to the assistant and come back as arguments, so they are checked
// against this shape before they are ever joined to a path.
func changeID(prefix string) string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

func validChangeID(prefix, id string) bool {
	rest, ok := strings.CutPrefix(id, prefix+"_")
	if !ok || len(rest) != 20 {
		return false
	}
	for i := range len(rest) {
		if c := rest[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validRequestID accepts the relay's request IDs and nothing that could climb
// out of the journal directory.
func validRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// planDigest binds a plan to exactly one target, one original and one
// proposed content. The consent UI signs it, the relay records it on the
// grant, and apply refuses anything else.
func planDigest(path, beforeSHA, afterSHA, planID string) string {
	h := sha256.New()
	for _, part := range []string{"keyhole/change/v1", path, beforeSHA, afterSHA, planID} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// writeFileSync replaces path with data durably: a temporary file beside it,
// flushed, then renamed. Only the agent's own private directory is written
// this way; target files go through the change pipeline instead.
func writeFileSync(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
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

// changeCall is the state one change op needs beyond a read: its capability,
// the store, and the key its grant is charged against.
type changeCall struct {
	*call
	store *changeStore
	cap   *proto.Capability
	key   string
	now   time.Time
}

// change checks the authority every change op shares: the store exists, the
// request carries a capability, and that capability covers this op. The
// endpoint has already matched the capability against its live grant
// (Runner.authorize); this is the executor refusing to write without one at
// all, which is what keeps a legacy client-bound session read-only.
func (c *call) change() (*changeCall, error) {
	if c.x.changes == nil {
		return nil, failf(proto.ErrUnsupported, "this agent has no change store, so %s is not available", c.op)
	}
	cap := c.cap
	switch {
	case cap == nil:
		return nil, failf(proto.ErrConsentRequired, "%s requires an approved access grant; this request carries none", c.op)
	case !containsString(cap.Operations, c.op):
		return nil, failf(proto.ErrNotAllowed, "the approved grant does not include %s", c.op)
	case !validRequestID(c.id):
		return nil, failf(proto.ErrBadRequest, "the request ID is not a shape this agent will journal")
	case cap.Unlock != "" && c.op == proto.OpServiceRestart:
		// A technician unlock authorises reads, and every change under it needs
		// the technician's approval of that change. An approval names a plan;
		// a restart has none, so nothing can release one yet.
		return nil, failf(proto.ErrApprovalRequired, "this access grant came from a technician unlock, and a service restart needs the technician's approval of that restart, which Keyhole cannot ask for yet; nothing was restarted")
	}
	return &changeCall{call: c, store: c.x.changes, cap: cap, key: cap.AccessID + "/" + cap.GrantID, now: c.x.now().UTC()}, nil
}

// technician reports whether cc runs under a grant that came from a
// technician unlock (Slice 6). The unlock authorises reads; each write under
// such a grant needs the technician's own approval of exactly that write.
func (cc *changeCall) technician() bool { return cc.cap.Unlock != "" }

// reviewedAtMachine reports whether a plan prepared under cc's grant is shown
// to the person at the machine, and apply waits for their approval of it: for
// a legacy grant, which only they approved, and for a technician grant whose
// client's policy asks them as well. Under any other technician grant prepare
// is a dry run that prompts nobody.
func (cc *changeCall) reviewedAtMachine() bool {
	return cc.store.approver != nil && (!cc.technician() || cc.cap.EndpointConsent)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// openForChange resolves p through the whole read pipeline and then applies
// the change-deny list to the path as spelled and to the final path of the
// handle. A target must be an existing regular file: creating, deleting or
// moving files are separate primitives.
func (cc *changeCall) openForChange(p string) (*target, error) {
	if id, denied := policy.ChangeDenied(cc.goos, p); denied {
		return nil, cc.changeDenied(p, id)
	}
	t, err := cc.open(p)
	if err != nil {
		return nil, err
	}
	if id, denied := policy.ChangeDenied(cc.goos, t.path); denied {
		t.close()
		return nil, cc.changeDenied(p, id)
	}
	if t.info.IsDir() || !t.info.Mode().IsRegular() {
		t.close()
		return nil, failf(proto.ErrNotRegular, "%s is not a regular file; only an existing file can be changed", p)
	}
	return t, nil
}

func (c *call) changeDenied(p, ruleID string) error {
	c.meta.RuleID = ruleID
	return failf(proto.ErrChangeDenied, "%s is or resolves to a high-risk target (%s); no change capability may write it", p, ruleID)
}

// noteChange records what a change op did for the audit entry.
func (cc *changeCall) noteChange(m proto.ChangeMeta) {
	cc.meta.Change = &m
}

// replay returns the recorded result of a mutating request that has already
// run, so a retry after a lost reply changes nothing a second time.
func (cc *changeCall) replay(out any) (bool, error) {
	j, err := cc.store.loadJournal(cc.id)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, failf(proto.ErrInternal, "the change journal could not be read")
	}
	if j.Op != cc.op {
		return false, failf(proto.ErrBadRequest, "request ID %s was already used for %s", cc.id, j.Op)
	}
	if j.State != journalDone {
		return false, nil // an interrupted attempt; the op reconciles it
	}
	if err := json.Unmarshal(j.Result, out); err != nil {
		return false, failf(proto.ErrInternal, "the recorded result of this request could not be read")
	}
	if j.Change != nil {
		cc.noteChange(*j.Change)
	}
	return true, nil
}

// commit records the result of a mutating request under its request ID.
func (cc *changeCall) commit(planID string, result any, change proto.ChangeMeta) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return failf(proto.ErrInternal, "the result could not be recorded")
	}
	j := &journalRecord{Version: storeVersion, RequestID: cc.id, Op: cc.op, PlanID: planID,
		State: journalDone, Result: raw, Change: &change, At: cc.now}
	if err := cc.store.saveJournal(j); err != nil {
		return failf(proto.ErrIO, "the change was made but could not be journalled: %v", err)
	}
	return nil
}

// intent write-ahead logs what is about to happen, naming the temporary file,
// before anything in the target's directory is touched.
func (cc *changeCall) intent(planID, tempPath, rollbackID string) error {
	j := &journalRecord{Version: storeVersion, RequestID: cc.id, Op: cc.op, PlanID: planID,
		State: journalIntent, TempPath: tempPath, RollbackID: rollbackID, At: cc.now}
	if err := cc.store.saveJournal(j); err != nil {
		return failf(proto.ErrIO, "could not journal the change before making it: %v", err)
	}
	return nil
}
