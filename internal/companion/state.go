package companion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// What the companion shows. Every view is built field by field from the stored
// rows, never by passing a row through, so a nonce, an assertion, a secret's
// hash, or anything added to a row later, cannot reach the page by accident.

const (
	activityLimit        = 50   // calls shown for the active unlock
	receiptActivityLimit = 1000 // calls listed on a receipt
)

type stateView struct {
	Technician string         `json:"technician"`
	ServerTime time.Time      `json:"server_time"`
	Unlocks    []unlockView   `json:"unlocks"`  // open ones, and those requested in the last day; newest first
	Changes    []changeView   `json:"changes"`  // likewise
	Activity   []activityView `json:"activity"` // the active unlock's calls, newest first
}

type deviceView struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

type unlockView struct {
	ID          string       `json:"id"`
	Client      string       `json:"client"`
	ClientName  string       `json:"client_name"`
	Purpose     string       `json:"purpose"`
	State       string       `json:"state"`
	Reason      string       `json:"reason,omitempty"`
	Duration    int64        `json:"duration_seconds"`
	IdleTimeout int64        `json:"idle_timeout_seconds"`
	RequestedAt time.Time    `json:"requested_at"`
	Deadline    time.Time    `json:"deadline"`               // unanswered by then, it expires
	DecidedAt   *time.Time   `json:"decided_at,omitempty"`   // approved or denied
	ExpiresAt   *time.Time   `json:"expires_at,omitempty"`   // once approved: its end
	IdleAt      *time.Time   `json:"idle_at,omitempty"`      // active: when it ends without another call
	LastUsedAt  *time.Time   `json:"last_used_at,omitempty"` //
	EndedAt     *time.Time   `json:"ended_at,omitempty"`
	Calls       int64        `json:"calls"`
	Devices     []deviceView `json:"devices"`
	Passkey     string       `json:"passkey,omitempty"` // the name of the passkey that decided it
	Changes     []string     `json:"changes"`           // the change approvals made under it
}

type planView struct {
	Path          string    `json:"path"`
	Reason        string    `json:"reason,omitempty"`
	BeforeSHA256  string    `json:"before_sha256"`
	BeforeSize    int64     `json:"before_size"`
	AfterSHA256   string    `json:"after_sha256"`
	AfterSize     int64     `json:"after_size"`
	Diff          string    `json:"diff"`
	DiffLines     int       `json:"diff_lines"`
	DiffTruncated bool      `json:"diff_truncated"`
	Binary        bool      `json:"binary"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type changeView struct {
	ID          string          `json:"id"`
	Op          string          `json:"op"`
	Client      string          `json:"client"`
	ClientName  string          `json:"client_name"`
	Device      string          `json:"device"`
	Hostname    string          `json:"hostname"`
	State       string          `json:"state"`
	Reason      string          `json:"reason,omitempty"`
	ErrorCode   string          `json:"error_code,omitempty"`
	RequestedAt time.Time       `json:"requested_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
	DecidedAt   *time.Time      `json:"decided_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	PlanID      string          `json:"plan_id"`
	RollbackID  string          `json:"rollback_id,omitempty"`
	Unlock      string          `json:"unlock,omitempty"` // the unlock it was made under
	Plan        *planView       `json:"plan,omitempty"`   // nil once the relay's copy is purged
	Result      json.RawMessage `json:"result,omitempty"` // the endpoint's result, once applied
}

type activityView struct {
	Time      time.Time `json:"time"`
	Op        string    `json:"op"`
	Device    string    `json:"device"`
	Hostname  string    `json:"hostname"`
	Path      string    `json:"path,omitempty"`
	Result    string    `json:"result"`
	ErrorCode string    `json:"error_code,omitempty"`
	Bytes     int64     `json:"bytes"`
}

// handleState is everything the page shows, for the signed-in technician
// only.
func (s *Server) handleState(w http.ResponseWriter, r *http.Request, cs model.CompanionSession) {
	ctx, now := r.Context(), s.now()
	since := now.Add(-model.ApprovalRetention)
	unlocks, err := s.store.Unlocks(ctx, cs.Technician, since)
	if err != nil {
		s.fail(w, err)
		return
	}
	changes, err := s.store.ChangeApprovals(ctx, cs.Technician, since)
	if err != nil {
		s.fail(w, err)
		return
	}
	keys, err := s.store.PasskeysForTechnician(ctx, cs.Technician)
	if err != nil {
		s.fail(w, err)
		return
	}
	n := s.resolver(ctx)
	v := stateView{Technician: cs.Technician, ServerTime: now.UTC(),
		Unlocks: []unlockView{}, Changes: []changeView{}, Activity: []activityView{}}
	under := map[string]int{} // access request ID → its unlock's index in v.Unlocks
	for _, u := range unlocks {
		v.Unlocks = append(v.Unlocks, unlockViewOf(n, u, keys))
		if u.State == model.UnlockAwaiting {
			continue // nothing has run under it yet
		}
		access, err := s.store.AccessForUnlock(ctx, u.ID)
		if err != nil {
			s.fail(w, err)
			return
		}
		for _, a := range access {
			under[a.ID] = len(v.Unlocks) - 1
		}
		if u.State == model.UnlockActive {
			acts, err := s.store.UnlockActivity(ctx, u.ID, activityLimit)
			if err != nil {
				s.fail(w, err)
				return
			}
			for _, a := range acts {
				v.Activity = append(v.Activity, activityView{Time: a.Time, Op: a.Op, Device: a.Device,
					Hostname: n.host(u.Client, a.Device), Path: a.Path, Result: a.Result, ErrorCode: a.ErrorCode, Bytes: a.Bytes})
			}
		}
	}
	for _, c := range changes {
		cv, err := s.changeViewOf(ctx, n, c)
		if err != nil {
			s.fail(w, err)
			return
		}
		if i, ok := under[c.AccessID]; ok {
			cv.Unlock = v.Unlocks[i].ID
			v.Unlocks[i].Changes = append(v.Unlocks[i].Changes, c.ID)
		}
		v.Changes = append(v.Changes, cv)
	}
	writeJSON(w, http.StatusOK, v)
}

func unlockViewOf(n *resolver, u model.Unlock, keys []model.Passkey) unlockView {
	v := unlockView{ID: u.ID, Client: u.Client, ClientName: n.client(u.Client), Purpose: u.Purpose, State: u.State,
		Reason: u.Reason, Duration: int64(u.Duration / time.Second), IdleTimeout: int64(u.IdleTimeout / time.Second),
		RequestedAt: u.RequestedAt, Deadline: u.Deadline, DecidedAt: u.DecidedAt, LastUsedAt: u.LastUsedAt,
		EndedAt: u.EndedAt, Calls: u.Calls, Devices: []deviceView{}, Changes: []string{}}
	// While it awaits, ExpiresAt is only what the open prompt offers.
	if u.State != model.UnlockAwaiting {
		v.ExpiresAt = u.ExpiresAt
	}
	if u.State == model.UnlockActive && u.IdleTimeout > 0 {
		last := u.LastUsedAt
		if last == nil {
			last = u.DecidedAt
		}
		if last != nil {
			at := last.Add(u.IdleTimeout)
			v.IdleAt = &at
		}
	}
	for _, d := range u.Devices {
		v.Devices = append(v.Devices, deviceView{ID: d, Hostname: n.host(u.Client, d)})
	}
	for _, k := range keys {
		if u.Credential != "" && k.CredentialID == u.Credential {
			v.Passkey = k.Name
		}
	}
	return v
}

func (s *Server) changeViewOf(ctx context.Context, n *resolver, c model.ChangeApproval) (changeView, error) {
	v := changeView{ID: c.ID, Op: c.Op, Client: c.Client, ClientName: n.client(c.Client), Device: c.Device,
		Hostname: n.host(c.Client, c.Device), State: c.State, Reason: c.Reason, ErrorCode: c.ErrorCode,
		RequestedAt: c.RequestedAt, ExpiresAt: c.ExpiresAt, DecidedAt: c.DecidedAt, CompletedAt: c.CompletedAt,
		PlanID: c.PlanID, RollbackID: c.RollbackID, Result: cleanResult(c.Result)}
	rec, err := s.store.ChangePlan(ctx, c.PlanID)
	switch {
	case errors.Is(err, model.ErrNotFound):
		return v, nil
	case err != nil:
		return v, err
	}
	var p proto.ChangePlan
	if err := json.Unmarshal(rec.Plan, &p); err != nil {
		s.log.Error("stored change plan is not a proto.ChangePlan", "plan", c.PlanID, "err", err)
		return v, nil
	}
	v.Plan = &planView{Path: p.Before.Path, Reason: p.Reason, BeforeSHA256: p.Before.SHA256, BeforeSize: p.Before.Size,
		AfterSHA256: p.AfterSHA256, AfterSize: p.AfterSize, Diff: p.Diff, DiffLines: p.DiffLines,
		DiffTruncated: p.DiffTruncated, Binary: p.Binary, ExpiresAt: rec.ExpiresAt}
	return v, nil
}

// cleanResult passes the endpoint's result of a change to the card, less
// anything that authorises or signs: the page shows what happened, never
// what proves it.
func cleanResult(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	for k := range m {
		switch strings.ToLower(k) {
		case "approval", "assertion", "nonce", "signature", "capability", "credential":
			delete(m, k)
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return b
}

func (s *Server) respondUnlock(w http.ResponseWriter, r *http.Request, u model.Unlock) {
	// The passkey's name is decoration; the answer stands without it.
	keys, _ := s.store.PasskeysForTechnician(r.Context(), u.Technician)
	writeJSON(w, http.StatusOK, unlockViewOf(s.resolver(r.Context()), u, keys))
}

func (s *Server) respondChange(w http.ResponseWriter, r *http.Request, c model.ChangeApproval) {
	v, err := s.changeViewOf(r.Context(), s.resolver(r.Context()), c)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleReceipt is an unlock's receipt, as plain text for the ticket.
func (s *Server) handleReceipt(w http.ResponseWriter, r *http.Request, cs model.CompanionSession) {
	u, err := s.ownUnlock(r.Context(), r.PathValue("id"), cs.Technician)
	if err != nil {
		s.fail(w, err)
		return
	}
	text, err := s.receipt(r.Context(), u)
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, text)
}

// reasonText says why an unlock or a change ended.
var reasonText = map[string]string{
	model.ReasonUnanswered: "nobody answered in time",
	model.ReasonIdle:       "no call used it for its idle limit",
	model.ReasonLocked:     "the technician pressed Lock",
	model.ReasonSignedOut:  "the technician signed out",
	model.ReasonSwitched:   "the technician unlocked another client",
	model.ReasonDenied:     "the technician denied it",
	proto.ReasonExpired:    "it reached its end",
}

func outcome(state, reason string) string {
	if why, ok := reasonText[reason]; ok {
		return state + ": " + why
	}
	if reason != "" {
		return state + ": " + reason
	}
	return state
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }

// receipt is the plain-text record of an unlock, to attach to the ticket: who
// unlocked which client and why, when it began and ended, the devices and the
// calls it covered, each change made under it with its outcome and hashes,
// and every call it served.
func (s *Server) receipt(ctx context.Context, u model.Unlock) (string, error) {
	n := s.resolver(ctx)
	keys, err := s.store.PasskeysForTechnician(ctx, u.Technician)
	if err != nil {
		return "", err
	}
	access, err := s.store.AccessForUnlock(ctx, u.ID)
	if err != nil {
		return "", err
	}
	under := make(map[string]bool, len(access))
	for _, a := range access {
		under[a.ID] = true
	}
	changes, err := s.store.ChangeApprovals(ctx, u.Technician, u.RequestedAt)
	if err != nil {
		return "", err
	}
	activity, err := s.store.UnlockActivity(ctx, u.ID, receiptActivityLimit)
	if err != nil {
		return "", err
	}
	v := unlockViewOf(n, u, keys)

	var b strings.Builder
	field := func(k, val string) { fmt.Fprintf(&b, "%-13s%s\n", k, val) }
	b.WriteString("Keyhole unlock receipt\n\n")
	field("Client", fmt.Sprintf("%s (%s)", v.ClientName, u.Client))
	field("Technician", u.Technician)
	field("Purpose", u.Purpose)
	field("Unlock", u.ID)
	field("Outcome", outcome(u.State, u.Reason))
	field("Requested", stamp(u.RequestedAt))
	if u.DecidedAt != nil {
		how := stamp(*u.DecidedAt)
		if v.Passkey != "" {
			how += " with passkey " + strconv.Quote(v.Passkey)
		}
		field("Decided", how)
	}
	if v.ExpiresAt != nil {
		field("Valid until", stamp(*v.ExpiresAt))
	}
	if u.EndedAt != nil {
		field("Ended", stamp(*u.EndedAt))
	}
	field("Calls", strconv.FormatInt(u.Calls, 10))
	devices := make([]string, 0, len(v.Devices))
	for _, d := range v.Devices {
		devices = append(devices, d.Hostname+" ("+d.ID+")")
	}
	if len(devices) == 0 {
		devices = append(devices, "none")
	}
	field("Devices", strings.Join(devices, ", "))

	b.WriteString("\nChanges\n")
	listed := 0
	for i := len(changes) - 1; i >= 0; i-- { // oldest first
		c := changes[i]
		if !under[c.AccessID] {
			continue
		}
		listed++
		cv, err := s.changeViewOf(ctx, n, c)
		if err != nil {
			return "", err
		}
		op := "apply"
		if c.Op == proto.OpRollbackFileChange {
			op = "undo"
		}
		path := "(the relay no longer keeps this plan)"
		if cv.Plan != nil {
			path = cv.Plan.Path
		}
		fmt.Fprintf(&b, "  %s %s on %s: %s\n", op, path, cv.Hostname, outcome(c.State, c.Reason))
		if p := cv.Plan; p != nil {
			fmt.Fprintf(&b, "    before  sha256 %s (%d bytes)\n    after   sha256 %s (%d bytes)\n",
				p.BeforeSHA256, p.BeforeSize, p.AfterSHA256, p.AfterSize)
		}
		fmt.Fprintf(&b, "    plan %s, change %s, requested %s", c.PlanID, c.ID, stamp(c.RequestedAt))
		if c.CompletedAt != nil {
			fmt.Fprintf(&b, ", done %s", stamp(*c.CompletedAt))
		}
		b.WriteString("\n")
		if c.ErrorCode != "" {
			fmt.Fprintf(&b, "    error %s\n", c.ErrorCode)
		}
	}
	if listed == 0 {
		b.WriteString("  none\n")
	}

	b.WriteString("\nCalls, newest first\n")
	for _, a := range activity {
		res := a.Result
		if a.ErrorCode != "" {
			res += " (" + a.ErrorCode + ")"
		}
		fmt.Fprintf(&b, "  %s  %-20s %-16s %-10s %s\n", a.Time.UTC().Format("15:04:05"), a.Op, n.host(u.Client, a.Device), res, a.Path)
	}
	switch {
	case len(activity) == 0:
		b.WriteString("  none\n")
	case len(activity) == receiptActivityLimit:
		fmt.Fprintf(&b, "  (only the latest %d calls are listed)\n", receiptActivityLimit)
	}
	fmt.Fprintf(&b, "\nGenerated %s by the Keyhole companion.\n", stamp(s.now()))
	return b.String(), nil
}

// resolver names clients and devices for the cards, looking each up once per
// request. A name that cannot be found shows as its ID: the card must still
// show.
type resolver struct {
	ctx     context.Context
	dir     model.Directory
	clients map[string]string
	hosts   map[string]map[string]string // client → device → hostname
}

func (s *Server) resolver(ctx context.Context) *resolver {
	return &resolver{ctx: ctx, dir: s.dir, clients: map[string]string{}, hosts: map[string]map[string]string{}}
}

func (n *resolver) client(slug string) string {
	if name, ok := n.clients[slug]; ok {
		return name
	}
	name := slug
	if c, err := n.dir.Client(n.ctx, slug); err == nil && c.Name != "" {
		name = c.Name
	}
	n.clients[slug] = name
	return name
}

func (n *resolver) host(client, device string) string {
	m, ok := n.hosts[client]
	if !ok {
		m = map[string]string{}
		if devices, err := n.dir.Devices(n.ctx, client); err == nil {
			for _, d := range devices {
				m[d.ID] = d.Hostname
			}
		}
		n.hosts[client] = m
	}
	if h := m[device]; h != "" {
		return h
	}
	return device
}
