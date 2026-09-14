// Package consentipc connects the Keyhole service to the per-user consent
// application. The service owns the device credential, the relay connection
// and every filesystem operation; the consent application only shows what is
// being asked for and carries the endpoint user's answer back. They talk
// over a local named pipe with newline-delimited JSON.
//
// The transport is Windows-only. Everything that decides what a message
// means lives in Hub, which builds and is tested on every platform.
package consentipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

const (
	// PipeName is the service's endpoint. It is a local name: a named pipe
	// with no network path cannot be reached from another machine.
	PipeName = `\\.\pipe\keyhole-consent`

	// PipeSDDL gives SYSTEM and Administrators full control and lets
	// interactive users read and write. Every connection is then checked
	// again: the peer must be the installed consent executable, and only an
	// elevated peer may approve.
	PipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019f;;;IU)"

	// ProtocolVersion is the service/consent-application contract. The two
	// are installed and updated together. The protocol grows additively: a
	// peer ignores message types and JSON fields it does not know, so a new
	// message pair (Slice 5's change-plan review is the first planned) needs
	// no new version. The version changes only for a change an existing peer
	// would misread; a service that sees another version logs it.
	ProtocolVersion = 1

	// MaxMessageBytes bounds one line on the pipe.
	MaxMessageBytes = 256 << 10
)

// Message types.
const (
	TypeHello      = "hello"       // both ways, first message
	TypeRequest    = "request"     // service -> application: show this access request
	TypeState      = "state"       // service -> application: the request moved
	TypeActivity   = "activity"    // service -> application: one operation happened
	TypePlan       = "plan"        // service -> application: review a staged file change
	TypePlanState  = "plan_state"  // service -> application: a staged change's review moved
	TypeDecide     = "decide"      // application -> service: the user answered
	TypePlanDecide = "plan_decide" // application -> service: the user reviewed a staged change
	TypeControl    = "control"     // application -> service: pause, resume or terminate
)

// Review states of a staged change, as PlanStateView reports them.
const (
	PlanAwaiting = "awaiting" // shown, not yet answered
	PlanApproved = "approved"
	PlanDenied   = "denied"
	PlanEnded    = "ended" // no longer answerable: the grant ended, the plan expired, or a newer plan replaced it
)

// Decisions and controls the consent application can send.
const (
	DecideApprove = "approve" // with Select: narrow to those paths
	DecideDeny    = "deny"
	ControlPause  = "pause"
	ControlResume = "resume"
	ControlEnd    = "terminate"
)

// Envelope is one message. Exactly one payload field is set.
type Envelope struct {
	Type       string                 `json:"type"`
	Hello      *Hello                 `json:"hello,omitempty"`
	Request    *RequestView           `json:"request,omitempty"`
	State      *StateView             `json:"state,omitempty"`
	Activity   *proto.ConsentActivity `json:"activity,omitempty"`
	Plan       *PlanView              `json:"plan,omitempty"`
	PlanState  *PlanStateView         `json:"plan_state,omitempty"`
	Decide     *Decision              `json:"decide,omitempty"`
	PlanDecide *PlanDecision          `json:"plan_decide,omitempty"`
	Control    *Control               `json:"control,omitempty"`
}

// Hello identifies each side. The service's copy names the machine so the
// window can show which endpoint is being asked about; the application's
// copy carries nothing the service trusts, because the service establishes
// the peer's identity from the pipe itself.
type Hello struct {
	Version  int    `json:"version"`
	Device   string `json:"device,omitempty"`
	Client   string `json:"client,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Agent    string `json:"agent,omitempty"`
}

// RequestView is an access request as the endpoint user sees it. It is
// exactly what the relay asked for, never a summary the relay wrote.
type RequestView struct {
	AccessID    string        `json:"access_id"`
	Client      string        `json:"client"`
	Device      string        `json:"device"`
	Technician  string        `json:"technician"`
	Purpose     string        `json:"purpose"`
	Paths       []string      `json:"paths"`
	Operations  []string      `json:"operations"`
	Duration    time.Duration `json:"duration"`
	IdleTimeout time.Duration `json:"idle_timeout"`
	ExpiresAt   time.Time     `json:"expires_at"`
	DecideBy    time.Time     `json:"decide_by"` // the consent window closes here
	State       string        `json:"state"`
	Approver    string        `json:"approver,omitempty"`
	Effective   []string      `json:"effective,omitempty"` // granted paths once approved
}

// StateView tells the application a request moved.
type StateView struct {
	AccessID  string    `json:"access_id"`
	State     string    `json:"state"`
	Reason    string    `json:"reason,omitempty"`
	Approver  string    `json:"approver,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Effective []string  `json:"effective,omitempty"`
}

// PlanView is a bounded staged change for local review. The digest is what
// the endpoint user approves; the service never accepts a digest from a UI
// message that it did not send.
type PlanView struct {
	AccessID   string    `json:"access_id"`
	Digest     string    `json:"digest"`
	Path       string    `json:"path"`
	Diff       string    `json:"diff"`
	Reason     string    `json:"reason,omitempty"`     // what the technician says the change fixes
	Technician string    `json:"technician,omitempty"` // who prepared it
	ExpiresAt  time.Time `json:"expires_at"`
}

// PlanStateView tells the application a staged change's review moved. A window
// that is still showing the plan closes it on any state but PlanAwaiting, so a
// late click never reaches UAC for a review that is already over.
type PlanStateView struct {
	AccessID string `json:"access_id"`
	Digest   string `json:"digest"`
	State    string `json:"state"`              // PlanAwaiting, PlanApproved, PlanDenied or PlanEnded
	Reason   string `json:"reason,omitempty"`   // why a review ended
	Approver string `json:"approver,omitempty"` // who answered, once answered
}

type PlanDecision struct {
	AccessID string `json:"access_id"`
	Digest   string `json:"digest"`
	Decision string `json:"decision"`
}

// Decision is the endpoint user's answer. Select lists the indexes of
// RequestView.Paths the user left ticked; empty means all of them. The
// application never sends paths of its own, so it cannot widen a request
// even if it is lying.
type Decision struct {
	AccessID string `json:"access_id"`
	Decision string `json:"decision"`
	Select   []int  `json:"select,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Control is pause, resume or terminate on a live grant.
type Control struct {
	AccessID string `json:"access_id"`
	Action   string `json:"action"`
}

// ErrTooLong is returned when a peer sends a line over MaxMessageBytes.
var ErrTooLong = errors.New("consentipc: message is too long")

// NewReader returns a reader bounded to one message per line.
func NewReader(r io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(r, 8<<10)
}

// ReadEnvelope reads one newline-delimited message.
func ReadEnvelope(r *bufio.Reader) (Envelope, error) {
	var line []byte
	for {
		chunk, more, err := r.ReadLine()
		if err != nil {
			return Envelope{}, err
		}
		line = append(line, chunk...)
		if len(line) > MaxMessageBytes {
			return Envelope{}, ErrTooLong
		}
		if !more {
			break
		}
	}
	var e Envelope
	if err := json.Unmarshal(line, &e); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

// WriteEnvelope writes one newline-delimited message.
func WriteEnvelope(w io.Writer, e Envelope) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(b) > MaxMessageBytes {
		return ErrTooLong
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
