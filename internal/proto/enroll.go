package proto

import "time"

// Enrollment runs over HTTPS on the relay's public listener, before the
// device has any NATS credential. The device generates its own NATS user
// NKey, sends only the public half, and gets back a user JWT signed for its
// client's account. The enrollment token is used once per device and never
// written to disk by the agent.
const EnrollPath = "/v1/enroll"

// EnrollRequest is the body of POST EnrollPath.
type EnrollRequest struct {
	Token        string `json:"token"`
	Org          string `json:"org,omitempty"` // optional; if set it must equal the token's client
	PublicKey    string `json:"public_key"`    // NATS user NKey public key ("U…") generated on the device
	Hostname     string `json:"hostname"`
	MachineID    string `json:"machine_id"` // MachineGuid / /etc/machine-id / IOPlatformUUID
	OS           string `json:"os"`         // runtime.GOOS
	OSVersion    string `json:"os_version"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agent_version"`
}

// EnrollResponse is the 200 body. The agent stores UserJWT together with its
// own seed as a standard NATS .creds file.
type EnrollResponse struct {
	DeviceID string   `json:"device_id"`
	Client   string   `json:"client"`
	UserJWT  string   `json:"user_jwt"`
	NATSURLs []string `json:"nats_urls"` // e.g. wss://keyhole.example.invalid/nats
}

// TempOfferPath is the public, pre-enrolment read of what a temporary
// install would be. The endpoint user must be shown the MSP's own terms
// before anything is installed, and the technician's command line is not a
// trustworthy source for them. The request consumes no token use and returns
// the same invalid_token refusal as enrolment for any unusable token.
const TempOfferPath = "/v1/enroll/offer"

// TempOfferRequest is the body of POST TempOfferPath. OS selects which of the
// client's allow rules are shown.
type TempOfferRequest struct {
	Token string `json:"token"`
	OS    string `json:"os,omitempty"`
}

// TempOffer is what the helper displays and the user consents to. It carries
// no credential and no capability.
type TempOffer struct {
	Client      string        `json:"client"`
	ClientName  string        `json:"client_name"`
	Technician  string        `json:"technician,omitempty"`
	Reason      string        `json:"reason,omitempty"`
	Operations  []string      `json:"operations"`
	Paths       []string      `json:"paths,omitempty"`
	MaxDuration time.Duration `json:"max_duration"`
	Ephemeral   bool          `json:"ephemeral"`
}

// ReadOps are the operations a temporary install can serve. They are
// read-only, and each one is still checked against policy and the hard-deny
// list at the endpoint. A temporary install's consent is the one given at the
// machine when it was installed, for these terms: it runs no per-request
// consent window, so it cannot grant a consented access request.
var ReadOps = []string{OpListDir, OpStat, OpReadFile, OpSearchFiles, OpGrep, OpHashFile}

// Enrollment error codes. Unknown, expired, revoked and used-up tokens all
// return ErrInvalidToken so the endpoint is not an oracle for token state.
const (
	ErrInvalidToken = "invalid_token"
	ErrOrgMismatch  = "org_mismatch"
)

// HTTPError is the body of every non-2xx response from the relay's HTTP
// APIs (enrollment and admin).
type HTTPError struct {
	Error Error `json:"error"`
}
