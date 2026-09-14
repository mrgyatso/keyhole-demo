// Package natsauth mints the NATS credentials that form Keyhole's tenant
// boundary, and the nats-server configuration that trusts them.
//
// The trust chain is:
//
//	operator identity key      signs only the operator JWT
//	└─ operator signing key    signs every account JWT (SYS and clients)
//	   ├─ SYS account, whose signing key signs the relay's SYS user
//	   └─ one account per client, whose one signing key signs
//	      ├─ the relay user    pub kh.d.*.rpc.> kh.audit $JS.API.>  sub _INBOX.> kh.d.*.evt.>
//	      └─ one device user   pub kh.d.<id>.evt.>  sub kh.d.<id>.rpc.>  replies (max 1)
//
// The operator is strict (StrictSigningKeyUsage): an identity key never signs
// what sits below it, only signing keys do. The operator identity seed is
// needed only to re-issue the operator JWT.
package natsauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// JetStream limits of a client account. The only stream a client account
// holds is its audit stream, so the disk quota is the audit quota.
//
// A single nats-server reserves each account's disk quota against its
// max_file_store and refuses JetStream to an account that would overflow it,
// so max_file_store / AccountDiskQuota is the number of clients that can
// have an audit stream (64 with the defaults). Raise max_file_store as the
// client count grows; nats-server does not check it against the real disk.
const (
	AccountDiskQuota   = 1 << 30 // bytes of file storage per client account
	AccountMemoryQuota = 0       // no memory-backed streams
)

// RelayUserName names the relay's user in every client account.
const RelayUserName = "keyhole-relay"

// jsAPI is the JetStream API prefix; the relay user needs it to manage the
// audit stream.
const jsAPI = "$JS.API.>"

// relayPermissions is the relay user's whole reach inside a client account.
func relayPermissions() jwt.Permissions {
	var p jwt.Permissions
	p.Pub.Allow.Add(proto.AllRPCWildcard, proto.AuditSubject, jsAPI)
	p.Sub.Allow.Add("_INBOX.>", proto.AllEventsWildcard)
	return p
}

// devicePermissions lets a device serve its own RPC subjects, publish its own
// events, and answer each request once. Nothing else.
func devicePermissions(deviceID string) jwt.Permissions {
	var p jwt.Permissions
	p.Pub.Allow.Add(proto.EventWildcard(deviceID))
	p.Sub.Allow.Add(proto.RPCWildcard(deviceID))
	p.Resp = &jwt.ResponsePermission{MaxMsgs: 1}
	return p
}

// deviceIDRE keeps a device ID to a single NATS subject token.
var deviceIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// UserCreds is one NATS user credential: a user JWT and the seed of the NKey
// the JWT names.
type UserCreds struct {
	JWT  string
	Seed string
}

// Option authenticates a nats.go connection with c.
func (c UserCreds) Option() nats.Option { return nats.UserJWTAndSeed(c.JWT, c.Seed) }

// Marshal formats c as a standard NATS .creds file.
func (c UserCreds) Marshal() ([]byte, error) {
	b, err := jwt.FormatUserConfig(c.JWT, []byte(c.Seed))
	if err != nil {
		return nil, fmt.Errorf("natsauth: format creds: %w", err)
	}
	return b, nil
}

// ParseCreds reads a .creds file and checks that its seed matches its JWT.
func ParseCreds(b []byte) (UserCreds, error) {
	tok, err := jwt.ParseDecoratedJWT(b)
	if err != nil {
		return UserCreds{}, fmt.Errorf("natsauth: creds jwt: %w", err)
	}
	uc, err := jwt.DecodeUserClaims(tok)
	if err != nil {
		return UserCreds{}, fmt.Errorf("natsauth: creds jwt: %w", err)
	}
	kp, err := jwt.ParseDecoratedUserNKey(b)
	if err != nil {
		return UserCreds{}, fmt.Errorf("natsauth: creds seed: %w", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return UserCreds{}, fmt.Errorf("natsauth: creds seed: %w", err)
	}
	if pub != uc.Subject {
		return UserCreds{}, errors.New("natsauth: creds seed does not match its jwt")
	}
	seed, err := kp.Seed()
	if err != nil {
		return UserCreds{}, fmt.Errorf("natsauth: creds seed: %w", err)
	}
	return UserCreds{JWT: tok, Seed: string(seed)}, nil
}

// ReadCreds reads a .creds file from disk.
func ReadCreds(path string) (UserCreds, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return UserCreds{}, fmt.Errorf("natsauth: %w", err)
	}
	return ParseCreds(b)
}

// Operator is the root of trust of one Keyhole deployment, together with the
// SYS account the relay pushes account JWTs through. It is secret: keep it in
// a 0600 file.
type Operator struct {
	Name           string `json:"name"`
	PublicKey      string `json:"public_key"`   // "O…"
	Seed           string `json:"seed"`         // operator identity; signs only the operator JWT
	SigningSeed    string `json:"signing_seed"` // signs every account JWT
	JWT            string `json:"jwt"`
	SysAccount     string `json:"sys_account"` // "A…"
	SysAccountSeed string `json:"sys_account_seed"`
	SysSigningSeed string `json:"sys_signing_seed"` // signs SYS users
	SysAccountJWT  string `json:"sys_account_jwt"`
}

// NewOperator creates an operator with one signing key, and its SYS account.
func NewOperator(name string) (*Operator, error) {
	opKP, err := nkeys.CreateOperator()
	if err != nil {
		return nil, fmt.Errorf("natsauth: operator key: %w", err)
	}
	signKP, err := nkeys.CreateOperator()
	if err != nil {
		return nil, fmt.Errorf("natsauth: operator signing key: %w", err)
	}
	sysKP, err := nkeys.CreateAccount()
	if err != nil {
		return nil, fmt.Errorf("natsauth: sys account key: %w", err)
	}
	sysSignKP, err := nkeys.CreateAccount()
	if err != nil {
		return nil, fmt.Errorf("natsauth: sys account signing key: %w", err)
	}
	o := &Operator{Name: name}
	o.PublicKey, o.Seed, err = keyStrings(opKP)
	if err != nil {
		return nil, err
	}
	var signPub, sysSignPub string
	signPub, o.SigningSeed, err = keyStrings(signKP)
	if err != nil {
		return nil, err
	}
	o.SysAccount, o.SysAccountSeed, err = keyStrings(sysKP)
	if err != nil {
		return nil, err
	}
	sysSignPub, o.SysSigningSeed, err = keyStrings(sysSignKP)
	if err != nil {
		return nil, err
	}

	oc := jwt.NewOperatorClaims(o.PublicKey)
	oc.Name = name
	oc.SigningKeys.Add(signPub)
	oc.SystemAccount = o.SysAccount
	oc.StrictSigningKeyUsage = true
	if o.JWT, err = oc.Encode(opKP); err != nil {
		return nil, fmt.Errorf("natsauth: operator jwt: %w", err)
	}

	ac := jwt.NewAccountClaims(o.SysAccount)
	ac.Name = "SYS"
	ac.SigningKeys.Add(sysSignPub)
	if o.SysAccountJWT, err = ac.Encode(signKP); err != nil {
		return nil, fmt.Errorf("natsauth: sys account jwt: %w", err)
	}
	return o, nil
}

// LoadOperator reads an operator written by WriteFile and checks that its
// keys and JWTs belong together.
func LoadOperator(path string) (*Operator, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("natsauth: %w", err)
	}
	var o Operator
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, fmt.Errorf("natsauth: %s: %w", path, err)
	}
	if err := o.validate(); err != nil {
		return nil, fmt.Errorf("natsauth: %s: %w", path, err)
	}
	return &o, nil
}

// WriteFile saves the operator, seeds included, to a new 0600 file.
func (o *Operator) WriteFile(path string) error {
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return fmt.Errorf("natsauth: %w", err)
	}
	return writeNewFile(path, append(b, '\n'))
}

func (o *Operator) validate() error {
	if err := seedMatches(o.Seed, o.PublicKey); err != nil {
		return fmt.Errorf("operator seed: %w", err)
	}
	if err := seedMatches(o.SysAccountSeed, o.SysAccount); err != nil {
		return fmt.Errorf("sys account seed: %w", err)
	}
	signer, err := o.signer()
	if err != nil {
		return err
	}
	signPub, err := signer.PublicKey()
	if err != nil {
		return fmt.Errorf("operator signing seed: %w", err)
	}
	oc, err := jwt.DecodeOperatorClaims(o.JWT)
	if err != nil {
		return fmt.Errorf("operator jwt: %w", err)
	}
	if oc.Subject != o.PublicKey || !oc.SigningKeys.Contains(signPub) || oc.SystemAccount != o.SysAccount {
		return errors.New("operator jwt does not match the operator keys")
	}
	ac, err := jwt.DecodeAccountClaims(o.SysAccountJWT)
	if err != nil {
		return fmt.Errorf("sys account jwt: %w", err)
	}
	sysSigner, err := nkeys.FromSeed([]byte(o.SysSigningSeed))
	if err != nil {
		return fmt.Errorf("sys signing seed: %w", err)
	}
	sysSignPub, err := sysSigner.PublicKey()
	if err != nil {
		return fmt.Errorf("sys signing seed: %w", err)
	}
	if ac.Subject != o.SysAccount || ac.Issuer != signPub || !ac.SigningKeys.Contains(sysSignPub) {
		return errors.New("sys account jwt does not match the operator keys")
	}
	return nil
}

func (o *Operator) signer() (nkeys.KeyPair, error) {
	kp, err := nkeys.FromSeed([]byte(o.SigningSeed))
	if err != nil {
		return nil, fmt.Errorf("natsauth: operator signing seed: %w", err)
	}
	return kp, nil
}

// NewSysUser mints an unrestricted user in the SYS account. The relay uses it
// to push account JWTs; an operator can use its .creds with the nats CLI.
func (o *Operator) NewSysUser(name string) (UserCreds, error) {
	kp, err := nkeys.FromSeed([]byte(o.SysSigningSeed))
	if err != nil {
		return UserCreds{}, fmt.Errorf("natsauth: sys signing seed: %w", err)
	}
	return newUser(kp, o.SysAccount, name, jwt.Permissions{})
}

// Account is one client's NATS account and everything the relay needs to
// sign inside it. It is secret.
type Account struct {
	PublicKey   string // "A…"
	Seed        string // account identity
	SigningSeed string // the account's one signing key; signs the relay and device users
	JWT         string // account JWT signed by the operator signing key
	Relay       UserCreds
}

// NewAccount creates a client account with JetStream enabled for the audit
// stream, one signing key, and the relay user.
func (o *Operator) NewAccount(name string) (*Account, error) {
	accKP, err := nkeys.CreateAccount()
	if err != nil {
		return nil, fmt.Errorf("natsauth: account key: %w", err)
	}
	signKP, err := nkeys.CreateAccount()
	if err != nil {
		return nil, fmt.Errorf("natsauth: account signing key: %w", err)
	}
	a := &Account{}
	if a.PublicKey, a.Seed, err = keyStrings(accKP); err != nil {
		return nil, err
	}
	var signPub string
	if signPub, a.SigningSeed, err = keyStrings(signKP); err != nil {
		return nil, err
	}

	ac := jwt.NewAccountClaims(a.PublicKey)
	ac.Name = name
	ac.SigningKeys.Add(signPub)
	ac.Limits.DisallowBearer = true // a user JWT alone never authenticates; its seed must sign the nonce
	ac.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: AccountMemoryQuota,
		DiskStorage:   AccountDiskQuota,
		Streams:       jwt.NoLimit,
		Consumer:      jwt.NoLimit,
	}
	if a.JWT, err = o.sign(ac); err != nil {
		return nil, err
	}
	if a.Relay, err = newUser(signKP, a.PublicKey, RelayUserName, relayPermissions()); err != nil {
		return nil, err
	}
	return a, nil
}

// Revoke returns accountJWT re-signed so that every user JWT for one of the
// given public keys issued at or before its time is rejected, and connected
// users holding one are disconnected once the JWT is pushed. When every key
// is already revoked it returns accountJWT unchanged and changed=false.
func (o *Operator) Revoke(accountJWT string, keys map[string]time.Time) (updated string, changed bool, err error) {
	ac, err := o.decodeAccount(accountJWT)
	if err != nil {
		return "", false, err
	}
	for key, at := range keys {
		if !nkeys.IsValidPublicUserKey(key) {
			return "", false, fmt.Errorf("natsauth: revoke %q: not a user public key", key)
		}
		if ts, ok := ac.Revocations[key]; ok && ts >= at.Unix() {
			continue
		}
		ac.RevokeAt(key, at)
		changed = true
	}
	if !changed {
		return accountJWT, false, nil
	}
	if updated, err = o.sign(ac); err != nil {
		return "", false, err
	}
	return updated, true, nil
}

// decodeAccount decodes an account JWT and checks that this operator issued it.
func (o *Operator) decodeAccount(accountJWT string) (*jwt.AccountClaims, error) {
	ac, err := jwt.DecodeAccountClaims(accountJWT)
	if err != nil {
		return nil, fmt.Errorf("natsauth: account jwt: %w", err)
	}
	signer, err := o.signer()
	if err != nil {
		return nil, err
	}
	signPub, err := signer.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("natsauth: operator signing key: %w", err)
	}
	if ac.Issuer != signPub {
		return nil, fmt.Errorf("natsauth: account %s was not issued by this operator", ac.Subject)
	}
	return ac, nil
}

func (o *Operator) sign(ac *jwt.AccountClaims) (string, error) {
	vr := jwt.CreateValidationResults()
	ac.Validate(vr)
	if vr.IsBlocking(true) {
		return "", fmt.Errorf("natsauth: account %s: invalid claims: %v", ac.Subject, vr.Errors())
	}
	signer, err := o.signer()
	if err != nil {
		return "", err
	}
	tok, err := ac.Encode(signer)
	if err != nil {
		return "", fmt.Errorf("natsauth: sign account %s: %w", ac.Subject, err)
	}
	return tok, nil
}

// DeviceJWT signs a user JWT for a device's own NKey public key with the
// client account's signing key. The device keeps the seed; the JWT confines
// it to its own subjects.
func DeviceJWT(accountKey, signingSeed, deviceID, userKey string) (string, error) {
	if !deviceIDRE.MatchString(deviceID) {
		return "", fmt.Errorf("natsauth: device id %q is not a single subject token", deviceID)
	}
	if !nkeys.IsValidPublicUserKey(userKey) {
		return "", errors.New("natsauth: device key is not a user public key")
	}
	if !nkeys.IsValidPublicAccountKey(accountKey) {
		return "", errors.New("natsauth: not an account public key")
	}
	kp, err := nkeys.FromSeed([]byte(signingSeed))
	if err != nil {
		return "", fmt.Errorf("natsauth: account signing seed: %w", err)
	}
	return signUser(kp, accountKey, userKey, deviceID, devicePermissions(deviceID))
}

func newUser(issuer nkeys.KeyPair, issuerAccount, name string, perms jwt.Permissions) (UserCreds, error) {
	kp, err := nkeys.CreateUser()
	if err != nil {
		return UserCreds{}, fmt.Errorf("natsauth: user key: %w", err)
	}
	pub, seed, err := keyStrings(kp)
	if err != nil {
		return UserCreds{}, err
	}
	tok, err := signUser(issuer, issuerAccount, pub, name, perms)
	if err != nil {
		return UserCreds{}, err
	}
	return UserCreds{JWT: tok, Seed: seed}, nil
}

func signUser(issuer nkeys.KeyPair, issuerAccount, userKey, name string, perms jwt.Permissions) (string, error) {
	uc := jwt.NewUserClaims(userKey)
	uc.Name = name
	uc.IssuerAccount = issuerAccount
	uc.Permissions = perms
	tok, err := uc.Encode(issuer)
	if err != nil {
		return "", fmt.Errorf("natsauth: sign user %s: %w", name, err)
	}
	return tok, nil
}

func keyStrings(kp nkeys.KeyPair) (pub, seed string, err error) {
	if pub, err = kp.PublicKey(); err != nil {
		return "", "", fmt.Errorf("natsauth: public key: %w", err)
	}
	s, err := kp.Seed()
	if err != nil {
		return "", "", fmt.Errorf("natsauth: seed: %w", err)
	}
	return pub, string(s), nil
}

func seedMatches(seed, pub string) error {
	kp, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return err
	}
	got, err := kp.PublicKey()
	if err != nil {
		return err
	}
	if got != pub {
		return errors.New("does not match its public key")
	}
	return nil
}

// writeNewFile creates path with mode 0600 and refuses to replace a file.
func writeNewFile(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("natsauth: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return fmt.Errorf("natsauth: write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("natsauth: write %s: %w", path, err)
	}
	return nil
}
