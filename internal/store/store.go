// Package store is the relay's SQLite database: clients with the NATS keys
// the relay signs with for each, enrollment tokens, devices, MCP sessions,
// the admin token, and a small key-value table.
//
// Secrets (enrollment tokens, session bearers, the admin token) are stored
// only as model.HashSecret hashes, and never appear in returned errors. NATS
// seeds are stored in the clear, so the data dir must be 0700; encrypting
// them at rest is Phase 2.
//
// *Store implements model.Directory. Times are stored and returned in UTC.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite", pure Go

	"github.com/mrgyatso/keyhole/internal/model"
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrOrgMismatch is returned by EnrollDevice when the agent names a client
// other than the token's.
var ErrOrgMismatch = errors.New("org does not match the token's client")

var _ model.Directory = (*Store)(nil)

// Store is the relay's database. It is safe for concurrent use.
type Store struct {
	db *sql.DB
}

// Open opens (creating it 0600 if needed) and migrates the database at path.
func Open(path string) (*Store, error) {
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("store: invalid database path %q", path)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	f.Close()
	// Every connection gets these; _txlock=immediate makes each write
	// transaction take the write lock at BEGIN, so a read-check-write inside
	// one (like consuming a token) cannot race another.
	dsn := path + "?_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)" +
		"&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// migrate applies the embedded migrations the database has not seen yet,
// tracking progress in PRAGMA user_version.
func (s *Store) migrate(ctx context.Context) error {
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("store: migrations: %w", err)
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("store: schema version: %w", err)
	}
	if version > len(names) {
		return fmt.Errorf("store: database schema version %d is newer than this binary's %d", version, len(names))
	}
	for i, name := range names[version:] {
		b, err := migrations.ReadFile(name)
		if err != nil {
			return fmt.Errorf("store: %w", err)
		}
		n := version + i + 1
		err = s.inTx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, string(b)); err != nil {
				return fmt.Errorf("store: migration %s: %w", name, err)
			}
			_, err := tx.ExecContext(ctx, "PRAGMA user_version = "+strconv.Itoa(n))
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// querier is satisfied by *sql.DB and *sql.Tx.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type row interface{ Scan(dest ...any) error }

func queryAll[T any](ctx context.Context, q querier, scan func(row) (T, error), query string, args ...any) ([]T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return out, nil
}

// lookupErr wraps a single-row lookup error; key must not be a secret.
func lookupErr(what, key string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		err = model.ErrNotFound
	}
	return fmt.Errorf("store: %s %q: %w", what, key, err)
}

// mustAffect turns an UPDATE that matched no row into ErrNotFound.
func mustAffect(res sql.Result, err error, what, key string) error {
	if err != nil {
		return fmt.Errorf("store: %s %q: %w", what, key, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: %s %q: %w", what, key, err)
	}
	if n == 0 {
		return fmt.Errorf("store: %s %q: %w", what, key, model.ErrNotFound)
	}
	return nil
}

// Times are stored as fixed-width UTC text, so they also sort as text.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

func fmtTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("bad stored time %q: %w", s, err)
	}
	return t, nil
}

func parseTimePtr(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid {
		return nil, nil
	}
	t, err := parseTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func clientExists(ctx context.Context, q querier, slug string) error {
	var one int
	err := q.QueryRowContext(ctx, "SELECT 1 FROM clients WHERE slug = ?", slug).Scan(&one)
	if err != nil {
		return lookupErr("client", slug, err)
	}
	return nil
}

// ----- clients -----

// AccountKeys is the NATS material the relay keeps for one client account.
type AccountKeys struct {
	AccountKey  string // account public key ("A…")
	AccountSeed string
	SigningSeed string // the account signing key; signs the relay and device users
	AccountJWT  string // current account JWT, as last signed by the operator
	RelayJWT    string // the relay user's credential in this account
	RelaySeed   string
}

const clientCols = "slug, name, account_key, disabled, created_at, policy"

func scanClient(r row) (model.Client, error) {
	var (
		c                model.Client
		disabled         int
		created, polJSON string
	)
	if err := r.Scan(&c.Slug, &c.Name, &c.AccountKey, &disabled, &created, &polJSON); err != nil {
		return c, err
	}
	c.Disabled = disabled != 0
	var err error
	if c.CreatedAt, err = parseTime(created); err != nil {
		return c, err
	}
	if err := json.Unmarshal([]byte(polJSON), &c.Policy); err != nil {
		return c, fmt.Errorf("client %s policy: %w", c.Slug, err)
	}
	return c, nil
}

// CreateClient records a new client and its NATS keys. The client's
// AccountKey is taken from k. An existing slug or account is ErrConflict.
func (s *Store) CreateClient(ctx context.Context, c model.Client, k AccountKeys) error {
	if !model.ValidSlug(c.Slug) {
		return fmt.Errorf("store: client slug %q: %w", c.Slug, model.ErrInvalid)
	}
	pol, err := json.Marshal(c.Policy)
	if err != nil {
		return fmt.Errorf("store: client %s policy: %w", c.Slug, err)
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var n int
		err := tx.QueryRowContext(ctx, "SELECT count(*) FROM clients WHERE slug = ? OR account_key = ?",
			c.Slug, k.AccountKey).Scan(&n)
		if err != nil {
			return fmt.Errorf("store: client %q: %w", c.Slug, err)
		}
		if n > 0 {
			return fmt.Errorf("store: client %q: %w", c.Slug, model.ErrConflict)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO clients
			(slug, name, account_key, account_seed, signing_seed, account_jwt, relay_jwt, relay_seed, disabled, policy, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.Slug, c.Name, k.AccountKey, k.AccountSeed, k.SigningSeed, k.AccountJWT, k.RelayJWT, k.RelaySeed,
			boolInt(c.Disabled), string(pol), fmtTime(c.CreatedAt))
		if err != nil {
			return fmt.Errorf("store: create client %q: %w", c.Slug, err)
		}
		return nil
	})
}

// Client returns a client by slug, or ErrNotFound.
func (s *Store) Client(ctx context.Context, slug string) (model.Client, error) {
	c, err := scanClient(s.db.QueryRowContext(ctx, "SELECT "+clientCols+" FROM clients WHERE slug = ?", slug))
	if err != nil {
		return model.Client{}, lookupErr("client", slug, err)
	}
	return c, nil
}

// Clients returns every client, by slug.
func (s *Store) Clients(ctx context.Context) ([]model.Client, error) {
	return queryAll(ctx, s.db, scanClient, "SELECT "+clientCols+" FROM clients ORDER BY slug")
}

// AccountKeys returns a client's NATS keys, or ErrNotFound.
func (s *Store) AccountKeys(ctx context.Context, slug string) (AccountKeys, error) {
	var k AccountKeys
	err := s.db.QueryRowContext(ctx, `SELECT account_key, account_seed, signing_seed, account_jwt, relay_jwt, relay_seed
		FROM clients WHERE slug = ?`, slug).
		Scan(&k.AccountKey, &k.AccountSeed, &k.SigningSeed, &k.AccountJWT, &k.RelayJWT, &k.RelaySeed)
	if err != nil {
		return AccountKeys{}, lookupErr("client", slug, err)
	}
	return k, nil
}

// SetAccountJWT replaces a client's account JWT (after a re-sign, e.g. to
// add revocations).
func (s *Store) SetAccountJWT(ctx context.Context, slug, accountJWT string) error {
	res, err := s.db.ExecContext(ctx, "UPDATE clients SET account_jwt = ? WHERE slug = ?", accountJWT, slug)
	return mustAffect(res, err, "client", slug)
}

// SetDisabled turns a client's kill switch on (with a reason) or off, and
// returns the updated client.
func (s *Store) SetDisabled(ctx context.Context, slug string, disabled bool, reason string, at time.Time) (model.Client, error) {
	var disabledAt any
	if disabled {
		disabledAt = fmtTime(at)
	} else {
		reason = ""
	}
	res, err := s.db.ExecContext(ctx,
		"UPDATE clients SET disabled = ?, disabled_reason = ?, disabled_at = ? WHERE slug = ?",
		boolInt(disabled), reason, disabledAt, slug)
	if err := mustAffect(res, err, "client", slug); err != nil {
		return model.Client{}, err
	}
	return s.Client(ctx, slug)
}

// Policy returns a client's policy, or ErrNotFound.
func (s *Store) Policy(ctx context.Context, slug string) (model.ClientPolicy, error) {
	c, err := s.Client(ctx, slug)
	return c.Policy, err
}

// SetPolicy replaces a client's whole policy. The stored Version becomes the
// previous one plus one, whatever p.Version says; the stored policy is
// returned.
func (s *Store) SetPolicy(ctx context.Context, slug string, p model.ClientPolicy) (model.ClientPolicy, error) {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var raw string
		if err := tx.QueryRowContext(ctx, "SELECT policy FROM clients WHERE slug = ?", slug).Scan(&raw); err != nil {
			return lookupErr("client", slug, err)
		}
		var cur model.ClientPolicy
		if err := json.Unmarshal([]byte(raw), &cur); err != nil {
			return fmt.Errorf("store: client %s policy: %w", slug, err)
		}
		p.Version = cur.Version + 1
		b, err := json.Marshal(p)
		if err != nil {
			return fmt.Errorf("store: client %s policy: %w", slug, err)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE clients SET policy = ? WHERE slug = ?", string(b), slug); err != nil {
			return fmt.Errorf("store: client %s policy: %w", slug, err)
		}
		return nil
	})
	if err != nil {
		return model.ClientPolicy{}, err
	}
	return p, nil
}

// ----- enrollment tokens -----

const tokenCols = "id, client, hash, note, created_at, expires_at, max_uses, uses, revoked_at, " +
	"ephemeral, device_ttl_ns, technician"

func scanToken(r row) (model.EnrollToken, error) {
	var (
		t                model.EnrollToken
		created, expires string
		revoked          sql.NullString
		ephemeral        int
		ttl              int64
		err              error
	)
	if err = r.Scan(&t.ID, &t.Client, &t.Hash, &t.Note, &created, &expires, &t.MaxUses, &t.Uses, &revoked,
		&ephemeral, &ttl, &t.Technician); err != nil {
		return t, err
	}
	t.Ephemeral, t.DeviceTTL = ephemeral != 0, time.Duration(ttl)
	if t.CreatedAt, err = parseTime(created); err != nil {
		return t, err
	}
	if t.ExpiresAt, err = parseTime(expires); err != nil {
		return t, err
	}
	t.RevokedAt, err = parseTimePtr(revoked)
	return t, err
}

// CreateToken stores a new enrollment token. t.Hash must be the
// model.HashSecret of the secret; the secret itself is never stored.
func (s *Store) CreateToken(ctx context.Context, t model.EnrollToken) error {
	if t.ID == "" || t.Hash == "" || t.MaxUses < 0 {
		return fmt.Errorf("store: enroll token: %w", model.ErrInvalid)
	}
	// A temporary install that could enroll twice, or outlive its window, is
	// not temporary. The invariant is enforced here, not only in the API.
	if err := t.ValidEphemeral(); err != nil {
		return fmt.Errorf("store: ephemeral token %s needs max_uses 1 and a device TTL of at most %s: %w",
			t.ID, model.MaxDeviceTTL, err)
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := clientExists(ctx, tx, t.Client); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO enroll_tokens
			(id, client, hash, note, created_at, expires_at, max_uses, uses, ephemeral, device_ttl_ns, technician)
			VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
			t.ID, t.Client, t.Hash, t.Note, fmtTime(t.CreatedAt), fmtTime(t.ExpiresAt), t.MaxUses,
			boolInt(t.Ephemeral), int64(t.DeviceTTL), t.Technician)
		if err != nil {
			return fmt.Errorf("store: create enroll token %s: %w", t.ID, err)
		}
		return nil
	})
}

// TokenBySecret resolves an enrollment token by the hash of its secret, for
// the pre-enrolment offer. An unknown secret is ErrNotFound; callers check
// EnrollToken.Usable. Nothing here stores or logs the secret.
func (s *Store) TokenBySecret(ctx context.Context, secret string) (model.EnrollToken, error) {
	t, err := scanToken(s.db.QueryRowContext(ctx,
		"SELECT "+tokenCols+" FROM enroll_tokens WHERE hash = ?", model.HashSecret(secret)))
	if errors.Is(err, sql.ErrNoRows) {
		return model.EnrollToken{}, fmt.Errorf("store: enroll token: %w", model.ErrNotFound)
	} else if err != nil {
		return model.EnrollToken{}, fmt.Errorf("store: enroll token: %w", err)
	}
	return t, nil
}

// Token returns an enrollment token by ID, or ErrNotFound.
func (s *Store) Token(ctx context.Context, id string) (model.EnrollToken, error) {
	t, err := scanToken(s.db.QueryRowContext(ctx, "SELECT "+tokenCols+" FROM enroll_tokens WHERE id = ?", id))
	if err != nil {
		return model.EnrollToken{}, lookupErr("enroll token", id, err)
	}
	return t, nil
}

// Tokens returns a client's enrollment tokens, oldest first.
func (s *Store) Tokens(ctx context.Context, client string) ([]model.EnrollToken, error) {
	return queryAll(ctx, s.db, scanToken,
		"SELECT "+tokenCols+" FROM enroll_tokens WHERE client = ? ORDER BY created_at, id", client)
}

// RevokeToken revokes an enrollment token; revoking it again keeps the first
// revocation time.
func (s *Store) RevokeToken(ctx context.Context, id string, at time.Time) (model.EnrollToken, error) {
	res, err := s.db.ExecContext(ctx,
		"UPDATE enroll_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?", fmtTime(at), id)
	if err := mustAffect(res, err, "enroll token", id); err != nil {
		return model.EnrollToken{}, err
	}
	return s.Token(ctx, id)
}

// ----- devices -----

const deviceCols = "id, client, public_key, hostname, machine_id, os, os_version, arch, agent_version, " +
	"enrolled_at, enroll_token_id, last_seen, revoked_at, ephemeral, expires_at"

func scanDevice(r row) (model.Device, error) {
	var (
		d                 model.Device
		enrolled          string
		lastSeen, revoked sql.NullString
		expires           sql.NullString
		ephemeral         int
		err               error
	)
	if err = r.Scan(&d.ID, &d.Client, &d.PublicKey, &d.Hostname, &d.MachineID, &d.OS, &d.OSVersion, &d.Arch,
		&d.AgentVersion, &enrolled, &d.EnrollTokenID, &lastSeen, &revoked, &ephemeral, &expires); err != nil {
		return d, err
	}
	if d.EnrolledAt, err = parseTime(enrolled); err != nil {
		return d, err
	}
	if d.LastSeen, err = parseTimePtr(lastSeen); err != nil {
		return d, err
	}
	if d.RevokedAt, err = parseTimePtr(revoked); err != nil {
		return d, err
	}
	d.Ephemeral = ephemeral != 0
	d.ExpiresAt, err = parseTimePtr(expires)
	return d, err
}

// Device returns a device by ID, or ErrNotFound.
func (s *Store) Device(ctx context.Context, id string) (model.Device, error) {
	d, err := scanDevice(s.db.QueryRowContext(ctx, "SELECT "+deviceCols+" FROM devices WHERE id = ?", id))
	if err != nil {
		return model.Device{}, lookupErr("device", id, err)
	}
	return d, nil
}

// Devices returns every device of a client, revoked ones included, in
// enrollment order.
func (s *Store) Devices(ctx context.Context, client string) ([]model.Device, error) {
	return queryAll(ctx, s.db, scanDevice,
		"SELECT "+deviceCols+" FROM devices WHERE client = ? ORDER BY enrolled_at, id", client)
}

// RevokeDevice marks a device revoked; revoking it again keeps the first
// revocation time. It does not touch NATS: the caller must also revoke the
// device's key in the client's account JWT.
func (s *Store) RevokeDevice(ctx context.Context, id string, at time.Time) (model.Device, error) {
	res, err := s.db.ExecContext(ctx,
		"UPDATE devices SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?", fmtTime(at), id)
	if err := mustAffect(res, err, "device", id); err != nil {
		return model.Device{}, err
	}
	return s.Device(ctx, id)
}

// RevokeDeviceOwned revokes a live device that belongs to client. An unknown
// device, another client's device, or one already revoked is ErrNotFound, so
// an endpoint's self-revocation can never reach outside its own account.
func (s *Store) RevokeDeviceOwned(ctx context.Context, client, id string, at time.Time) (model.Device, error) {
	res, err := s.db.ExecContext(ctx,
		"UPDATE devices SET revoked_at = ? WHERE id = ? AND client = ? AND revoked_at IS NULL",
		fmtTime(at), id, client)
	if err := mustAffect(res, err, "device", id); err != nil {
		return model.Device{}, err
	}
	return s.Device(ctx, id)
}

// ExpireEphemeralDevices revokes every live temporary device whose deadline
// has passed and returns them, so the caller can push the revocations into
// the affected accounts and audit them. The relay, not the endpoint, is what
// makes a temporary install stop working: a machine that is switched off,
// killed or offline at its deadline is revoked all the same.
func (s *Store) ExpireEphemeralDevices(ctx context.Context, now time.Time) ([]model.Device, error) {
	var out []model.Device
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		due, err := queryAll(ctx, tx, scanDevice, "SELECT "+deviceCols+` FROM devices
			WHERE ephemeral = 1 AND revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?
			ORDER BY expires_at, id`, fmtTime(now))
		if err != nil || len(due) == 0 {
			return err
		}
		at := now.UTC()
		for i := range due {
			if _, err := tx.ExecContext(ctx, "UPDATE devices SET revoked_at = ? WHERE id = ?",
				fmtTime(at), due[i].ID); err != nil {
				return fmt.Errorf("store: expire device %s: %w", due[i].ID, err)
			}
			due[i].RevokedAt = &at
		}
		out = due
		return nil
	})
	return out, err
}

// TouchDevice records that a live device of client was heard from at at.
// An unknown, revoked or other client's device is ErrNotFound.
func (s *Store) TouchDevice(ctx context.Context, client, id string, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		"UPDATE devices SET last_seen = ? WHERE id = ? AND client = ? AND revoked_at IS NULL",
		fmtTime(at), id, client)
	return mustAffect(res, err, "device", id)
}

// DeviceInfo is what a device reports about itself on every (re)connect.
// The OS is fixed at enrollment, because it selects the device's policy.
type DeviceInfo struct {
	Hostname     string
	OSVersion    string
	Arch         string
	AgentVersion string
}

// UpdateDeviceInfo records a live device's self-description and marks it
// seen. Empty fields keep their stored values. An unknown, revoked or other
// client's device is ErrNotFound.
func (s *Store) UpdateDeviceInfo(ctx context.Context, client, id string, info DeviceInfo, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET
			hostname = COALESCE(NULLIF(?, ''), hostname),
			os_version = COALESCE(NULLIF(?, ''), os_version),
			arch = COALESCE(NULLIF(?, ''), arch),
			agent_version = COALESCE(NULLIF(?, ''), agent_version),
			last_seen = ?
		WHERE id = ? AND client = ? AND revoked_at IS NULL`,
		info.Hostname, info.OSVersion, info.Arch, info.AgentVersion, fmtTime(at), id, client)
	return mustAffect(res, err, "device", id)
}

// EnrollParams is one enrollment attempt.
type EnrollParams struct {
	Secret string       // the enrollment token as presented; only its hash is looked up
	Org    string       // optional; must equal the token's client when set
	Device model.Device // the new device: ID, PublicKey and the self-reported fields
	Now    time.Time
}

// Enrollment is the outcome of a successful EnrollDevice.
type Enrollment struct {
	Token    model.EnrollToken // as it stands after this use
	Device   model.Device
	Replaced []model.Device // the client's live devices with the same machine ID, now revoked
}

// EnrollDevice consumes one use of an enrollment token and records a new
// device, in one transaction, so a token can never be used more than its
// MaxUses. The token must be usable (else a wrapped ErrNotFound, ErrExpired,
// ErrRevoked or ErrExhausted), p.Org must match (ErrOrgMismatch), and the
// device's key must be new (ErrConflict). Live devices of the same client
// with the same machine ID are revoked; the caller must revoke their keys in
// NATS too.
func (s *Store) EnrollDevice(ctx context.Context, p EnrollParams) (Enrollment, error) {
	d := p.Device
	if d.ID == "" || d.PublicKey == "" {
		return Enrollment{}, fmt.Errorf("store: enroll: %w", model.ErrInvalid)
	}
	now := p.Now.UTC()
	var out Enrollment
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		tok, err := scanToken(tx.QueryRowContext(ctx,
			"SELECT "+tokenCols+" FROM enroll_tokens WHERE hash = ?", model.HashSecret(p.Secret)))
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: enroll token: %w", model.ErrNotFound)
		} else if err != nil {
			return fmt.Errorf("store: enroll token: %w", err)
		}
		if err := tok.Usable(now); err != nil {
			return fmt.Errorf("store: enroll token %s: %w", tok.ID, err)
		}
		if p.Org != "" && p.Org != tok.Client {
			return fmt.Errorf("store: enroll token %s: %w", tok.ID, ErrOrgMismatch)
		}
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM devices WHERE public_key = ? OR id = ?",
			d.PublicKey, d.ID).Scan(&n); err != nil {
			return fmt.Errorf("store: enroll: %w", err)
		}
		if n > 0 {
			return fmt.Errorf("store: enroll: device key already enrolled: %w", model.ErrConflict)
		}
		if d.MachineID != "" {
			// A temporary install replaces only earlier temporary installs on
			// the machine. The machine ID is self-reported, so an ephemeral
			// token must not be able to revoke a managed device by naming it.
			scope := ""
			if tok.Ephemeral {
				scope = " AND ephemeral = 1"
			}
			out.Replaced, err = queryAll(ctx, tx, scanDevice, "SELECT "+deviceCols+
				" FROM devices WHERE client = ? AND machine_id = ? AND revoked_at IS NULL"+scope+" ORDER BY enrolled_at, id",
				tok.Client, d.MachineID)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				"UPDATE devices SET revoked_at = ? WHERE client = ? AND machine_id = ? AND revoked_at IS NULL"+scope,
				fmtTime(now), tok.Client, d.MachineID); err != nil {
				return fmt.Errorf("store: enroll: revoke replaced devices: %w", err)
			}
			for i := range out.Replaced {
				out.Replaced[i].RevokedAt = &now
			}
		}
		d.Client, d.EnrolledAt, d.EnrollTokenID, d.LastSeen, d.RevokedAt = tok.Client, now, tok.ID, nil, nil
		// An ephemeral token's device carries its own deadline from the
		// moment it enrolls. Nothing on the endpoint can extend it.
		d.Ephemeral, d.ExpiresAt = tok.Ephemeral, nil
		if tok.Ephemeral {
			exp := now.Add(tok.DeviceTTL)
			d.ExpiresAt = &exp
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO devices
			(id, client, public_key, hostname, machine_id, os, os_version, arch, agent_version, enrolled_at,
			 enroll_token_id, ephemeral, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			d.ID, d.Client, d.PublicKey, d.Hostname, d.MachineID, d.OS, d.OSVersion, d.Arch, d.AgentVersion,
			fmtTime(d.EnrolledAt), d.EnrollTokenID, boolInt(d.Ephemeral), fmtTimePtr(d.ExpiresAt))
		if err != nil {
			return fmt.Errorf("store: enroll: insert device: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE enroll_tokens SET uses = uses + 1 WHERE id = ?", tok.ID); err != nil {
			return fmt.Errorf("store: enroll: count token use: %w", err)
		}
		tok.Uses++
		out.Token, out.Device = tok, d
		return nil
	})
	if err != nil {
		return Enrollment{}, err
	}
	return out, nil
}

// ----- sessions -----

const sessionCols = "id, client, tech, hash, note, created_at, expires_at, revoked_at"

func scanSession(r row) (model.Session, error) {
	var (
		ses              model.Session
		created, expires string
		revoked          sql.NullString
		err              error
	)
	if err = r.Scan(&ses.ID, &ses.Client, &ses.Tech, &ses.Hash, &ses.Note, &created, &expires, &revoked); err != nil {
		return ses, err
	}
	if ses.CreatedAt, err = parseTime(created); err != nil {
		return ses, err
	}
	if ses.ExpiresAt, err = parseTime(expires); err != nil {
		return ses, err
	}
	ses.RevokedAt, err = parseTimePtr(revoked)
	return ses, err
}

// CreateSession stores a new MCP session. ses.Hash must be the
// model.HashSecret of the bearer; the bearer itself is never stored.
func (s *Store) CreateSession(ctx context.Context, ses model.Session) error {
	if ses.ID == "" || ses.Hash == "" || ses.Tech == "" {
		return fmt.Errorf("store: session: %w", model.ErrInvalid)
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := clientExists(ctx, tx, ses.Client); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO sessions
			(id, client, tech, hash, note, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			ses.ID, ses.Client, ses.Tech, ses.Hash, ses.Note, fmtTime(ses.CreatedAt), fmtTime(ses.ExpiresAt))
		if err != nil {
			return fmt.Errorf("store: create session %s: %w", ses.ID, err)
		}
		return nil
	})
}

// SessionByToken resolves an MCP bearer secret by its hash. An unknown
// bearer is ErrNotFound; callers check Session.Valid.
func (s *Store) SessionByToken(ctx context.Context, bearer string) (model.Session, error) {
	ses, err := scanSession(s.db.QueryRowContext(ctx,
		"SELECT "+sessionCols+" FROM sessions WHERE hash = ?", model.HashSecret(bearer)))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Session{}, fmt.Errorf("store: session: %w", model.ErrNotFound)
	} else if err != nil {
		return model.Session{}, fmt.Errorf("store: session: %w", err)
	}
	return ses, nil
}

// Session returns a session by ID, or ErrNotFound.
func (s *Store) Session(ctx context.Context, id string) (model.Session, error) {
	ses, err := scanSession(s.db.QueryRowContext(ctx, "SELECT "+sessionCols+" FROM sessions WHERE id = ?", id))
	if err != nil {
		return model.Session{}, lookupErr("session", id, err)
	}
	return ses, nil
}

// Sessions returns a client's sessions, oldest first.
func (s *Store) Sessions(ctx context.Context, client string) ([]model.Session, error) {
	return queryAll(ctx, s.db, scanSession,
		"SELECT "+sessionCols+" FROM sessions WHERE client = ? ORDER BY created_at, id", client)
}

// RevokeSession revokes a session; revoking it again keeps the first
// revocation time.
func (s *Store) RevokeSession(ctx context.Context, id string, at time.Time) (model.Session, error) {
	res, err := s.db.ExecContext(ctx,
		"UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?", fmtTime(at), id)
	if err := mustAffect(res, err, "session", id); err != nil {
		return model.Session{}, err
	}
	return s.Session(ctx, id)
}

// ----- consented access -----

// GrantTechnicianClient adds one durable technician-to-client authorization.
// ACL administration is intentionally kept out of the MCP surface.
func (s *Store) GrantTechnicianClient(ctx context.Context, technician, client string, at time.Time) error {
	technician = strings.TrimSpace(technician)
	if technician == "" || client == "" {
		return fmt.Errorf("store: technician acl: %w", model.ErrInvalid)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO technician_client_acl (technician, client, created_at)
		VALUES (?, ?, ?) ON CONFLICT (technician, client) DO NOTHING`, technician, client, fmtTime(at))
	if err != nil {
		return fmt.Errorf("store: grant technician %q client %q: %w", technician, client, err)
	}
	return nil
}

// RevokeTechnicianClient removes one authorization. Revocation takes effect on
// the technician's next MCP call because the gateway rechecks this table.
func (s *Store) RevokeTechnicianClient(ctx context.Context, technician, client string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM technician_client_acl WHERE technician = ? AND client = ?", technician, client)
	return mustAffect(res, err, "technician acl", technician+"/"+client)
}

func (s *Store) TechnicianCanAccess(ctx context.Context, technician, client string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, "SELECT 1 FROM technician_client_acl WHERE technician = ? AND client = ?", technician, client).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: technician acl: %w", err)
	}
	return true, nil
}

func (s *Store) ClientsForTechnician(ctx context.Context, technician string) ([]model.Client, error) {
	return queryAll(ctx, s.db, scanClient, `SELECT c.slug, c.name, c.account_key, c.disabled, c.created_at, c.policy FROM clients c
		JOIN technician_client_acl a ON a.client = c.slug
		WHERE a.technician = ? ORDER BY c.name, c.slug`, technician)
}

func (s *Store) CreateAccess(ctx context.Context, a model.AccessRequest) error {
	if a.ID == "" || a.Client == "" || a.Device == "" || a.Technician == "" || a.Session == "" || a.State == "" {
		return fmt.Errorf("store: access: %w", model.ErrInvalid)
	}
	rs, _ := json.Marshal(a.RequestedScope)
	es, _ := json.Marshal(a.EffectiveScope)
	ro, _ := json.Marshal(a.RequestedOperations)
	eo, _ := json.Marshal(a.EffectiveOperations)
	_, err := s.db.ExecContext(ctx, `INSERT INTO access_requests
		(id,client,device,technician,session,purpose,state,requested_scope,effective_scope,requested_operations,effective_operations,requested_at,expires_at,idle_timeout_ns,grant_id,nonce,approver,reason,policy_version,decided_at,terminated_at,approver_session,consent_deadline,paused_at,event_seq,plan_digest,unlock,endpoint_consent)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, a.ID, a.Client, a.Device, a.Technician, a.Session, a.Purpose, a.State, string(rs), string(es), string(ro), string(eo), fmtTime(a.RequestedAt), fmtTime(a.ExpiresAt), int64(a.IdleTimeout), a.GrantID, a.Nonce, a.Approver, a.Reason, a.PolicyVersion, fmtTimePtr(a.DecidedAt), fmtTimePtr(a.TerminatedAt), a.ApproverSession, fmtTimePtr(a.ConsentDeadline), fmtTimePtr(a.PausedAt), int64(a.EventSeq), a.PlanDigest, a.Unlock, boolInt(a.EndpointConsent))
	if err != nil {
		return fmt.Errorf("store: create access %s: %w", a.ID, err)
	}
	return nil
}

func scanAccess(r row) (model.AccessRequest, error) {
	var a model.AccessRequest
	var rs, es, ro, eo, requested, expires string
	var decided, terminated, deadline, paused sql.NullString
	var idle, seq, endpointConsent int64
	err := r.Scan(&a.ID, &a.Client, &a.Device, &a.Technician, &a.Session, &a.Purpose, &a.State, &rs, &es, &ro, &eo, &requested, &expires, &idle, &a.GrantID, &a.Nonce, &a.Approver, &a.Reason, &a.PolicyVersion, &decided, &terminated, &a.ApproverSession, &deadline, &paused, &seq, &a.PlanDigest, &a.Unlock, &endpointConsent)
	if err != nil {
		return a, err
	}
	a.EventSeq, a.EndpointConsent = uint64(seq), endpointConsent != 0
	if err = json.Unmarshal([]byte(rs), &a.RequestedScope); err != nil {
		return a, err
	}
	if err = json.Unmarshal([]byte(es), &a.EffectiveScope); err != nil {
		return a, err
	}
	if err = json.Unmarshal([]byte(ro), &a.RequestedOperations); err != nil {
		return a, err
	}
	if err = json.Unmarshal([]byte(eo), &a.EffectiveOperations); err != nil {
		return a, err
	}
	if a.RequestedAt, err = parseTime(requested); err != nil {
		return a, err
	}
	if a.ExpiresAt, err = parseTime(expires); err != nil {
		return a, err
	}
	a.IdleTimeout = time.Duration(idle)
	if a.DecidedAt, err = parseTimePtr(decided); err != nil {
		return a, err
	}
	if a.ConsentDeadline, err = parseTimePtr(deadline); err != nil {
		return a, err
	}
	if a.PausedAt, err = parseTimePtr(paused); err != nil {
		return a, err
	}
	a.TerminatedAt, err = parseTimePtr(terminated)
	return a, err
}

const accessCols = "id,client,device,technician,session,purpose,state,requested_scope,effective_scope,requested_operations,effective_operations,requested_at,expires_at,idle_timeout_ns,grant_id,nonce,approver,reason,policy_version,decided_at,terminated_at,approver_session,consent_deadline,paused_at,event_seq,plan_digest,unlock,endpoint_consent"

func (s *Store) Access(ctx context.Context, id string) (model.AccessRequest, error) {
	a, err := scanAccess(s.db.QueryRowContext(ctx, "SELECT "+accessCols+" FROM access_requests WHERE id = ?", id))
	if err != nil {
		return a, lookupErr("access", id, err)
	}
	return a, nil
}

func (s *Store) UpdateAccess(ctx context.Context, a model.AccessRequest) error {
	return s.updateAccess(ctx, s.db, a)
}

// updateAccess writes an access request's mutable fields. The idle timeout is
// one of them because a request that waited for a technician unlock reaches
// its endpoint with less of its lifetime left than it was made with, and its
// idle timeout must then shrink to fit.
func (s *Store) updateAccess(ctx context.Context, q querier, a model.AccessRequest) error {
	es, _ := json.Marshal(a.EffectiveScope)
	eo, _ := json.Marshal(a.EffectiveOperations)
	res, err := q.ExecContext(ctx, `UPDATE access_requests SET state=?,effective_scope=?,effective_operations=?,expires_at=?,idle_timeout_ns=?,grant_id=?,nonce=?,approver=?,reason=?,decided_at=?,terminated_at=?,approver_session=?,consent_deadline=?,paused_at=?,event_seq=?,plan_digest=?,unlock=?,endpoint_consent=? WHERE id=?`, a.State, string(es), string(eo), fmtTime(a.ExpiresAt), int64(a.IdleTimeout), a.GrantID, a.Nonce, a.Approver, a.Reason, fmtTimePtr(a.DecidedAt), fmtTimePtr(a.TerminatedAt), a.ApproverSession, fmtTimePtr(a.ConsentDeadline), fmtTimePtr(a.PausedAt), int64(a.EventSeq), a.PlanDigest, a.Unlock, boolInt(a.EndpointConsent), a.ID)
	return mustAffect(res, err, "access", a.ID)
}

// UpdateAccessTx applies fn to one access request under a transaction, so a
// consent event from the endpoint and a gateway update cannot interleave and
// lose each other's transition. fn returns model.ErrConflict to leave the
// row untouched; the stored request is returned either way.
func (s *Store) UpdateAccessTx(ctx context.Context, id string, fn func(*model.AccessRequest) error) (model.AccessRequest, error) {
	var out model.AccessRequest
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		a, err := scanAccess(tx.QueryRowContext(ctx, "SELECT "+accessCols+" FROM access_requests WHERE id = ?", id))
		if err != nil {
			return lookupErr("access", id, err)
		}
		out = a
		if err := fn(&a); err != nil {
			return err
		}
		out = a
		return s.updateAccess(ctx, tx, a)
	})
	return out, err
}

// ----- admin token and kv -----

// SetAdminTokenHash replaces the admin API token's hash.
func (s *Store) SetAdminTokenHash(ctx context.Context, hash string, at time.Time) error {
	if hash == "" {
		return fmt.Errorf("store: admin token: %w", model.ErrInvalid)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_token (id, hash, created_at) VALUES (1, ?, ?)
		ON CONFLICT (id) DO UPDATE SET hash = excluded.hash, created_at = excluded.created_at`, hash, fmtTime(at))
	if err != nil {
		return fmt.Errorf("store: admin token: %w", err)
	}
	return nil
}

// AdminTokenHash returns the admin API token's hash, or ErrNotFound if none
// is set.
func (s *Store) AdminTokenHash(ctx context.Context) (string, error) {
	var h string
	if err := s.db.QueryRowContext(ctx, "SELECT hash FROM admin_token WHERE id = 1").Scan(&h); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = model.ErrNotFound
		}
		return "", fmt.Errorf("store: admin token: %w", err)
	}
	return h, nil
}

// KV returns a value from the key-value table, or ErrNotFound.
func (s *Store) KV(ctx context.Context, key string) (string, error) {
	var v string
	if err := s.db.QueryRowContext(ctx, "SELECT value FROM kv WHERE key = ?", key).Scan(&v); err != nil {
		return "", lookupErr("kv", key, err)
	}
	return v, nil
}

// SetKV sets a value in the key-value table.
func (s *Store) SetKV(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value", key, value)
	if err != nil {
		return fmt.Errorf("store: kv %q: %w", key, err)
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func fmtTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return fmtTime(*t)
}
