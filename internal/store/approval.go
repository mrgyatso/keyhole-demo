package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// ----- technician approval (Slice 6) -----

var _ model.ApprovalStore = (*Store)(nil)

// inStates renders one placeholder per state for an IN clause, with the
// states as its arguments.
func inStates(states []string) (string, []any) {
	marks := strings.TrimSuffix(strings.Repeat("?,", len(states)), ",")
	args := make([]any, len(states))
	for i, s := range states {
		args[i] = s
	}
	return marks, args
}

// jsonList stores a string list; nil is the empty list.
func jsonList(v []string) string {
	if v == nil {
		return "[]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// nullBytes stores an empty blob as NULL.
func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// ----- passkeys and their enrollment links -----

const passkeyLinkCols = "id, technician, hash, created_at, expires_at, used_at"

func scanPasskeyLink(r row) (model.PasskeyLink, error) {
	var (
		l                model.PasskeyLink
		created, expires string
		used             sql.NullString
	)
	if err := r.Scan(&l.ID, &l.Technician, &l.Hash, &created, &expires, &used); err != nil {
		return l, err
	}
	var err error
	if l.CreatedAt, err = parseTime(created); err != nil {
		return l, err
	}
	if l.ExpiresAt, err = parseTime(expires); err != nil {
		return l, err
	}
	l.UsedAt, err = parseTimePtr(used)
	return l, err
}

// CreatePasskeyLink stores a one-time enrollment link. l.Hash must be the
// model.HashSecret of the link's secret; the secret itself is never stored.
func (s *Store) CreatePasskeyLink(ctx context.Context, l model.PasskeyLink) error {
	if l.ID == "" || l.Hash == "" || strings.TrimSpace(l.Technician) == "" || !l.CreatedAt.Before(l.ExpiresAt) {
		return fmt.Errorf("store: passkey link: %w", model.ErrInvalid)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO passkey_links (id, technician, hash, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`, l.ID, l.Technician, l.Hash, fmtTime(l.CreatedAt), fmtTime(l.ExpiresAt))
	if err != nil {
		return fmt.Errorf("store: create passkey link %s: %w", l.ID, err)
	}
	return nil
}

// PasskeyLinkByToken resolves a one-time enrollment secret by its hash, if
// the link can still be used at now.
func (s *Store) PasskeyLinkByToken(ctx context.Context, secret string, now time.Time) (model.PasskeyLink, error) {
	l, err := scanPasskeyLink(s.db.QueryRowContext(ctx,
		"SELECT "+passkeyLinkCols+" FROM passkey_links WHERE hash = ?", model.HashSecret(secret)))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return model.PasskeyLink{}, fmt.Errorf("store: passkey link: %w", model.ErrNotFound)
	case err != nil:
		return model.PasskeyLink{}, fmt.Errorf("store: passkey link: %w", err)
	}
	if err := l.Usable(now); err != nil {
		return l, fmt.Errorf("store: passkey link %q: %w", l.ID, err)
	}
	return l, nil
}

// UsePasskeyLink consumes a link and stores the passkey it enrolled in one
// transaction, so a link enrolls exactly one passkey, for its own technician.
func (s *Store) UsePasskeyLink(ctx context.Context, linkID string, p model.Passkey, now time.Time) error {
	if p.CredentialID == "" || len(p.PublicKey) == 0 || p.Algorithm == 0 {
		return fmt.Errorf("store: passkey: %w", model.ErrInvalid)
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		l, err := scanPasskeyLink(tx.QueryRowContext(ctx, "SELECT "+passkeyLinkCols+" FROM passkey_links WHERE id = ?", linkID))
		if err != nil {
			return lookupErr("passkey link", linkID, err)
		}
		if err := l.Usable(now); err != nil {
			return fmt.Errorf("store: passkey link %q: %w", linkID, err)
		}
		if p.Technician != l.Technician {
			return fmt.Errorf("store: passkey link %q enrolls another technician: %w", linkID, model.ErrInvalid)
		}
		var one int
		switch err := tx.QueryRowContext(ctx, "SELECT 1 FROM passkeys WHERE credential_id = ?", p.CredentialID).Scan(&one); {
		case err == nil:
			return fmt.Errorf("store: passkey already enrolled: %w", model.ErrConflict)
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("store: passkey: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE passkey_links SET used_at = ? WHERE id = ?", fmtTime(now), linkID); err != nil {
			return fmt.Errorf("store: use passkey link %q: %w", linkID, err)
		}
		created := p.CreatedAt
		if created.IsZero() {
			created = now
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO passkeys (credential_id, technician, public_key, algorithm, sign_count, name, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, p.CredentialID, p.Technician, p.PublicKey, p.Algorithm, int64(p.SignCount), p.Name, fmtTime(created))
		if err != nil {
			return fmt.Errorf("store: create passkey: %w", err)
		}
		return nil
	})
}

const passkeyCols = "credential_id, technician, public_key, algorithm, sign_count, name, created_at, last_used_at, revoked_at"

func scanPasskey(r row) (model.Passkey, error) {
	var (
		p             model.Passkey
		count         int64
		created       string
		used, revoked sql.NullString
	)
	if err := r.Scan(&p.CredentialID, &p.Technician, &p.PublicKey, &p.Algorithm, &count, &p.Name, &created, &used, &revoked); err != nil {
		return p, err
	}
	p.SignCount = uint32(count)
	var err error
	if p.CreatedAt, err = parseTime(created); err != nil {
		return p, err
	}
	if p.LastUsedAt, err = parseTimePtr(used); err != nil {
		return p, err
	}
	p.RevokedAt, err = parseTimePtr(revoked)
	return p, err
}

// Passkey returns a passkey by credential ID, or ErrNotFound. Revoked
// passkeys are returned too; callers check Passkey.Live.
func (s *Store) Passkey(ctx context.Context, credentialID string) (model.Passkey, error) {
	p, err := scanPasskey(s.db.QueryRowContext(ctx, "SELECT "+passkeyCols+" FROM passkeys WHERE credential_id = ?", credentialID))
	if err != nil {
		return model.Passkey{}, lookupErr("passkey", credentialID, err)
	}
	return p, nil
}

// PasskeysForTechnician returns every passkey of a technician, oldest first.
func (s *Store) PasskeysForTechnician(ctx context.Context, technician string) ([]model.Passkey, error) {
	return queryAll(ctx, s.db, scanPasskey,
		"SELECT "+passkeyCols+" FROM passkeys WHERE technician = ? ORDER BY created_at, credential_id", technician)
}

// TouchPasskey records a verified assertion.
func (s *Store) TouchPasskey(ctx context.Context, credentialID string, signCount uint32, at time.Time) error {
	res, err := s.db.ExecContext(ctx, "UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE credential_id = ?",
		int64(signCount), fmtTime(at), credentialID)
	return mustAffect(res, err, "passkey", credentialID)
}

// RevokePasskey revokes a passkey; revoking it again keeps the first time.
func (s *Store) RevokePasskey(ctx context.Context, credentialID string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, "UPDATE passkeys SET revoked_at = COALESCE(revoked_at, ?) WHERE credential_id = ?",
		fmtTime(at), credentialID)
	return mustAffect(res, err, "passkey", credentialID)
}

// ----- companion sign-ins -----

const companionCols = "id, technician, credential, hash, created_at, expires_at, revoked_at"

func scanCompanionSession(r row) (model.CompanionSession, error) {
	var (
		cs               model.CompanionSession
		created, expires string
		revoked          sql.NullString
	)
	if err := r.Scan(&cs.ID, &cs.Technician, &cs.Credential, &cs.Hash, &created, &expires, &revoked); err != nil {
		return cs, err
	}
	var err error
	if cs.CreatedAt, err = parseTime(created); err != nil {
		return cs, err
	}
	if cs.ExpiresAt, err = parseTime(expires); err != nil {
		return cs, err
	}
	cs.RevokedAt, err = parseTimePtr(revoked)
	return cs, err
}

// CreateCompanionSession stores a sign-in. cs.Hash must be the
// model.HashSecret of the cookie secret.
func (s *Store) CreateCompanionSession(ctx context.Context, cs model.CompanionSession) error {
	if cs.ID == "" || cs.Hash == "" || strings.TrimSpace(cs.Technician) == "" || cs.Credential == "" || !cs.CreatedAt.Before(cs.ExpiresAt) {
		return fmt.Errorf("store: companion session: %w", model.ErrInvalid)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO companion_sessions (id, technician, credential, hash, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, cs.ID, cs.Technician, cs.Credential, cs.Hash, fmtTime(cs.CreatedAt), fmtTime(cs.ExpiresAt))
	if err != nil {
		return fmt.Errorf("store: create companion session %s: %w", cs.ID, err)
	}
	return nil
}

// CompanionSessionByToken resolves a sign-in cookie secret by its hash. An
// unknown secret is ErrNotFound; callers check CompanionSession.Valid.
func (s *Store) CompanionSessionByToken(ctx context.Context, secret string) (model.CompanionSession, error) {
	cs, err := scanCompanionSession(s.db.QueryRowContext(ctx,
		"SELECT "+companionCols+" FROM companion_sessions WHERE hash = ?", model.HashSecret(secret)))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return model.CompanionSession{}, fmt.Errorf("store: companion session: %w", model.ErrNotFound)
	case err != nil:
		return model.CompanionSession{}, fmt.Errorf("store: companion session: %w", err)
	}
	return cs, nil
}

// RevokeCompanionSessions revokes every live sign-in of a technician.
func (s *Store) RevokeCompanionSessions(ctx context.Context, technician string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE companion_sessions SET revoked_at = ? WHERE technician = ? AND revoked_at IS NULL",
		fmtTime(at), technician)
	if err != nil {
		return fmt.Errorf("store: revoke companion sessions: %w", err)
	}
	return nil
}

// ----- unlocks -----

const unlockCols = "id, technician, client, session, purpose, state, duration_ns, idle_timeout_ns, requested_at, deadline, nonce, expires_at, decided_at, last_used_at, ended_at, reason, credential, assertion, calls, devices"

func scanUnlock(r row) (model.Unlock, error) {
	var (
		u                            model.Unlock
		duration, idle               int64
		requested, deadline, devices string
		expires, decided, used, end  sql.NullString
		assertion                    []byte
	)
	if err := r.Scan(&u.ID, &u.Technician, &u.Client, &u.Session, &u.Purpose, &u.State, &duration, &idle, &requested,
		&deadline, &u.Nonce, &expires, &decided, &used, &end, &u.Reason, &u.Credential, &assertion, &u.Calls, &devices); err != nil {
		return u, err
	}
	u.Duration, u.IdleTimeout = time.Duration(duration), time.Duration(idle)
	if len(assertion) > 0 {
		u.Assertion = assertion
	}
	var err error
	if u.RequestedAt, err = parseTime(requested); err != nil {
		return u, err
	}
	if u.Deadline, err = parseTime(deadline); err != nil {
		return u, err
	}
	if u.ExpiresAt, err = parseTimePtr(expires); err != nil {
		return u, err
	}
	if u.DecidedAt, err = parseTimePtr(decided); err != nil {
		return u, err
	}
	if u.LastUsedAt, err = parseTimePtr(used); err != nil {
		return u, err
	}
	if u.EndedAt, err = parseTimePtr(end); err != nil {
		return u, err
	}
	return u, json.Unmarshal([]byte(devices), &u.Devices)
}

// CreateUnlock stores a new unlock.
func (s *Store) CreateUnlock(ctx context.Context, u model.Unlock) error {
	if u.ID == "" || strings.TrimSpace(u.Technician) == "" || u.Client == "" || u.Session == "" || u.State == "" ||
		u.Duration <= 0 || u.Duration > model.MaxUnlockDuration || u.IdleTimeout < 0 || u.RequestedAt.IsZero() || u.Deadline.IsZero() {
		return fmt.Errorf("store: unlock: %w", model.ErrInvalid)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO unlocks (`+unlockCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Technician, u.Client, u.Session, u.Purpose, u.State, int64(u.Duration), int64(u.IdleTimeout),
		fmtTime(u.RequestedAt), fmtTime(u.Deadline), u.Nonce, fmtTimePtr(u.ExpiresAt), fmtTimePtr(u.DecidedAt),
		fmtTimePtr(u.LastUsedAt), fmtTimePtr(u.EndedAt), u.Reason, u.Credential, nullBytes(u.Assertion), u.Calls, jsonList(u.Devices))
	if err != nil {
		return fmt.Errorf("store: create unlock %s: %w", u.ID, err)
	}
	return nil
}

// Unlock returns an unlock by ID, or ErrNotFound.
func (s *Store) Unlock(ctx context.Context, id string) (model.Unlock, error) {
	u, err := scanUnlock(s.db.QueryRowContext(ctx, "SELECT "+unlockCols+" FROM unlocks WHERE id = ?", id))
	if err != nil {
		return model.Unlock{}, lookupErr("unlock", id, err)
	}
	return u, nil
}

// updateUnlock writes an unlock's mutable fields. Who it belongs to, what it
// is for and how long it may last never change after it is created.
func (s *Store) updateUnlock(ctx context.Context, q querier, u model.Unlock) error {
	res, err := q.ExecContext(ctx, `UPDATE unlocks SET state = ?, nonce = ?, expires_at = ?, decided_at = ?, last_used_at = ?,
		ended_at = ?, reason = ?, credential = ?, assertion = ?, calls = ?, devices = ? WHERE id = ?`,
		u.State, u.Nonce, fmtTimePtr(u.ExpiresAt), fmtTimePtr(u.DecidedAt), fmtTimePtr(u.LastUsedAt), fmtTimePtr(u.EndedAt),
		u.Reason, u.Credential, nullBytes(u.Assertion), u.Calls, jsonList(u.Devices), u.ID)
	return mustAffect(res, err, "unlock", u.ID)
}

// UpdateUnlockTx applies fn to an unlock under a transaction. fn returns an
// error wrapping model.ErrConflict to leave the row untouched; the stored
// unlock is returned either way.
func (s *Store) UpdateUnlockTx(ctx context.Context, id string, fn func(*model.Unlock) error) (model.Unlock, error) {
	var out model.Unlock
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		u, err := scanUnlock(tx.QueryRowContext(ctx, "SELECT "+unlockCols+" FROM unlocks WHERE id = ?", id))
		if err != nil {
			return lookupErr("unlock", id, err)
		}
		out = u
		if err := fn(&u); err != nil {
			return err
		}
		out = u
		return s.updateUnlock(ctx, tx, u)
	})
	return out, err
}

// ActivateUnlockTx approves an unlock and locks every other active unlock of
// the same technician in the same transaction, so a technician never holds
// two clients open at once.
func (s *Store) ActivateUnlockTx(ctx context.Context, id string, fn func(*model.Unlock) error, now time.Time) (model.Unlock, []model.Unlock, error) {
	var (
		out    model.Unlock
		locked []model.Unlock
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		locked = nil
		u, err := scanUnlock(tx.QueryRowContext(ctx, "SELECT "+unlockCols+" FROM unlocks WHERE id = ?", id))
		if err != nil {
			return lookupErr("unlock", id, err)
		}
		out = u
		if err := fn(&u); err != nil {
			return err
		}
		if u.State != model.UnlockActive {
			return fmt.Errorf("store: activating unlock %q left it %s: %w", id, u.State, model.ErrInvalid)
		}
		if err := s.updateUnlock(ctx, tx, u); err != nil {
			return err
		}
		others, err := queryAll(ctx, tx, scanUnlock, "SELECT "+unlockCols+" FROM unlocks WHERE technician = ? AND state = ? AND id != ?",
			u.Technician, model.UnlockActive, u.ID)
		if err != nil {
			return err
		}
		ended := now.UTC()
		for _, o := range others {
			o.State, o.Reason, o.EndedAt = model.UnlockLocked, model.ReasonSwitched, &ended
			if err := s.updateUnlock(ctx, tx, o); err != nil {
				return err
			}
			locked = append(locked, o)
		}
		out = u
		return nil
	})
	if err != nil {
		locked = nil
	}
	return out, locked, err
}

// UnlockFor returns the technician's most recent unlock of client in one of
// states, or ErrNotFound.
func (s *Store) UnlockFor(ctx context.Context, technician, client string, states ...string) (model.Unlock, error) {
	if len(states) == 0 {
		return model.Unlock{}, fmt.Errorf("store: unlock: %w", model.ErrInvalid)
	}
	marks, args := inStates(states)
	u, err := scanUnlock(s.db.QueryRowContext(ctx, "SELECT "+unlockCols+" FROM unlocks WHERE technician = ? AND client = ? AND state IN ("+marks+
		") ORDER BY requested_at DESC, id DESC LIMIT 1", append([]any{technician, client}, args...)...))
	if err != nil {
		return model.Unlock{}, lookupErr("unlock", technician+"/"+client, err)
	}
	return u, nil
}

// Unlocks returns a technician's open unlocks and those requested at or after
// since, newest first.
func (s *Store) Unlocks(ctx context.Context, technician string, since time.Time) ([]model.Unlock, error) {
	return queryAll(ctx, s.db, scanUnlock, "SELECT "+unlockCols+` FROM unlocks WHERE technician = ?
		AND (requested_at >= ? OR state IN (?, ?)) ORDER BY requested_at DESC, id DESC`,
		technician, fmtTime(since), model.UnlockAwaiting, model.UnlockActive)
}

// UnlocksOpen returns every unlock awaiting approval or active.
func (s *Store) UnlocksOpen(ctx context.Context) ([]model.Unlock, error) {
	return queryAll(ctx, s.db, scanUnlock, "SELECT "+unlockCols+" FROM unlocks WHERE state IN (?, ?) ORDER BY requested_at, id",
		model.UnlockAwaiting, model.UnlockActive)
}

// RecordUnlockUse records one device call under an unlock.
func (s *Store) RecordUnlockUse(ctx context.Context, id string, a model.UnlockActivity) error {
	if a.Op == "" || a.Device == "" || a.Result == "" || a.Time.IsZero() {
		return fmt.Errorf("store: unlock activity: %w", model.ErrInvalid)
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		u, err := scanUnlock(tx.QueryRowContext(ctx, "SELECT "+unlockCols+" FROM unlocks WHERE id = ?", id))
		if err != nil {
			return lookupErr("unlock", id, err)
		}
		u.Calls++
		if !slices.Contains(u.Devices, a.Device) {
			u.Devices = append(u.Devices, a.Device)
		}
		if at := a.Time.UTC(); u.LastUsedAt == nil || at.After(*u.LastUsedAt) {
			u.LastUsedAt = &at
		}
		if err := s.updateUnlock(ctx, tx, u); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO unlock_activity (unlock, at, op, device, path, result, error_code, bytes)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, id, fmtTime(a.Time), a.Op, a.Device, a.Path, a.Result, a.ErrorCode, a.Bytes)
		if err != nil {
			return fmt.Errorf("store: unlock activity %q: %w", id, err)
		}
		return nil
	})
}

func scanUnlockActivity(r row) (model.UnlockActivity, error) {
	var (
		a  model.UnlockActivity
		at string
	)
	if err := r.Scan(&a.Unlock, &at, &a.Op, &a.Device, &a.Path, &a.Result, &a.ErrorCode, &a.Bytes); err != nil {
		return a, err
	}
	var err error
	a.Time, err = parseTime(at)
	return a, err
}

// UnlockActivity returns up to limit of an unlock's activity rows, newest
// first. A limit of zero or less means 100.
func (s *Store) UnlockActivity(ctx context.Context, id string, limit int) ([]model.UnlockActivity, error) {
	if limit <= 0 {
		limit = 100
	}
	return queryAll(ctx, s.db, scanUnlockActivity, `SELECT unlock, at, op, device, path, result, error_code, bytes
		FROM unlock_activity WHERE unlock = ? ORDER BY seq DESC LIMIT ?`, id, limit)
}

// AccessForUnlock returns the access requests made under or waiting for an
// unlock, oldest first.
func (s *Store) AccessForUnlock(ctx context.Context, unlockID string) ([]model.AccessRequest, error) {
	if unlockID == "" {
		return nil, fmt.Errorf("store: access for unlock: %w", model.ErrInvalid)
	}
	return queryAll(ctx, s.db, scanAccess,
		"SELECT "+accessCols+" FROM access_requests WHERE unlock = ? ORDER BY requested_at, id", unlockID)
}

// ----- change plans and change approvals -----

const changePlanCols = "plan_id, access_id, client, device, technician, digest, plan, prepared_at, expires_at"

func scanChangePlan(r row) (model.ChangePlanRecord, error) {
	var (
		p                       model.ChangePlanRecord
		plan, prepared, expires string
	)
	if err := r.Scan(&p.PlanID, &p.AccessID, &p.Client, &p.Device, &p.Technician, &p.Digest, &plan, &prepared, &expires); err != nil {
		return p, err
	}
	p.Plan = json.RawMessage(plan)
	var err error
	if p.PreparedAt, err = parseTime(prepared); err != nil {
		return p, err
	}
	p.ExpiresAt, err = parseTime(expires)
	return p, err
}

// CreateChangePlan stores the relay's display copy of a prepared plan.
func (s *Store) CreateChangePlan(ctx context.Context, p model.ChangePlanRecord) error {
	if p.PlanID == "" || p.AccessID == "" || p.Client == "" || p.Device == "" || p.Technician == "" || p.Digest == "" ||
		!json.Valid(p.Plan) || p.PreparedAt.IsZero() || !p.PreparedAt.Before(p.ExpiresAt) {
		return fmt.Errorf("store: change plan: %w", model.ErrInvalid)
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var one int
		switch err := tx.QueryRowContext(ctx, "SELECT 1 FROM change_plans WHERE plan_id = ?", p.PlanID).Scan(&one); {
		case err == nil:
			return fmt.Errorf("store: change plan %q: %w", p.PlanID, model.ErrConflict)
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("store: change plan: %w", err)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO change_plans (`+changePlanCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			p.PlanID, p.AccessID, p.Client, p.Device, p.Technician, p.Digest, string(p.Plan), fmtTime(p.PreparedAt), fmtTime(p.ExpiresAt))
		if err != nil {
			return fmt.Errorf("store: create change plan %s: %w", p.PlanID, err)
		}
		return nil
	})
}

// ChangePlan returns a plan record by plan ID, or ErrNotFound.
func (s *Store) ChangePlan(ctx context.Context, planID string) (model.ChangePlanRecord, error) {
	p, err := scanChangePlan(s.db.QueryRowContext(ctx, "SELECT "+changePlanCols+" FROM change_plans WHERE plan_id = ?", planID))
	if err != nil {
		return model.ChangePlanRecord{}, lookupErr("change plan", planID, err)
	}
	return p, nil
}

const changeApprovalCols = "id, op, technician, client, device, access_id, grant_id, session, plan_id, plan_digest, rollback_id, state, requested_at, expires_at, nonce, request_id, decided_at, completed_at, credential, assertion, reason, error_code, result"

func scanChangeApproval(r row) (model.ChangeApproval, error) {
	var (
		c                          model.ChangeApproval
		requested, expires, result string
		decided, completed         sql.NullString
		assertion                  []byte
	)
	if err := r.Scan(&c.ID, &c.Op, &c.Technician, &c.Client, &c.Device, &c.AccessID, &c.GrantID, &c.Session, &c.PlanID,
		&c.PlanDigest, &c.RollbackID, &c.State, &requested, &expires, &c.Nonce, &c.RequestID, &decided, &completed,
		&c.Credential, &assertion, &c.Reason, &c.ErrorCode, &result); err != nil {
		return c, err
	}
	if len(assertion) > 0 {
		c.Assertion = assertion
	}
	if result != "" {
		c.Result = json.RawMessage(result)
	}
	var err error
	if c.RequestedAt, err = parseTime(requested); err != nil {
		return c, err
	}
	if c.ExpiresAt, err = parseTime(expires); err != nil {
		return c, err
	}
	if c.DecidedAt, err = parseTimePtr(decided); err != nil {
		return c, err
	}
	c.CompletedAt, err = parseTimePtr(completed)
	return c, err
}

// CreateChangeApproval stores a submitted apply or rollback awaiting the
// technician.
func (s *Store) CreateChangeApproval(ctx context.Context, c model.ChangeApproval) error {
	switch {
	case c.ID == "" || c.Technician == "" || c.Client == "" || c.Device == "" || c.AccessID == "" || c.Session == "" ||
		c.PlanID == "" || c.PlanDigest == "" || c.State == "" || c.Nonce == "" || c.RequestID == "":
		return fmt.Errorf("store: change approval: %w", model.ErrInvalid)
	case c.Op != proto.OpApplyFileChange && c.Op != proto.OpRollbackFileChange:
		return fmt.Errorf("store: change approval for %q: %w", c.Op, model.ErrInvalid)
	case c.RequestedAt.IsZero() || !c.RequestedAt.Before(c.ExpiresAt):
		return fmt.Errorf("store: change approval lifetime: %w", model.ErrInvalid)
	case len(c.Result) > 0 && !json.Valid(c.Result):
		return fmt.Errorf("store: change approval result: %w", model.ErrInvalid)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO change_approvals (`+changeApprovalCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Op, c.Technician, c.Client, c.Device, c.AccessID, c.GrantID, c.Session, c.PlanID, c.PlanDigest, c.RollbackID,
		c.State, fmtTime(c.RequestedAt), fmtTime(c.ExpiresAt), c.Nonce, c.RequestID, fmtTimePtr(c.DecidedAt),
		fmtTimePtr(c.CompletedAt), c.Credential, nullBytes(c.Assertion), c.Reason, c.ErrorCode, string(c.Result))
	if err != nil {
		return fmt.Errorf("store: create change approval %s: %w", c.ID, err)
	}
	return nil
}

// ChangeApproval returns a change approval by ID, or ErrNotFound.
func (s *Store) ChangeApproval(ctx context.Context, id string) (model.ChangeApproval, error) {
	c, err := scanChangeApproval(s.db.QueryRowContext(ctx, "SELECT "+changeApprovalCols+" FROM change_approvals WHERE id = ?", id))
	if err != nil {
		return model.ChangeApproval{}, lookupErr("change approval", id, err)
	}
	return c, nil
}

// updateChangeApproval writes a change approval's decision and outcome.
// What it approves never changes after it is created.
func (s *Store) updateChangeApproval(ctx context.Context, q querier, c model.ChangeApproval) error {
	if len(c.Result) > 0 && !json.Valid(c.Result) {
		return fmt.Errorf("store: change approval result: %w", model.ErrInvalid)
	}
	res, err := q.ExecContext(ctx, `UPDATE change_approvals SET state = ?, decided_at = ?, completed_at = ?, credential = ?,
		assertion = ?, reason = ?, error_code = ?, result = ? WHERE id = ?`,
		c.State, fmtTimePtr(c.DecidedAt), fmtTimePtr(c.CompletedAt), c.Credential, nullBytes(c.Assertion), c.Reason,
		c.ErrorCode, string(c.Result), c.ID)
	return mustAffect(res, err, "change approval", c.ID)
}

// UpdateChangeApprovalTx applies fn to a change approval under a transaction.
// fn returns an error wrapping model.ErrConflict to leave the row untouched;
// the stored approval is returned either way.
func (s *Store) UpdateChangeApprovalTx(ctx context.Context, id string, fn func(*model.ChangeApproval) error) (model.ChangeApproval, error) {
	var out model.ChangeApproval
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		c, err := scanChangeApproval(tx.QueryRowContext(ctx, "SELECT "+changeApprovalCols+" FROM change_approvals WHERE id = ?", id))
		if err != nil {
			return lookupErr("change approval", id, err)
		}
		out = c
		if err := fn(&c); err != nil {
			return err
		}
		out = c
		return s.updateChangeApproval(ctx, tx, c)
	})
	return out, err
}

// ChangeApprovalFor returns the most recent approval of op on a plan under an
// access grant in one of states, or ErrNotFound.
func (s *Store) ChangeApprovalFor(ctx context.Context, accessID, planID, op string, states ...string) (model.ChangeApproval, error) {
	if len(states) == 0 {
		return model.ChangeApproval{}, fmt.Errorf("store: change approval: %w", model.ErrInvalid)
	}
	marks, args := inStates(states)
	c, err := scanChangeApproval(s.db.QueryRowContext(ctx, "SELECT "+changeApprovalCols+
		" FROM change_approvals WHERE access_id = ? AND plan_id = ? AND op = ? AND state IN ("+marks+
		") ORDER BY requested_at DESC, id DESC LIMIT 1", append([]any{accessID, planID, op}, args...)...))
	if err != nil {
		return model.ChangeApproval{}, lookupErr("change approval", planID, err)
	}
	return c, nil
}

// ChangeApprovals returns a technician's open change approvals and those
// requested at or after since, newest first.
func (s *Store) ChangeApprovals(ctx context.Context, technician string, since time.Time) ([]model.ChangeApproval, error) {
	return queryAll(ctx, s.db, scanChangeApproval, "SELECT "+changeApprovalCols+` FROM change_approvals WHERE technician = ?
		AND (requested_at >= ? OR state IN (?, ?)) ORDER BY requested_at DESC, id DESC`,
		technician, fmtTime(since), model.ChangeAwaiting, model.ChangeApproved)
}

// ChangeApprovalsOpen returns every change approval awaiting approval or
// approved.
func (s *Store) ChangeApprovalsOpen(ctx context.Context) ([]model.ChangeApproval, error) {
	return queryAll(ctx, s.db, scanChangeApproval, "SELECT "+changeApprovalCols+
		" FROM change_approvals WHERE state IN (?, ?) ORDER BY requested_at, id", model.ChangeAwaiting, model.ChangeApproved)
}

// PurgeApprovals deletes what technician approval no longer needs, in one
// transaction, and reports how many rows went.
func (s *Store) PurgeApprovals(ctx context.Context, cutoff time.Time) (int64, error) {
	c := fmtTime(cutoff)
	var total int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		total = 0
		for _, q := range []struct {
			query string
			args  []any
		}{
			{`DELETE FROM unlock_activity WHERE unlock IN (SELECT id FROM unlocks WHERE ended_at IS NOT NULL AND ended_at < ?)`, []any{c}},
			{`DELETE FROM change_plans WHERE prepared_at < ? AND plan_id NOT IN
				(SELECT plan_id FROM change_approvals WHERE state IN (?, ?))`, []any{c, model.ChangeAwaiting, model.ChangeApproved}},
			{`DELETE FROM passkey_links WHERE expires_at < ?`, []any{c}},
			{`DELETE FROM companion_sessions WHERE expires_at < ?`, []any{c}},
		} {
			res, err := tx.ExecContext(ctx, q.query, q.args...)
			if err != nil {
				return fmt.Errorf("store: purge approvals: %w", err)
			}
			n, err := res.RowsAffected()
			if err != nil {
				return fmt.Errorf("store: purge approvals: %w", err)
			}
			total += n
		}
		return nil
	})
	return total, err
}
