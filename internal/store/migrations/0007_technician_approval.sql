-- Slice 6: technician approval. A managed endpoint no longer asks the person
-- at the machine: the technician unlocks a client with a passkey in the
-- companion, and approves each change there on its exact diff.

-- A technician's WebAuthn credentials. public_key is SubjectPublicKeyInfo DER.
CREATE TABLE passkeys (
 credential_id TEXT PRIMARY KEY,
 technician TEXT NOT NULL,
 public_key BLOB NOT NULL,
 algorithm INTEGER NOT NULL,
 sign_count INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
 name TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 last_used_at TEXT,
 revoked_at TEXT
) STRICT;
CREATE INDEX passkeys_technician ON passkeys (technician, created_at);

-- One-time enrollment links, minted on the admin control plane. Only the
-- secret's hash is stored.
CREATE TABLE passkey_links (
 id TEXT PRIMARY KEY,
 technician TEXT NOT NULL,
 hash TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 used_at TEXT
) STRICT;

-- Companion sign-ins, held in a cookie. Only the secret's hash is stored.
CREATE TABLE companion_sessions (
 id TEXT PRIMARY KEY,
 technician TEXT NOT NULL,
 credential TEXT NOT NULL,
 hash TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 revoked_at TEXT
) STRICT;
CREATE INDEX companion_sessions_technician ON companion_sessions (technician);

-- Client unlocks. nonce and expires_at are set when a passkey ceremony begins
-- and fixed by the approval; assertion is the approving PasskeyAssertion as
-- JSON, kept so the endpoint can verify it itself in Slice 7.
CREATE TABLE unlocks (
 id TEXT PRIMARY KEY,
 technician TEXT NOT NULL,
 client TEXT NOT NULL REFERENCES clients(slug),
 session TEXT NOT NULL,
 purpose TEXT NOT NULL,
 state TEXT NOT NULL,
 duration_ns INTEGER NOT NULL CHECK (duration_ns > 0),
 idle_timeout_ns INTEGER NOT NULL CHECK (idle_timeout_ns >= 0),
 requested_at TEXT NOT NULL,
 deadline TEXT NOT NULL,
 nonce TEXT NOT NULL DEFAULT '',
 expires_at TEXT,
 decided_at TEXT,
 last_used_at TEXT,
 ended_at TEXT,
 reason TEXT NOT NULL DEFAULT '',
 credential TEXT NOT NULL DEFAULT '',
 assertion BLOB,
 calls INTEGER NOT NULL DEFAULT 0,
 devices TEXT NOT NULL DEFAULT '[]'
) STRICT;
CREATE INDEX unlocks_technician ON unlocks (technician, client, requested_at);
CREATE INDEX unlocks_open ON unlocks (state) WHERE state IN ('awaiting_approval', 'active');

-- Every device call made under an unlock: the companion's activity view and
-- the receipt. Purged a day after the unlock ends.
CREATE TABLE unlock_activity (
 seq INTEGER PRIMARY KEY,
 unlock TEXT NOT NULL REFERENCES unlocks(id),
 at TEXT NOT NULL,
 op TEXT NOT NULL,
 device TEXT NOT NULL,
 path TEXT NOT NULL DEFAULT '',
 result TEXT NOT NULL,
 error_code TEXT NOT NULL DEFAULT '',
 bytes INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX unlock_activity_unlock ON unlock_activity (unlock, seq);

-- The unlock an access request was made under or waits for, and whether the
-- person at the machine must approve it as well.
ALTER TABLE access_requests ADD COLUMN unlock TEXT NOT NULL DEFAULT '';
ALTER TABLE access_requests ADD COLUMN endpoint_consent INTEGER NOT NULL DEFAULT 0;
CREATE INDEX access_requests_unlock ON access_requests (unlock) WHERE unlock != '';

-- The relay's display copy of each prepared plan, diff included, for the
-- change card. The endpoint holds the plan itself. Purged a day after prepare.
CREATE TABLE change_plans (
 plan_id TEXT PRIMARY KEY,
 access_id TEXT NOT NULL REFERENCES access_requests(id),
 client TEXT NOT NULL,
 device TEXT NOT NULL,
 technician TEXT NOT NULL,
 digest TEXT NOT NULL,
 plan TEXT NOT NULL,
 prepared_at TEXT NOT NULL,
 expires_at TEXT NOT NULL
) STRICT;

-- One approval per submitted apply or rollback. request_id is the endpoint
-- request ID of its release, so releasing it again is idempotent.
CREATE TABLE change_approvals (
 id TEXT PRIMARY KEY,
 op TEXT NOT NULL,
 technician TEXT NOT NULL,
 client TEXT NOT NULL,
 device TEXT NOT NULL,
 access_id TEXT NOT NULL REFERENCES access_requests(id),
 grant_id TEXT NOT NULL,
 session TEXT NOT NULL,
 plan_id TEXT NOT NULL,
 plan_digest TEXT NOT NULL,
 rollback_id TEXT NOT NULL DEFAULT '',
 state TEXT NOT NULL,
 requested_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 nonce TEXT NOT NULL,
 request_id TEXT NOT NULL,
 decided_at TEXT,
 completed_at TEXT,
 credential TEXT NOT NULL DEFAULT '',
 assertion BLOB,
 reason TEXT NOT NULL DEFAULT '',
 error_code TEXT NOT NULL DEFAULT '',
 result TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX change_approvals_technician ON change_approvals (technician, requested_at);
CREATE INDEX change_approvals_plan ON change_approvals (access_id, plan_id, op);
CREATE INDEX change_approvals_open ON change_approvals (state) WHERE state IN ('awaiting_approval', 'approved');
