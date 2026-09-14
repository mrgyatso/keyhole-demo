-- Clients and the NATS material the relay signs with inside each client's
-- account. Seeds are in the clear in a 0700 data dir; at-rest encryption is
-- Phase 2.
CREATE TABLE clients (
	slug            TEXT PRIMARY KEY,
	name            TEXT NOT NULL,
	account_key     TEXT NOT NULL UNIQUE,
	account_seed    TEXT NOT NULL,
	signing_seed    TEXT NOT NULL,
	account_jwt     TEXT NOT NULL,
	relay_jwt       TEXT NOT NULL,
	relay_seed      TEXT NOT NULL,
	disabled        INTEGER NOT NULL DEFAULT 0,
	disabled_reason TEXT NOT NULL DEFAULT '',
	disabled_at     TEXT,
	policy          TEXT NOT NULL,
	created_at      TEXT NOT NULL
) STRICT;

-- Enrollment tokens. Only the SHA-256 of the secret is stored.
CREATE TABLE enroll_tokens (
	id         TEXT PRIMARY KEY,
	client     TEXT NOT NULL REFERENCES clients (slug),
	hash       TEXT NOT NULL UNIQUE,
	note       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	max_uses   INTEGER NOT NULL DEFAULT 0 CHECK (max_uses >= 0),
	uses       INTEGER NOT NULL DEFAULT 0,
	revoked_at TEXT
) STRICT;
CREATE INDEX enroll_tokens_client ON enroll_tokens (client);

-- Devices. A device's identity is its NATS user public key, which is never
-- reused: a revoked key stays revoked.
CREATE TABLE devices (
	id              TEXT PRIMARY KEY,
	client          TEXT NOT NULL REFERENCES clients (slug),
	public_key      TEXT NOT NULL UNIQUE,
	hostname        TEXT NOT NULL DEFAULT '',
	machine_id      TEXT NOT NULL DEFAULT '',
	os              TEXT NOT NULL DEFAULT '',
	os_version      TEXT NOT NULL DEFAULT '',
	arch            TEXT NOT NULL DEFAULT '',
	agent_version   TEXT NOT NULL DEFAULT '',
	enrolled_at     TEXT NOT NULL,
	enroll_token_id TEXT NOT NULL REFERENCES enroll_tokens (id),
	last_seen       TEXT,
	revoked_at      TEXT
) STRICT;
CREATE INDEX devices_client ON devices (client);
CREATE INDEX devices_live_machine ON devices (client, machine_id) WHERE revoked_at IS NULL;

-- MCP sessions. Only the SHA-256 of the bearer is stored.
CREATE TABLE sessions (
	id         TEXT PRIMARY KEY,
	client     TEXT NOT NULL REFERENCES clients (slug),
	tech       TEXT NOT NULL,
	hash       TEXT NOT NULL UNIQUE,
	note       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	revoked_at TEXT
) STRICT;
CREATE INDEX sessions_client ON sessions (client);

-- The admin API token. One row; only the SHA-256 of the token is stored.
CREATE TABLE admin_token (
	id         INTEGER PRIMARY KEY CHECK (id = 1),
	hash       TEXT NOT NULL,
	created_at TEXT NOT NULL
) STRICT;

CREATE TABLE kv (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
) STRICT;
