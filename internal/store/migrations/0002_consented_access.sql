CREATE TABLE access_requests (
 id TEXT PRIMARY KEY,
 client TEXT NOT NULL REFERENCES clients(slug),
 device TEXT NOT NULL REFERENCES devices(id),
 technician TEXT NOT NULL,
 session TEXT NOT NULL REFERENCES sessions(id),
 purpose TEXT NOT NULL,
 state TEXT NOT NULL,
 requested_scope TEXT NOT NULL,
 effective_scope TEXT NOT NULL,
 requested_operations TEXT NOT NULL,
 effective_operations TEXT NOT NULL,
 requested_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 idle_timeout_ns INTEGER NOT NULL,
 grant_id TEXT NOT NULL DEFAULT '',
 nonce TEXT NOT NULL DEFAULT '',
 approver TEXT NOT NULL DEFAULT '',
 reason TEXT NOT NULL DEFAULT '',
 policy_version INTEGER NOT NULL,
 decided_at TEXT,
 terminated_at TEXT
) STRICT;
CREATE INDEX access_requests_client ON access_requests(client, requested_at);
