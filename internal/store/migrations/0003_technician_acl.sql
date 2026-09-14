CREATE TABLE technician_client_acl (
 technician TEXT NOT NULL,
 client TEXT NOT NULL REFERENCES clients(slug) ON DELETE CASCADE,
 created_at TEXT NOT NULL,
 PRIMARY KEY (technician, client)
) STRICT;
CREATE INDEX technician_client_acl_client ON technician_client_acl(client, technician);

-- Identity-provider sessions are verified on every MCP request and are not
-- local client-bound session rows. Keep their stable session identifier for
-- audit correlation without pretending they are locally minted credentials.
ALTER TABLE access_requests RENAME TO access_requests_slice1;
CREATE TABLE access_requests (
 id TEXT PRIMARY KEY,
 client TEXT NOT NULL REFERENCES clients(slug),
 device TEXT NOT NULL REFERENCES devices(id),
 technician TEXT NOT NULL,
 session TEXT NOT NULL,
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
INSERT INTO access_requests SELECT * FROM access_requests_slice1;
DROP TABLE access_requests_slice1;
CREATE INDEX access_requests_client ON access_requests(client, requested_at);
