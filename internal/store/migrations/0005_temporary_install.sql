-- Temporary installation (Slice 4). Additive columns only: a managed token
-- and a managed device keep their existing rows and defaults.

-- An ephemeral token enrolls exactly one device (max_uses is forced to 1) and
-- that device lives for device_ttl_ns. technician is the identity shown to the
-- endpoint user before the install; it authorises nothing.
ALTER TABLE enroll_tokens ADD COLUMN ephemeral     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE enroll_tokens ADD COLUMN device_ttl_ns INTEGER NOT NULL DEFAULT 0 CHECK (device_ttl_ns >= 0);
ALTER TABLE enroll_tokens ADD COLUMN technician    TEXT    NOT NULL DEFAULT '';

-- A temporary device dies at expires_at whether or not the endpoint is
-- reachable. The relay's reconcile loop turns expiry into a real revocation.
ALTER TABLE devices ADD COLUMN ephemeral  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN expires_at TEXT;

-- The reconcile loop's sweep: live temporary devices, oldest deadline first.
CREATE INDEX devices_expiring ON devices (expires_at)
	WHERE ephemeral = 1 AND revoked_at IS NULL;
