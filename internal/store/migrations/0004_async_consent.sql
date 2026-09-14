-- Consent is asynchronous: the endpoint acks the request, a human decides
-- minutes later, and the decision arrives as a device event. The request
-- therefore carries the window it must be decided in, who decided and in
-- which OS session, when it was paused, and the sequence of the last
-- endpoint event applied so a stale or duplicate delivery cannot move it.
ALTER TABLE access_requests ADD COLUMN approver_session TEXT NOT NULL DEFAULT '';
ALTER TABLE access_requests ADD COLUMN consent_deadline TEXT;
ALTER TABLE access_requests ADD COLUMN paused_at TEXT;
ALTER TABLE access_requests ADD COLUMN event_seq INTEGER NOT NULL DEFAULT 0;
