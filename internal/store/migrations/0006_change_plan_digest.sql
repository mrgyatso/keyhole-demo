-- Slice 5: the change plan a grant may apply. The endpoint issues the digest
-- when it stages a plan; the relay records it here so an apply that quotes
-- another plan is refused before a device is contacted. The endpoint holds the
-- plan itself and checks again, and its decision is the authoritative one.
ALTER TABLE access_requests ADD COLUMN plan_digest TEXT NOT NULL DEFAULT '';
