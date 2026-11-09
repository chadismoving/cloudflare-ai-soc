CREATE TABLE r2_deletion_outbox (
  id TEXT PRIMARY KEY,
  valid INTEGER NOT NULL DEFAULT 1 CHECK(valid=1),
  source_kind TEXT NOT NULL CHECK(source_kind IN ('case','archive')),
  source_id TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  expected_sha256 TEXT CHECK(expected_sha256 IS NULL OR (length(expected_sha256)=64 AND expected_sha256 NOT GLOB '*[^a-f0-9]*')),
  expires_at TEXT NOT NULL CHECK(strftime('%Y-%m-%dT%H:%M:%fZ',expires_at) IS expires_at),
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','deleting','deleted','blocked')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
  next_attempt_at TEXT NOT NULL CHECK(strftime('%Y-%m-%dT%H:%M:%fZ',next_attempt_at) IS next_attempt_at),
  lease_token TEXT,
  lease_until TEXT CHECK(lease_until IS NULL OR strftime('%Y-%m-%dT%H:%M:%fZ',lease_until) IS lease_until),
  last_error TEXT,
  completed_at TEXT CHECK(completed_at IS NULL OR strftime('%Y-%m-%dT%H:%M:%fZ',completed_at) IS completed_at),
  UNIQUE(source_kind,source_id)
);
CREATE INDEX r2_outbox_due ON r2_deletion_outbox(state,next_attempt_at,expires_at);
CREATE INDEX r2_outbox_completed ON r2_deletion_outbox(state,completed_at);
