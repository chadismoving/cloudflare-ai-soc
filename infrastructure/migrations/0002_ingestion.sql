CREATE TABLE ingestion_objects (
  id TEXT PRIMARY KEY,
  object_key TEXT NOT NULL,
  etag TEXT NOT NULL,
  dataset TEXT NOT NULL,
  received_at TEXT NOT NULL,
  raw_expires_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('processing','complete','partial','failed','archived')),
  digest TEXT,
  valid_rows INTEGER NOT NULL DEFAULT 0,
  invalid_rows INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  UNIQUE(object_key,etag)
);
CREATE TABLE ingestion_event_keys (
  event_key TEXT PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  event_expires_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE ingestion_provenance (
  object_id TEXT NOT NULL REFERENCES ingestion_objects(id),
  event_id TEXT NOT NULL REFERENCES events(id),
  line_number INTEGER NOT NULL,
  PRIMARY KEY(object_id,line_number)
);
CREATE TABLE ingestion_failures (
  id TEXT PRIMARY KEY,
  object_id TEXT,
  reason TEXT NOT NULL,
  archive_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE ingestion_replays (
  id TEXT PRIMARY KEY,
  object_id TEXT NOT NULL REFERENCES ingestion_objects(id),
  state TEXT NOT NULL CHECK(state IN ('pending','queued','failed')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX ingestion_objects_expiry ON ingestion_objects(expires_at);
CREATE INDEX ingestion_keys_expiry ON ingestion_event_keys(expires_at);
CREATE INDEX ingestion_failures_expiry ON ingestion_failures(expires_at);
CREATE INDEX ingestion_replays_expiry ON ingestion_replays(expires_at);
