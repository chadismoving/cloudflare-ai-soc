PRAGMA foreign_keys = ON;

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  access_subject TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('Viewer','Analyst','Operator','Admin')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
  created_at TEXT NOT NULL
);
CREATE TABLE zones (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
  environment TEXT NOT NULL CHECK (environment IN ('live','simulation')),
  UNIQUE(id, environment)
);
CREATE TABLE zone_access (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  zone_id TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
  permission TEXT NOT NULL CHECK (permission IN ('read','investigate','approve','manage')),
  PRIMARY KEY(user_id, zone_id)
);
CREATE TABLE events (
  id TEXT PRIMARY KEY,
  environment TEXT NOT NULL CHECK (environment IN ('live','simulation')),
  zone_id TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('notification','logpush','audit','synthetic')),
  category TEXT NOT NULL,
  event_time TEXT NOT NULL,
  received_at TEXT NOT NULL,
  dedupe_key TEXT NOT NULL,
  metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json) AND length(metadata_json) <= 16384),
  expires_at TEXT NOT NULL,
  UNIQUE(id, environment),
  UNIQUE(id, environment, zone_id),
  UNIQUE(environment, source, dedupe_key),
  FOREIGN KEY(zone_id, environment) REFERENCES zones(id, environment)
);
CREATE INDEX events_expiry ON events(expires_at);
CREATE INDEX events_zone_time ON events(zone_id, environment, event_time);
CREATE TABLE incidents (
  id TEXT PRIMARY KEY,
  environment TEXT NOT NULL CHECK (environment IN ('live','simulation')),
  zone_id TEXT NOT NULL,
  title TEXT NOT NULL CHECK (length(title) <= 240),
  category TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  status TEXT NOT NULL CHECK (status IN ('new','triaging','investigating','awaiting_approval','mitigating','verifying','resolved','closed','failed')),
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL CHECK (last_seen >= first_seen),
  summary TEXT NOT NULL CHECK (length(summary) <= 4000),
  confidence REAL CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  expires_at TEXT NOT NULL,
  UNIQUE(id, environment),
  UNIQUE(id, environment, zone_id),
  FOREIGN KEY(zone_id, environment) REFERENCES zones(id, environment)
);
CREATE INDEX incidents_zone_time ON incidents(zone_id, environment, last_seen DESC);
CREATE INDEX incidents_expiry ON incidents(expires_at);
CREATE TABLE incident_events (
  incident_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  environment TEXT NOT NULL,
  zone_id TEXT NOT NULL,
  PRIMARY KEY(incident_id, event_id),
  FOREIGN KEY(incident_id, environment, zone_id) REFERENCES incidents(id, environment, zone_id) ON DELETE CASCADE,
  FOREIGN KEY(event_id, environment, zone_id) REFERENCES events(id, environment, zone_id) ON DELETE CASCADE
);
CREATE TABLE evidence_objects (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  environment TEXT NOT NULL CHECK (environment IN ('live','simulation')),
  zone_id TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL CHECK (kind IN ('raw','cases','tool-snapshots')),
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY(incident_id, environment, zone_id) REFERENCES incidents(id, environment, zone_id) ON DELETE CASCADE,
  FOREIGN KEY(zone_id, environment) REFERENCES zones(id, environment)
);
CREATE INDEX evidence_expiry ON evidence_objects(expires_at);
CREATE TABLE audit_trail (
  id TEXT PRIMARY KEY,
  actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  operation TEXT NOT NULL,
  target_id TEXT NOT NULL,
  details_json TEXT NOT NULL CHECK (json_valid(details_json) AND length(details_json) <= 2048),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX audit_created ON audit_trail(created_at DESC);
CREATE INDEX audit_expiry ON audit_trail(expires_at);
