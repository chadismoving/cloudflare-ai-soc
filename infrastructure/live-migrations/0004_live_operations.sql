CREATE TABLE ld_log_objects (
  id TEXT PRIMARY KEY,
  dataset TEXT NOT NULL CHECK(dataset IN ('http','firewall')),
  object_key TEXT NOT NULL,
  object_at TEXT NOT NULL,
  processed_at TEXT NOT NULL,
  size INTEGER NOT NULL,
  accepted INTEGER NOT NULL,
  rejected INTEGER NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN ('complete','partial','failed')),
  error TEXT,
  expires_at TEXT NOT NULL
);
CREATE INDEX ld_log_objects_processed ON ld_log_objects(dataset,processed_at DESC);
CREATE INDEX ld_log_objects_expiry ON ld_log_objects(expires_at);

CREATE TABLE ld_log_events (
  id TEXT PRIMARY KEY,
  dataset TEXT NOT NULL CHECK(dataset IN ('http','firewall')),
  occurred_at TEXT NOT NULL,
  ray_id TEXT NOT NULL,
  host TEXT NOT NULL,
  status INTEGER,
  action TEXT,
  source TEXT,
  rule_id TEXT,
  object_id TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX ld_log_events_time ON ld_log_events(dataset,occurred_at DESC,id);
CREATE INDEX ld_log_events_ray ON ld_log_events(ray_id,dataset,occurred_at DESC);
CREATE INDEX ld_log_events_expiry ON ld_log_events(expires_at);

CREATE TABLE ld_repairs (
  id TEXT PRIMARY KEY,
  path TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  note TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','applying','verified','rolling_back','rolled_back','review')),
  requested_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  approved_by TEXT,
  approved_at TEXT,
  apply_before TEXT NOT NULL,
  rule_expires_at TEXT,
  ruleset_id TEXT,
  rule_id TEXT,
  lease_until TEXT,
  result TEXT,
  retain_until TEXT NOT NULL
);
CREATE INDEX ld_repairs_expiry ON ld_repairs(status,rule_expires_at);
CREATE INDEX ld_repairs_retention ON ld_repairs(retain_until);

CREATE TABLE ld_repair_audit (
  id TEXT PRIMARY KEY,
  repair_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE INDEX ld_repair_audit_lookup ON ld_repair_audit(repair_id,at);
CREATE INDEX ld_repair_audit_expiry ON ld_repair_audit(at);

CREATE TABLE ld_ops_state (
  task TEXT PRIMARY KEY,
  last_attempt TEXT NOT NULL,
  last_success TEXT,
  error TEXT,
  removed INTEGER NOT NULL DEFAULT 0
);
