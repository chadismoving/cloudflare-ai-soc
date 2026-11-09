CREATE TABLE ld_state (
  id INTEGER PRIMARY KEY CHECK(id=1),
  lease_token TEXT,
  lease_until TEXT,
  last_attempt TEXT,
  last_success TEXT,
  last_error TEXT,
  last_end TEXT,
  last_gap_seconds INTEGER NOT NULL DEFAULT 0
);
INSERT INTO ld_state(id) VALUES(1);
CREATE TABLE ld_snapshots (
  id TEXT PRIMARY KEY,
  zone_id TEXT NOT NULL CHECK(zone_id='00000000000000000000000000000002'),
  window_start TEXT NOT NULL,
  window_end TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  facts_json TEXT NOT NULL CHECK(json_valid(facts_json) AND length(facts_json)<=65536),
  sha256 TEXT NOT NULL CHECK(length(sha256)=64),
  expires_at TEXT NOT NULL,
  UNIQUE(zone_id,window_end)
);
CREATE INDEX ld_snapshots_expiry ON ld_snapshots(expires_at);
CREATE TABLE ld_findings (
  id TEXT PRIMARY KEY,
  zone_id TEXT NOT NULL CHECK(zone_id='00000000000000000000000000000002'),
  window_end TEXT NOT NULL,
  rule TEXT NOT NULL CHECK(rule IN ('mitigation-volume-v1','http-5xx-v1')),
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('low','medium')),
  summary TEXT NOT NULL,
  evidence_json TEXT NOT NULL CHECK(json_valid(evidence_json) AND length(evidence_json)<=65536),
  sha256 TEXT NOT NULL CHECK(length(sha256)=64),
  expires_at TEXT NOT NULL,
  UNIQUE(zone_id,window_end,rule)
);
CREATE INDEX ld_findings_expiry ON ld_findings(expires_at);
CREATE INDEX ld_findings_time ON ld_findings(window_end DESC);
