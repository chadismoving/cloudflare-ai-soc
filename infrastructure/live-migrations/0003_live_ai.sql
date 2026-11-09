CREATE TABLE ld_ai_runs (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL,
  month TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('running','complete','failed')),
  started_at TEXT NOT NULL,
  report_expires_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  cost_micro INTEGER NOT NULL CHECK(cost_micro>=0),
  usage_known INTEGER NOT NULL DEFAULT 0 CHECK(usage_known IN (0,1)),
  report_json TEXT CHECK(report_json IS NULL OR (json_valid(report_json) AND length(report_json)<=16000)),
  failure TEXT CHECK(failure IN ('timeout','invalid_response','provider_unavailable'))
);
CREATE INDEX ld_ai_finding_started ON ld_ai_runs(finding_id,started_at DESC);
CREATE INDEX ld_ai_month ON ld_ai_runs(month,cost_micro);
CREATE INDEX ld_ai_expiry ON ld_ai_runs(expires_at);
CREATE INDEX ld_ai_report_expiry ON ld_ai_runs(report_expires_at) WHERE report_json IS NOT NULL;
