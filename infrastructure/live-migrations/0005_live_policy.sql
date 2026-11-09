CREATE TABLE ld_policy (
  id INTEGER PRIMARY KEY CHECK(id=1),
  version INTEGER NOT NULL CHECK(version>=0),
  policy_json TEXT NOT NULL CHECK(json_valid(policy_json))
);
INSERT INTO ld_policy VALUES (1,0,'{"mode":"Approve","killSwitch":false,"autonomousActions":[],"requireSecondApprover":false,"monthlyBudgetUsd":50,"maxDurationSeconds":600,"maxRequestSharePercent":2,"maxEvidenceAgeSeconds":900,"triageDeadlineSeconds":30,"investigationDeadlineSeconds":75,"maxToolCalls":6,"provider":"workers_ai","triageModel":"@cf/zai-org/glm-5.3-flash","investigationModel":"@cf/zai-org/glm-5.3"}');
CREATE TABLE ld_policy_audit (
  version INTEGER PRIMARY KEY,
  changed_at TEXT NOT NULL,
  changed_by TEXT NOT NULL,
  policy_json TEXT NOT NULL CHECK(json_valid(policy_json))
);
ALTER TABLE ld_ai_runs ADD COLUMN model TEXT NOT NULL DEFAULT '@cf/zai-org/glm-5.3';
