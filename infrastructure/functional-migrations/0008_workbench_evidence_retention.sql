CREATE TABLE IF NOT EXISTS wb_evidence_registry (
 id TEXT PRIMARY KEY CHECK(length(id)=73 AND substr(id,1,9)='evidence-' AND substr(id,10) NOT GLOB '*[^a-f0-9]*'),
 incident_id TEXT NOT NULL CHECK(incident_id='sim-'||substr(id,10)),
 zone_id TEXT NOT NULL CHECK(zone_id='fixture-zone'),
 object_key TEXT NOT NULL UNIQUE CHECK(object_key IN ('cases/workbench/'||substr(id,10)||'.json','simulation/cases/workbench/'||substr(id,10)||'.json')),
 sha256 TEXT NOT NULL CHECK(length(sha256)=64 AND sha256 NOT GLOB '*[^a-f0-9]*'),
 created_at TEXT NOT NULL CHECK(strftime('%Y-%m-%dT%H:%M:%fZ',created_at) IS created_at),
 expires_at TEXT NOT NULL CHECK(strftime('%Y-%m-%dT%H:%M:%fZ',created_at,'+90 days') IS expires_at),
 state TEXT NOT NULL DEFAULT 'staging' CHECK(state IN ('staging','registered','deleting','deleted','blocked')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
 lease_token TEXT,
 lease_until TEXT,
 next_attempt_at TEXT NOT NULL,
 last_error TEXT,
 completed_at TEXT
);
CREATE INDEX IF NOT EXISTS wb_evidence_due ON wb_evidence_registry(state,next_attempt_at,expires_at);
CREATE INDEX IF NOT EXISTS wb_threads_incident ON wb_threads(incident_id);
CREATE INDEX IF NOT EXISTS wb_runs_incident ON wb_runs(incident_id);
CREATE INDEX IF NOT EXISTS wb_proposals_incident ON wb_proposals(incident_id);
CREATE INDEX IF NOT EXISTS wb_simulations_incident ON wb_simulations(incident_id);
INSERT OR IGNORE INTO wb_evidence_registry (id,incident_id,zone_id,object_key,sha256,created_at,expires_at,state,next_attempt_at)
 SELECT id,incident_id,zone_id,object_key,sha256,created_at,expires_at,'registered',expires_at FROM evidence_objects
 WHERE object_key='cases/workbench/'||substr(id,10)||'.json' OR object_key='simulation/cases/workbench/'||substr(id,10)||'.json';
