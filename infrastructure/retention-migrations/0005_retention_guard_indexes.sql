CREATE TABLE retention_guard (
  id TEXT PRIMARY KEY,
  valid INTEGER NOT NULL CHECK (valid=1),
  counts_json TEXT NOT NULL CHECK (json_valid(counts_json) AND length(counts_json)<=4096)
);
CREATE INDEX retention_provenance_event ON ingestion_provenance(event_id);
CREATE INDEX retention_incident_links_event ON incident_events(event_id);
CREATE INDEX retention_evidence_incident ON evidence_objects(incident_id);
CREATE INDEX retention_replays_object ON ingestion_replays(object_id);
CREATE INDEX retention_failures_object ON ingestion_failures(object_id);
