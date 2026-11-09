-- Nullable: historical upload timestamps cannot establish processing times.
ALTER TABLE ingestion_objects ADD COLUMN first_attempt_at TEXT;
ALTER TABLE ingestion_objects ADD COLUMN last_attempt_at TEXT;
ALTER TABLE ingestion_objects ADD COLUMN processed_at TEXT;
ALTER TABLE ingestion_objects ADD COLUMN archived_at TEXT;
