ALTER TABLE ingestion_objects ADD COLUMN metrics_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(metrics_json) AND length(metrics_json)<=2048);
