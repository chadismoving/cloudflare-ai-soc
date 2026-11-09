INSERT OR IGNORE INTO zones VALUES
 ('fixture-zone','fixture-account','demo.fixture.invalid',1,'simulation'),
 ('other-zone','fixture-account','other.fixture.invalid',1,'simulation');
INSERT OR IGNORE INTO events VALUES
 ('event-001','simulation','fixture-zone','synthetic','waf',strftime('%Y-%m-%dT%H:%M:%fZ','now','-12 minutes'),strftime('%Y-%m-%dT%H:%M:%fZ','now'),'fixture-waf-001','{"fixture":true,"requestCount":1847,"client":"client-a"}',strftime('%Y-%m-%dT%H:%M:%fZ','now','+30 days'));
INSERT OR IGNORE INTO incidents VALUES
 ('incident-001','simulation','fixture-zone','Repeated WAF matches on a synthetic endpoint','waf','high','new',strftime('%Y-%m-%dT%H:%M:%fZ','now','-12 minutes'),strftime('%Y-%m-%dT%H:%M:%fZ','now','-2 minutes'),'Seeded fixture: 1,847 requests from an anonymized client. This record has not been evaluated by an AI model.',NULL,strftime('%Y-%m-%dT%H:%M:%fZ','now','+90 days')),
 ('incident-002','simulation','fixture-zone','Expected automation in a baseline window','bot','low','new',strftime('%Y-%m-%dT%H:%M:%fZ','now','-48 minutes'),strftime('%Y-%m-%dT%H:%M:%fZ','now','-19 minutes'),'Seeded benign fixture for the foundation UI. No malicious/benign model classification or mitigation has run.',NULL,strftime('%Y-%m-%dT%H:%M:%fZ','now','+90 days')),
 ('incident-other','simulation','other-zone','Unpermitted-zone fixture','http','info','new',strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now'),'Used only to verify server-side zone isolation.',NULL,strftime('%Y-%m-%dT%H:%M:%fZ','now','+90 days'));
INSERT OR IGNORE INTO incident_events VALUES ('incident-001','event-001','simulation','fixture-zone');
INSERT OR IGNORE INTO evidence_objects VALUES
 ('evidence-001','incident-001','simulation','fixture-zone','simulation/cases/fixture/evidence-001.json','cases','__EVIDENCE_SHA256__',strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now','+90 days'));
