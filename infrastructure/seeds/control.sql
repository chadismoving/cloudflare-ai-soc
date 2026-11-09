INSERT OR IGNORE INTO users VALUES
 ('user-admin','fixture-admin','admin@fixture.invalid','Admin',1,0,strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 ('user-viewer','fixture-viewer','viewer@fixture.invalid','Viewer',1,0,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
INSERT OR IGNORE INTO zones VALUES ('fixture-zone','fixture-account','demo.fixture.invalid',1,'simulation');
INSERT OR IGNORE INTO zone_access VALUES ('user-admin','fixture-zone','manage'),('user-viewer','fixture-zone','approve');
