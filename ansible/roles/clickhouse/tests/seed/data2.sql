-- data2 as on 2026-10-26: oonimeasurements created by hand with only a memory limit, and
-- quotas that exist but are empty and assigned to nobody.
CREATE USER oonimeasurements IDENTIFIED WITH sha256_hash BY '{password:oonimeasurements}' SETTINGS max_memory_usage = 4294967296;
CREATE USER fastpath IDENTIFIED WITH sha256_hash BY '{password:fastpath}' SETTINGS PROFILE 'write';
GRANT SELECT ON ooni.* TO oonimeasurements, fastpath;
CREATE QUOTA oonimeasurements;
CREATE QUOTA ooniprobe;
CREATE QUOTA oonirun;
CREATE QUOTA oonitestlists;
CREATE QUOTA notebook;
