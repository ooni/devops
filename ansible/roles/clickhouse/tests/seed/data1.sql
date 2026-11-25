-- data1 as on 2026-10-26: oonimeasurements created by hand (old limits, no profile, so
-- readonly 2 from the default profile), the writers on the XML write profile, an empty
-- role granted to the user of the same name, the oonimeasurements quota set up and
-- assigned by hand, grants the role doesn't list, and objects that aren't in vars.
-- {password:<user>} is the hash of the user's password from vars.
CREATE USER oonimeasurements IDENTIFIED WITH sha256_hash BY '{password:oonimeasurements}' SETTINGS max_memory_usage = 501001000, max_execution_time = 60;
CREATE USER fastpath IDENTIFIED WITH sha256_hash BY '{password:fastpath}' SETTINGS PROFILE 'write';
CREATE USER ooniprobe IDENTIFIED WITH sha256_hash BY '{password:ooniprobe}' SETTINGS PROFILE 'write';
CREATE USER oonirun IDENTIFIED WITH sha256_hash BY '{password:oonirun}' SETTINGS PROFILE 'write';
CREATE USER oonitestlists IDENTIFIED WITH sha256_hash BY '{password:oonitestlists}' SETTINGS PROFILE 'write';
CREATE USER notebook IDENTIFIED WITH sha256_hash BY '{password:notebook}' SETTINGS PROFILE 'write';
CREATE ROLE oonimeasurements;
GRANT oonimeasurements TO oonimeasurements;
GRANT SELECT ON ooni.* TO oonimeasurements, fastpath, ooniprobe, oonirun, notebook;
GRANT INSERT ON ooni.fastpath TO fastpath;
CREATE QUOTA oonimeasurements FOR INTERVAL 600 second MAX queries = 12000, errors = 1000, execution_time = 1000 TO oonimeasurements;
CREATE QUOTA ooniprobe;
GRANT ALTER UPDATE ON ooni.* TO oonimeasurements;
GRANT INSERT ON ooni.fastpath TO oonimeasurements;
GRANT SELECT ON extra.* TO ooniprobe;
CREATE USER manual_user IDENTIFIED WITH plaintext_password BY 'manual';
CREATE QUOTA manual_quota;
