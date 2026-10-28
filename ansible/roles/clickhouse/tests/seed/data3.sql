-- data3 as on 2026-10-26: the users as upstream's role created them from older vars, with
-- the XML readonly profile (readonly 1, which refuses log_comment) and old passwords.
-- {old_password:<user>} is the hash of a password that isn't the one in vars.
CREATE USER oonimeasurements IDENTIFIED WITH sha256_hash BY '{old_password:oonimeasurements}' SETTINGS max_memory_usage = 1001001000, max_execution_time = 30, max_bytes_to_read = 501001001000, max_rows_to_read = 5001001000, timeout_before_checking_execution_speed = 5, max_result_rows = 51000, PROFILE 'readonly';
CREATE USER fastpath IDENTIFIED WITH sha256_hash BY '{old_password:fastpath}' SETTINGS PROFILE 'write';
CREATE USER ooniprobe IDENTIFIED WITH sha256_hash BY '{old_password:ooniprobe}' SETTINGS PROFILE 'write';
GRANT SELECT ON ooni.* TO oonimeasurements, fastpath, ooniprobe;
GRANT INSERT ON ooni.fastpath TO fastpath;
CREATE QUOTA oonimeasurements;
