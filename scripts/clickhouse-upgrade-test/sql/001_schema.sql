-- Schema for the test cluster.
--
-- `fastpath`, `citizenlab`, `jsonl`, `analysis_web_measurement`,
-- `event_detector_changepoints`, `event_detector_cusums`, and
-- `faulty_measurements` are reproduced verbatim (columns/engine/ORDER BY/
-- indexes) from ooni/devops scripts/cluster-migration/schema.sql, which is
-- this cluster's own migration script and the closest thing to an
-- authoritative current-state schema dump we have -- see
-- verification notes below for how this was cross-checked against
-- ooni/backend.
--
-- `url_priorities` has no definition anywhere in ooni/devops -- it doesn't
-- appear in schema.sql at all, even though the ansible grants
-- (group_vars/clickhouse/vars.yml -> clickhouse_custom_grants) reference it
-- explicitly for the `oonitestlists` user. Its DDL below is ported from
-- ooni/backend's copy (see below) to ReplicatedCollapsingMergeTree since
-- there's no devops source to match against.
--
-- `obs_web` doesn't appear in devops' schema.sql either (it's created by a
-- different repo/pipeline not in scope here), so its DDL is derived from
-- ooni/backend ooniapi/services/oonimeasurements/tests/fixtures/initdb/clickhouse.sql.
--
-- ==========================================================================
-- Verification against ooni/backend (2026-08-11)
-- ==========================================================================
-- Every ooniapi/services/{oonimeasurements,ooniprobe,oonirun,testlists}
-- ClickHouse fixture was diffed column-by-column against devops'
-- schema.sql. Three real divergences were found and are recorded here
-- rather than silently "fixed" one way or the other, since devops and
-- backend disagree with each other, not just with this test:
--
-- 1. `event_detector_changepoints`: devops' schema.sql and ooni/backend's
--    ooniapi/services/oonimeasurements/tests/migrations/0_clickhouse_init_tables.sql
--    define TWO DIFFERENT, INCOMPATIBLE column sets for this table --
--    devops uses `last_ts` + `*_obs_w_sum` + `*_w_sum` + `current_mean`
--    (an exponentially-weighted-sum CUSUM design, paired with the separate
--    `event_detector_cusums` table below), while backend's oonimeasurements
--    fixture uses `*_current_state` string enums instead (no w_sum/obs_w_sum
--    columns, no separate cusums table). An earlier version of this file
--    accidentally used backend's column set here while crediting it to
--    devops in this header -- that's fixed now; this table matches devops'
--    schema.sql exactly. If backend's oonimeasurements service is actually
--    reading/writing `*_current_state` columns against production, this is
--    a real bug worth raising separately -- either that table was migrated
--    to the w_sum design after oonimeasurements' fixture was last updated,
--    or oonimeasurements is silently failing to read columns it expects.
-- 2. `fastpath`: backend's legacy ooniprobe/oonirun/testlists fixtures
--    (`ooniapi/services/{ooniprobe,oonirun,testlists}/tests/fixtures/initdb/01-scheme.sql`,
--    all three byte-for-byte identical to each other) define `probe_cc`/
--    `test_name` as plain `String` and `probe_asn` as `UInt32`, add
--    `is_verified` via a bare `ALTER ... ADD COLUMN` with no default, and
--    have neither the `fastpath_rid_idx`/`measurement_uid_idx` indexes nor
--    `measurement_uid` in the ORDER BY key. devops' schema.sql has
--    `LowCardinality(String)`, `probe_asn Int32` (signed -- ASNs are
--    unsigned by definition, so this looks like a latent devops bug, not
--    something to copy), the two indexes, `measurement_uid` in ORDER BY,
--    and `is_verified` defaulted to 'u' via a later `MODIFY COLUMN`. This
--    file follows devops' schema.sql (kept `Int32` as-is rather than
--    "fixing" it to `UInt32`, to stay faithful to what's actually deployed
--    -- flagging it here instead).
-- 3. `analysis_web_measurement`: backend's oonimeasurements fixture omits
--    `PARTITION BY substring(measurement_uid, 1, 6)` and leaves `domain`
--    out of the `ORDER BY` key that devops' schema.sql has. This file
--    follows devops.
-- 4. `jsonl`: backend's fixtures (oonimeasurements AND the legacy
--    ooniprobe/oonirun/testlists trio) define a plain `MergeTree` with only
--    `report_id`/`input`/`s3path`/`linenum`/`measurement_uid` -- no `date`,
--    `source`, or `update_time` columns, and no Replicated/versioned
--    engine. devops' schema.sql has all three extra columns and uses
--    `ReplicatedReplacingMergeTree(..., update_time)`. This file follows
--    devops; if `date`/`source` are genuinely new/planned columns, backend
--    code may not be populating them.
-- 5. `faulty_measurements`: ooniprobe's fixture
--    (tests/fixtures/initdb/03-faulty-msm-detection.sql) adds
--    `SETTINGS async_insert=1, wait_for_async_insert=0`; devops' schema.sql
--    has no such settings on this table. Not schema-breaking (an insert
--    behavior setting, not a column/engine difference) so not copied here,
--    just noted.
--
-- Separately, backend's legacy ooniprobe/oonirun/testlists fixtures define
-- eleven more tables that don't exist anywhere in devops' schema.sql at
-- all: `test_groups` (Join engine), `accounts` + `session_expunge`
-- (EmbeddedRocksDB), `counters_test_list` + `counters_asn_test_list`
-- (materialized views over fastpath+citizenlab), `msmt_feedback`,
-- `fingerprints_dns` + `fingerprints_http` (EmbeddedRocksDB),
-- `asnmeta`, `incidents`, and a `oonirun` table (distinct from the
-- `oonirun` *service*). These aren't included here -- unclear whether
-- they're still live on oonidata_cluster or leftovers from the pre-split
-- monolith devops' schema.sql doesn't track. Flagging for a decision
-- rather than guessing; see the PR description / follow-up discussion.
--
-- ==========================================================================
-- Verification against live production `SHOW CREATE TABLE` (2026-08-11)
-- ==========================================================================
-- Aaron ran `SHOW CREATE TABLE` directly against prod for the tables below;
-- ground truth beats every repo's copy of it, so these override anything
-- said above where they conflict.
--
-- - `fastpath`: exact match, column-for-column, engine args, ORDER BY,
--   both indexes. devops' schema.sql (what this file already followed) is
--   accurate for this table.
-- - `obs_web`: three real divergences from the backend-fixture-derived
--   version this file had. Fixed:
--     1. Missing `probe_id FixedString(64)` column (added at the end,
--        matching prod's column order).
--     2. Missing all three indexes (`measurement_start_time_idx`,
--        `probe_cc_idx`, `probe_asn_idx`, all `minmax`).
--     3. Missing `PARTITION BY concat(substring(bucket_date, 1, 4),
--        substring(bucket_date, 6, 2))` entirely -- this table isn't
--        partitioned by toYYYYMM(x) like the others, it derives the
--        partition from the `bucket_date` string column.
--   Also note (not a bug, just a fact worth recording): the ZK path is
--   `/clickhouse/{cluster}/tables/ooni/obs_web_repl/{shard}`, i.e. the
--   table was apparently renamed from `obs_web_repl` to `obs_web` at some
--   point -- `RENAME TABLE` doesn't touch the underlying ZK path, so the
--   mismatch between table name and path is expected, not something to
--   "correct" to `.../obs_web/{shard}`.
--
-- Round 2 (2026-08-11, same day): got `SHOW CREATE TABLE` for the rest --
-- `citizenlab`, `citizenlab_flip`, `jsonl`, `analysis_web_measurement`,
-- `event_detector_changepoints`, `event_detector_cusums`,
-- `faulty_measurements`. Findings, each fixed inline at the relevant table:
--
-- - `jsonl`, `faulty_measurements`: exact matches, no changes. devops'
--   schema.sql was accurate for both.
-- - `citizenlab` / `citizenlab_flip`: columns match, but their ZK paths are
--   swapped relative to what the table names suggest -- `citizenlab`'s data
--   lives under `.../citizenlab_flip/{shard}` and vice versa (a swap-pair
--   pattern, not a mistake to tidy up). Also, `citizenlab_flip` was missing
--   from this file entirely -- only `citizenlab` had been added.
-- - `analysis_web_measurement`: missing 4 columns (`top_dns_rule_id`,
--   `top_tcp_rule_id`, `top_tls_rule_id`, `probe_id`) and all 3 indexes.
-- - `event_detector_changepoints` and `event_detector_cusums`: both
--   *completely* rewritten. devops' schema.sql -- which is to say, what
--   round 1 above followed -- doesn't match production for either table at
--   all: real prod uses plain, non-replicated `ReplacingMergeTree` for
--   both (no `Replicated` prefix, no `ON CLUSTER`-implied coordination
--   across replicas -- confirmed from the `ENGINE =` line, which has no ZK
--   path/replica args), neither has a `PARTITION BY`, and both have
--   entirely different column sets than devops' schema.sql describes. This
--   means devops' own migration script was stale/aspirational for these
--   two tables specifically, not just backend's fixtures -- worth raising
--   with whoever maintains scripts/cluster-migration/schema.sql, since
--   anyone using it as a reference for these two tables would be misled.
--
-- Every table in this file has now been checked against a live
-- `SHOW CREATE TABLE`, not just against devops/backend's copies of it.
-- Only genuinely open item left: the eleven legacy-monolith-only tables
-- noted above (test_groups, accounts, etc.) -- still an open question
-- whether those belong here at all, not a verification gap.
--
-- All DDL runs ON CLUSTER so it exercises ClickHouse's distributed_ddl queue
-- (the same mechanism prod uses to apply schema changes to all 3 replicas,
-- for every table except event_detector_changepoints/cusums -- see above).

CREATE DATABASE IF NOT EXISTS ooni ON CLUSTER oonidata_cluster;

CREATE TABLE IF NOT EXISTS ooni.jsonl ON CLUSTER oonidata_cluster
(
    `report_id` String,
    `input` String,
    `s3path` String,
    `linenum` Int32,
    `measurement_uid` String,
    `date` Date,
    `source` String,
    `update_time` DateTime64(3) MATERIALIZED now64()
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/jsonl/{shard}',
    '{replica}',
    update_time
)
ORDER BY (report_id, input, measurement_uid)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS ooni.fastpath ON CLUSTER oonidata_cluster
(
    `measurement_uid` String,
    `report_id` String,
    `input` String,
    `probe_cc` LowCardinality(String),
    `probe_asn` Int32,
    `test_name` LowCardinality(String),
    `test_start_time` DateTime,
    `measurement_start_time` DateTime,
    `filename` String,
    `scores` String,
    `platform` String,
    `anomaly` String,
    `confirmed` String,
    `msm_failure` String,
    `domain` String,
    `software_name` String,
    `software_version` String,
    `control_failure` String,
    `blocking_general` Float32,
    `is_ssl_expected` Int8,
    `page_len` Int32,
    `page_len_ratio` Float32,
    `server_cc` String,
    `server_asn` Int8,
    `server_as_name` String,
    `update_time` DateTime64(3) MATERIALIZED now64(),
    `test_version` String,
    `architecture` String,
    `engine_name` LowCardinality(String),
    `engine_version` String,
    `test_runtime` Float32,
    `blocking_type` String,
    `test_helper_address` LowCardinality(String),
    `test_helper_type` LowCardinality(String),
    `ooni_run_link_id` Nullable(UInt64),
    `is_verified` LowCardinality(String) DEFAULT 'u',
    INDEX fastpath_rid_idx report_id TYPE minmax GRANULARITY 1,
    INDEX measurement_uid_idx measurement_uid TYPE minmax GRANULARITY 8
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/fastpath/{shard}',
    '{replica}',
    update_time
)
ORDER BY (measurement_start_time, report_id, input, measurement_uid)
SETTINGS index_granularity = 8192;

-- Verified 2026-08-11 against live `SHOW CREATE TABLE`. The ZK paths for
-- citizenlab and citizenlab_flip are swapped relative to what their table
-- names would suggest: `citizenlab` stores its data under the
-- `.../citizenlab_flip/{shard}` path and vice versa. This isn't a typo to
-- "fix" -- these two tables are a swap pair (load fresh data into whichever
-- one isn't currently live, then the application-facing name gets
-- repointed), and this cross-wiring is what you get after however many
-- swaps have happened over the table's history. devops' schema.sql defines
-- citizenlab_flip with its own straightforwardly-matching path, which is
-- wrong -- either it was accurate once and drifted after a later swap, or
-- it was never applied for this table and both tables' current state came
-- from somewhere else entirely.
CREATE TABLE IF NOT EXISTS ooni.citizenlab ON CLUSTER oonidata_cluster
(
    `domain` String,
    `url` String,
    `cc` FixedString(32),
    `category_code` String
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/citizenlab_flip/{shard}',
    '{replica}'
)
ORDER BY (domain, url, cc, category_code)
SETTINGS index_granularity = 4;

-- Was missing from this file entirely until 2026-08-11 -- devops' schema.sql
-- defines it, but it got dropped when this file was first put together.
-- See the note on `citizenlab` above re: the swapped ZK paths.
CREATE TABLE IF NOT EXISTS ooni.citizenlab_flip ON CLUSTER oonidata_cluster
(
    `domain` String,
    `url` String,
    `cc` FixedString(32),
    `category_code` String
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/citizenlab/{shard}',
    '{replica}'
)
ORDER BY (domain, url, cc, category_code)
SETTINGS index_granularity = 4;

-- Verified 2026-08-11 against live `SHOW CREATE TABLE`. Was missing 4
-- columns (`top_dns_rule_id`, `top_tcp_rule_id`, `top_tls_rule_id`,
-- `probe_id`) and all 3 indexes -- same `measurement_start_time_idx` /
-- `probe_cc_idx` / `probe_asn_idx` minmax trio as `obs_web`. Neither devops'
-- schema.sql nor the ooni/backend fixture this file originally followed had
-- any of these.
CREATE TABLE IF NOT EXISTS ooni.analysis_web_measurement ON CLUSTER oonidata_cluster
(
    `domain` String,
    `input` String,
    `test_name` String,
    `probe_asn` UInt32,
    `probe_as_org_name` String,
    `probe_cc` String,
    `resolver_asn` UInt32,
    `resolver_as_cc` String,
    `network_type` String,
    `measurement_start_time` DateTime64(3, 'UTC'),
    `measurement_uid` String,
    `ooni_run_link_id` String,
    `top_probe_analysis` Nullable(String),
    `top_dns_failure` Nullable(String),
    `top_tcp_failure` Nullable(String),
    `top_tls_failure` Nullable(String),
    `dns_blocked` Float32,
    `dns_down` Float32,
    `dns_ok` Float32,
    `tcp_blocked` Float32,
    `tcp_down` Float32,
    `tcp_ok` Float32,
    `tls_blocked` Float32,
    `tls_down` Float32,
    `tls_ok` Float32,
    `top_dns_rule_id` LowCardinality(String),
    `top_tcp_rule_id` LowCardinality(String),
    `top_tls_rule_id` LowCardinality(String),
    `probe_id` FixedString(64),
    INDEX measurement_start_time_idx measurement_start_time TYPE minmax GRANULARITY 2,
    INDEX probe_cc_idx probe_cc TYPE minmax GRANULARITY 1,
    INDEX probe_asn_idx probe_asn TYPE minmax GRANULARITY 1
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/analysis_web_measurement/{shard}',
    '{replica}'
)
PARTITION BY substring(measurement_uid, 1, 6)
PRIMARY KEY measurement_uid
ORDER BY (measurement_uid, measurement_start_time, probe_cc, probe_asn, domain)
SETTINGS index_granularity = 8192;

-- Verified 2026-08-11 against `SHOW CREATE TABLE ooni.obs_web` run directly
-- against production. Columns originally came from ooni/backend
-- ooniapi/services/oonimeasurements/tests/fixtures/initdb/clickhouse.sql,
-- but that fixture was missing `probe_id`, all three indexes, and the
-- PARTITION BY clause -- all added here to match prod exactly. Note the ZK
-- path is `.../obs_web_repl/{shard}`, not `.../obs_web/{shard}` -- the
-- table was evidently renamed from `obs_web_repl` to `obs_web` at some
-- point (RENAME TABLE doesn't change the underlying ZK path), so this is
-- not a typo to "fix".
CREATE TABLE IF NOT EXISTS ooni.obs_web ON CLUSTER oonidata_cluster
(
    `measurement_uid` String,
    `observation_idx` UInt16,
    `input` Nullable(String),
    `report_id` String,
    `ooni_run_link_id` String DEFAULT '',
    `measurement_start_time` DateTime64(3, 'UTC'),
    `software_name` String,
    `software_version` String,
    `test_name` String,
    `test_version` String,
    `bucket_date` String,
    `probe_asn` UInt32,
    `probe_cc` String,
    `probe_as_org_name` String,
    `probe_as_cc` String,
    `probe_as_name` String,
    `network_type` String,
    `platform` String,
    `origin` String,
    `engine_name` String,
    `engine_version` String,
    `architecture` String,
    `resolver_ip` String,
    `resolver_asn` UInt32,
    `resolver_cc` String,
    `resolver_as_org_name` String,
    `resolver_as_cc` String,
    `resolver_is_scrubbed` UInt8,
    `resolver_asn_probe` UInt32,
    `resolver_as_org_name_probe` String,
    `created_at` Nullable(DateTime('UTC')),
    `target_id` Nullable(String),
    `hostname` Nullable(String),
    `transaction_id` Nullable(UInt16),
    `ip` Nullable(String),
    `port` Nullable(UInt16),
    `ip_asn` Nullable(UInt32),
    `ip_as_org_name` Nullable(String),
    `ip_as_cc` Nullable(String),
    `ip_cc` Nullable(String),
    `ip_is_bogon` Nullable(UInt8),
    `dns_query_type` Nullable(String),
    `dns_failure` Nullable(String),
    `dns_engine` Nullable(String),
    `dns_engine_resolver_address` Nullable(String),
    `dns_answer_type` Nullable(String),
    `dns_answer` Nullable(String),
    `dns_answer_asn` Nullable(UInt32),
    `dns_answer_as_org_name` Nullable(String),
    `dns_t` Nullable(Float64),
    `tcp_failure` Nullable(String),
    `tcp_success` Nullable(UInt8),
    `tcp_t` Nullable(Float64),
    `tls_failure` Nullable(String),
    `tls_server_name` Nullable(String),
    `tls_outer_server_name` Nullable(String),
    `tls_echconfig` Nullable(String),
    `tls_version` Nullable(String),
    `tls_cipher_suite` Nullable(String),
    `tls_is_certificate_valid` Nullable(UInt8),
    `tls_end_entity_certificate_fingerprint` Nullable(String),
    `tls_end_entity_certificate_subject` Nullable(String),
    `tls_end_entity_certificate_subject_common_name` Nullable(String),
    `tls_end_entity_certificate_issuer` Nullable(String),
    `tls_end_entity_certificate_issuer_common_name` Nullable(String),
    `tls_end_entity_certificate_san_list` Array(String),
    `tls_end_entity_certificate_not_valid_after` Nullable(DateTime64(3, 'UTC')),
    `tls_end_entity_certificate_not_valid_before` Nullable(DateTime64(3, 'UTC')),
    `tls_certificate_chain_length` Nullable(UInt16),
    `tls_certificate_chain_fingerprints` Array(String),
    `tls_handshake_read_count` Nullable(UInt16),
    `tls_handshake_write_count` Nullable(UInt16),
    `tls_handshake_read_bytes` Nullable(UInt32),
    `tls_handshake_write_bytes` Nullable(UInt32),
    `tls_handshake_last_operation` Nullable(String),
    `tls_handshake_time` Nullable(Float64),
    `tls_t` Nullable(Float64),
    `http_request_url` Nullable(String),
    `http_network` Nullable(String),
    `http_alpn` Nullable(String),
    `http_failure` Nullable(String),
    `http_request_body_length` Nullable(UInt32),
    `http_request_method` Nullable(String),
    `http_runtime` Nullable(Float64),
    `http_response_body_length` Nullable(Int32),
    `http_response_body_is_truncated` Nullable(UInt8),
    `http_response_body_sha1` Nullable(String),
    `http_response_status_code` Nullable(UInt16),
    `http_response_header_location` Nullable(String),
    `http_response_header_server` Nullable(String),
    `http_request_redirect_from` Nullable(String),
    `http_request_body_is_truncated` Nullable(UInt8),
    `http_t` Nullable(Float64),
    `probe_analysis` Nullable(String),
    `probe_id` FixedString(64),
    INDEX measurement_start_time_idx measurement_start_time TYPE minmax GRANULARITY 2,
    INDEX probe_cc_idx probe_cc TYPE minmax GRANULARITY 1,
    INDEX probe_asn_idx probe_asn TYPE minmax GRANULARITY 1
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/obs_web_repl/{shard}',
    '{replica}'
)
PARTITION BY concat(substring(bucket_date, 1, 4), substring(bucket_date, 6, 2))
PRIMARY KEY (measurement_uid, observation_idx)
ORDER BY (measurement_uid, observation_idx, measurement_start_time, probe_cc, probe_asn)
SETTINGS index_granularity = 8192;

-- Completely rewritten 2026-08-11 against live `SHOW CREATE TABLE`. Neither
-- ooni/devops' schema.sql NOR ooni/backend's oonimeasurements fixture
-- matches production for this table -- ground truth is a third, simpler
-- design that doesn't match either repo's copy:
--   - Plain `ReplacingMergeTree`, not `ReplicatedReplacingMergeTree` --
--     this table is NOT replicated in production. Kept `ON CLUSTER` here
--     anyway so the DDL still fans out and creates an independent copy on
--     all 3 nodes (matching how devops actually issues this table's DDL),
--     but be aware the 3 copies will NOT stay in sync with each other the
--     way every other table in this file does -- that's a real production
--     fact, not a simplification for the test.
--   - No `PARTITION BY` at all (devops' schema.sql had `toYYYYMM(ts)`).
--   - One `current_state` column, not per-metric `*_current_state` columns
--     (that's `event_detector_cusums`, below, a different table). No
--     `obs_w_sum`/`w_sum`/`current_mean`/`last_ts` columns anywhere.
CREATE TABLE IF NOT EXISTS ooni.event_detector_changepoints ON CLUSTER oonidata_cluster
(
    `probe_asn` UInt32,
    `probe_cc` String,
    `domain` String,
    `ts` DateTime64(3, 'UTC'),
    `count_isp_resolver` Nullable(UInt32),
    `count_other_resolver` Nullable(UInt32),
    `count` Nullable(UInt32),
    `dns_isp_blocked` Nullable(Float32),
    `dns_other_blocked` Nullable(Float32),
    `tcp_blocked` Nullable(Float32),
    `tls_blocked` Nullable(Float32),
    `change_dir` Nullable(Int8),
    `s_pos` Nullable(Float32),
    `s_neg` Nullable(Float32),
    `current_state` String,
    `h` Nullable(Float32),
    `block_type` String
)
ENGINE = ReplacingMergeTree
ORDER BY (probe_asn, probe_cc, ts, domain)
SETTINGS index_granularity = 8192;

-- Completely rewritten 2026-08-11 against live `SHOW CREATE TABLE` -- same
-- situation as event_detector_changepoints above: devops' schema.sql
-- version (obs_w_sum/w_sum/PARTITION BY toYYYYMM/Replicated) doesn't match
-- production at all. Real production is also plain `ReplacingMergeTree`
-- (version column `ts` this time), no PARTITION BY, and tracks
-- current_state + last_change + last_ts per metric instead of weighted
-- sums. Same non-replicated caveat as above applies here too.
CREATE TABLE IF NOT EXISTS ooni.event_detector_cusums ON CLUSTER oonidata_cluster
(
    `probe_asn` UInt32,
    `probe_cc` String,
    `domain` String,
    `ts` DateTime64(3, 'UTC'),
    `dns_isp_blocked_current_state` String DEFAULT 'ok',
    `dns_isp_blocked_s_pos` Nullable(Float64),
    `dns_isp_blocked_s_neg` Nullable(Float64),
    `dns_other_blocked_current_state` String DEFAULT 'ok',
    `dns_other_blocked_s_pos` Nullable(Float64),
    `dns_other_blocked_s_neg` Nullable(Float64),
    `tcp_blocked_current_state` String DEFAULT 'ok',
    `tcp_blocked_s_pos` Nullable(Float64),
    `tcp_blocked_s_neg` Nullable(Float64),
    `tls_blocked_current_state` String DEFAULT 'ok',
    `tls_blocked_s_pos` Nullable(Float64),
    `tls_blocked_s_neg` Nullable(Float64),
    `dns_isp_blocked_last_change` Int8 DEFAULT 0,
    `dns_isp_blocked_last_ts` Nullable(DateTime64(3, 'UTC')),
    `dns_other_blocked_last_change` Int8 DEFAULT 0,
    `dns_other_blocked_last_ts` Nullable(DateTime64(3, 'UTC')),
    `tcp_blocked_last_change` Int8 DEFAULT 0,
    `tcp_blocked_last_ts` Nullable(DateTime64(3, 'UTC')),
    `tls_blocked_last_change` Int8 DEFAULT 0,
    `tls_blocked_last_ts` Nullable(DateTime64(3, 'UTC'))
)
ENGINE = ReplacingMergeTree(ts)
ORDER BY (probe_asn, probe_cc, domain)
SETTINGS index_granularity = 8192;

-- No definition exists anywhere in ooni/devops (see header note); ported from
-- ooni/backend ooniapi/services/{ooniprobe,oonirun,testlists}/tests/fixtures/initdb/01-scheme.sql
-- (CollapsingMergeTree -> ReplicatedCollapsingMergeTree). Verified
-- 2026-08-11 against live `SHOW CREATE TABLE`: exact match, including the
-- ZK path -- no changes needed despite having no devops source to check
-- against originally.
CREATE TABLE IF NOT EXISTS ooni.url_priorities ON CLUSTER oonidata_cluster
(
    `sign` Int8,
    `category_code` String,
    `cc` String,
    `domain` String,
    `url` String,
    `priority` Int32
)
ENGINE = ReplicatedCollapsingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/url_priorities/{shard}',
    '{replica}',
    sign
)
ORDER BY (category_code, cc, domain, url, priority)
SETTINGS index_granularity = 1024;

CREATE TABLE IF NOT EXISTS ooni.faulty_measurements ON CLUSTER oonidata_cluster
(
    `ts` DateTime64(3, 'UTC') DEFAULT now64(),
    `type` String,
    `uid` UUID DEFAULT generateUUIDv4(),
    `probe_cc` String,
    `probe_asn` UInt32,
    `details` String
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/faulty_measurements/{shard}',
    '{replica}'
)
ORDER BY (ts, type, probe_cc, probe_asn, uid);
