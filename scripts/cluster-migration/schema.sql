CREATE TABLE
    ooni.jsonl ON CLUSTER oonidata_cluster (
        `report_id` String,
        `input` String,
        `s3path` String,
        `linenum` Int32,
        `measurement_uid` String,
        `date` Date,
        `source` String,
        `update_time` DateTime64 (3) MATERIALIZED now64 ()
    ) ENGINE = ReplicatedReplacingMergeTree (
        '/clickhouse/{cluster}/tables/ooni/jsonl/{shard}',
        '{replica}',
        update_time
    )
ORDER BY
    (report_id, input, measurement_uid) SETTINGS index_granularity = 8192;

CREATE TABLE
    ooni.fastpath ON CLUSTER oonidata_cluster (
        `measurement_uid` String,
        `report_id` String,
        `input` String,
        `probe_cc` LowCardinality (String),
        `probe_asn` Int32,
        `test_name` LowCardinality (String),
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
        `update_time` DateTime64 (3) MATERIALIZED now64 (),
        `test_version` String,
        `architecture` String,
        `engine_name` LowCardinality (String),
        `engine_version` String,
        `test_runtime` Float32,
        `blocking_type` String,
        `test_helper_address` LowCardinality (String),
        `test_helper_type` LowCardinality (String),
        `ooni_run_link_id` Nullable (UInt64),
        INDEX fastpath_rid_idx report_id TYPE minmax GRANULARITY 1,
        INDEX measurement_uid_idx measurement_uid TYPE minmax GRANULARITY 8
    ) ENGINE = ReplicatedReplacingMergeTree (
        '/clickhouse/{cluster}/tables/ooni/fastpath/{shard}',
        '{replica}',
        update_time
    )
ORDER BY
    (
        measurement_start_time,
        report_id,
        input,
        measurement_uid
    ) SETTINGS index_granularity = 8192;

CREATE TABLE
    ooni.citizenlab ON CLUSTER oonidata_cluster (
        `domain` String,
        `url` String,
        `cc` FixedString (32),
        `category_code` String
    ) ENGINE = ReplicatedReplacingMergeTree (
        '/clickhouse/{cluster}/tables/ooni/citizenlab/{shard}',
        '{replica}'
    )
ORDER BY
    (domain, url, cc, category_code) SETTINGS index_granularity = 4;

CREATE TABLE
    ooni.citizenlab_flip ON CLUSTER oonidata_cluster (
        `domain` String,
        `url` String,
        `cc` FixedString (32),
        `category_code` String
    ) ENGINE = ReplicatedReplacingMergeTree (
        '/clickhouse/{cluster}/tables/ooni/citizenlab_flip/{shard}',
        '{replica}'
    )
ORDER BY
    (domain, url, cc, category_code) SETTINGS index_granularity = 4;

CREATE TABLE
    analysis_web_measurement ON CLUSTER oonidata_cluster (
        `domain` String,
        `input` String,
        `test_name` String,
        `probe_asn` UInt32,
        `probe_as_org_name` String,
        `probe_cc` String,
        `resolver_asn` UInt32,
        `resolver_as_cc` String,
        `network_type` String,
        `measurement_start_time` DateTime64 (3, 'UTC'),
        `measurement_uid` String,
        `ooni_run_link_id` String,
        `top_probe_analysis` Nullable (String),
        `top_dns_failure` Nullable (String),
        `top_tcp_failure` Nullable (String),
        `top_tls_failure` Nullable (String),
        `dns_blocked` Float32,
        `dns_down` Float32,
        `dns_ok` Float32,
        `tcp_blocked` Float32,
        `tcp_down` Float32,
        `tcp_ok` Float32,
        `tls_blocked` Float32,
        `tls_down` Float32,
        `tls_ok` Float32
    ) ENGINE = ReplicatedReplacingMergeTree (
        '/clickhouse/{cluster}/tables/ooni/analysis_web_measurement/{shard}',
        '{replica}'
    )
PARTITION BY
    substring(measurement_uid, 1, 6) PRIMARY KEY measurement_uid
ORDER BY
    (
        measurement_uid,
        measurement_start_time,
        probe_cc,
        probe_asn,
        domain
    ) SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS event_detector_changepoints ON CLUSTER oonidata_cluster(
    `probe_asn` UInt32,
    `probe_cc` String,
    `domain` String,
    `ts` DateTime64(3, 'UTC'),
    `count_isp_resolver` Nullable(UInt32),
    `count_other_resolver` Nullable(UInt32),
    `count` Nullable(UInt32),
    `dns_isp_blocked` Nullable(float),
    `dns_other_blocked` Nullable(float),
    `tcp_blocked` Nullable(float),
    `tls_blocked` Nullable(float),
    `last_ts` DateTime64(3, 'UTC'),
    `dns_isp_blocked_obs_w_sum` Nullable(float),
    `dns_isp_blocked_w_sum` Nullable(float),
    `dns_isp_blocked_s_pos` Nullable(float),
    `dns_isp_blocked_s_neg` Nullable(float),
    `dns_other_blocked_obs_w_sum` Nullable(float),
    `dns_other_blocked_w_sum` Nullable(float),
    `dns_other_blocked_s_pos` Nullable(float),
    `dns_other_blocked_s_neg` Nullable(float),
    `tcp_blocked_obs_w_sum` Nullable(float),
    `tcp_blocked_w_sum` Nullable(float),
    `tcp_blocked_s_pos` Nullable(float),
    `tcp_blocked_s_neg` Nullable(float),
    `tls_blocked_obs_w_sum` Nullable(float),
    `tls_blocked_w_sum` Nullable(float),
    `tls_blocked_s_pos` Nullable(float),
    `tls_blocked_s_neg` Nullable(float),
    `change_dir` Nullable(Int8),
    `s_pos` Nullable(float),
    `s_neg` Nullable(float),
    `current_mean` Nullable(float),
    `h` Nullable(float)
    )
ENGINE = ReplicatedReplacingMergeTree (
        '/clickhouse/{cluster}/tables/ooni/event_detector_changepoints/{shard}',
        '{replica}'
    )
PARTITION BY toYYYYMM(ts)
ORDER BY (probe_asn, probe_cc, ts, domain)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS event_detector_cusums ON CLUSTER oonidata_cluster
(
    `probe_asn` UInt32,
    `probe_cc` String,
    `domain` String,
    `ts` DateTime64(3, 'UTC'),
    `dns_isp_blocked_obs_w_sum` Nullable(Float64),
    `dns_isp_blocked_w_sum` Nullable(Float64),
    `dns_isp_blocked_s_pos` Nullable(Float64),
    `dns_isp_blocked_s_neg` Nullable(Float64),

    `dns_other_blocked_obs_w_sum` Nullable(Float64),
    `dns_other_blocked_w_sum` Nullable(Float64),
    `dns_other_blocked_s_pos` Nullable(Float64),
    `dns_other_blocked_s_neg` Nullable(Float64),

    `tcp_blocked_obs_w_sum` Nullable(Float64),
    `tcp_blocked_w_sum` Nullable(Float64),
    `tcp_blocked_s_pos` Nullable(Float64),
    `tcp_blocked_s_neg` Nullable(Float64),

    `tls_blocked_obs_w_sum` Nullable(Float64),
    `tls_blocked_w_sum` Nullable(Float64),
    `tls_blocked_s_pos` Nullable(Float64),
    `tls_blocked_s_neg` Nullable(Float64)
)
ENGINE = ReplicatedReplacingMergeTree (
        '/clickhouse/{cluster}/tables/ooni/event_detector_cusums/{shard}',
        '{replica}'
)
PARTITION BY toYYYYMM(ts)
ORDER BY (probe_asn, probe_cc, domain)
SETTINGS index_granularity = 8192;

ALTER TABLE event_detector_changepoints ON CLUSTER oonidata_cluster ADD COLUMN `block_type` String;

-- faulty measurements
CREATE TABLE IF NOT EXISTS faulty_measurements ON CLUSTER oonidata_cluster
(
    `ts` DateTime64(3, 'UTC') DEFAULT now64(),
    `type` String,
    `uid` UUID DEFAULT generateUUIDv4(),
    -- geoip lookup result for the probe IP
    `probe_cc` String,
    `probe_asn` UInt32,
    -- JSON-encoded details about the anomaly
    `details` String
)
ENGINE = ReplicatedReplacingMergeTree (
        '/clickhouse/{cluster}/tables/ooni/faulty_measurements/{shard}',
        '{replica}'
)
ORDER BY (ts, type, probe_cc, probe_asn, uid);

-- Anonymous Credentials fields
ALTER TABLE ooni.fastpath ADD COLUMN IF NOT EXISTS `is_verified` Int8;
ALTER TABLE ooni.fastpath ADD COLUMN IF NOT EXISTS `nym` Nullable(String);
ALTER TABLE ooni.fastpath ADD COLUMN IF NOT EXISTS `zkp_request` Nullable(String);
ALTER TABLE ooni.fastpath ADD COLUMN IF NOT EXISTS `age_range` Nullable(String);
ALTER TABLE ooni.fastpath ADD COLUMN IF NOT EXISTS `msm_range` Nullable(String);

ALTER TABLE ooni.fastpath DROP COLUMN IF EXISTS `nym`;
ALTER TABLE ooni.fastpath DROP COLUMN IF EXISTS `zkp_request`;
ALTER TABLE ooni.fastpath DROP COLUMN IF EXISTS `age_range`;
ALTER TABLE ooni.fastpath DROP COLUMN IF EXISTS `msm_range`;
ALTER TABLE ooni.fastpath MODIFY COLUMN `is_verified` LowCardinality(String) DEFAULT 'u';


-- =====================================================================
-- Tables below this point were added to make this file a complete
-- ClickHouse schema definition, not just the fastpath/jsonl/citizenlab/
-- analysis_web_measurement/event_detector_*/faulty_measurements set this
-- file originally covered as a migration target (see migrate-tables.py -
-- this file's original scope was "what that specific migration effort
-- needed", not "every table the ooni database has).
--
-- Reconciled primarily from ooni/backend's
-- ooniapi/common/fixtures/initdb/ (the most accurate source available -
-- it's what the backend services' own integration tests are checked
-- against), cross-referenced against:
--   - ooni/devops's ansible/group_vars/clickhouse/vars.yml
--     (clickhouse_custom_grants), which is the closest thing to a
--     ground-truth list of which tables actually exist in production
--   - ooni/backend's fastpath/fastpath/db.py and reprocessor.py, for the
--     two tables (obs_openvpn, new_jsonl) that ansible's grants name but
--     that appear nowhere in either backend's fixtures or this file
--
-- Converted from common/fixtures/initdb's `default.<table>` (single-node
-- test-only convention) to `ooni.<table>` to match the database this
-- file's own pre-existing tables use, and the ansible grants
-- (`databases: [ooni, oonitest]`) confirming that's what production
-- actually runs. Engines converted to their Replicated* form with the
-- same path/replica convention already used above, except where the
-- engine has no Replicated variant (EmbeddedRocksDB, Join) - those keep
-- their original engine and rely on ON CLUSTER alone to create the same
-- (unreplicated, per-node) structure everywhere.
-- =====================================================================

-- url_priorities: written by testlists (INSERT grant in ansible), read
-- by ooniprobe's check-in prioritization (common/prio.py).
CREATE TABLE ooni.url_priorities ON CLUSTER oonidata_cluster (
    `sign` Int8,
    `category_code` String,
    `cc` String,
    `domain` String,
    `url` String,
    `priority` Int32
) ENGINE = ReplicatedCollapsingMergeTree(
        '/clickhouse/{cluster}/tables/ooni/url_priorities/{shard}',
        '{replica}',
        sign
    )
ORDER BY (category_code, cc, domain, url, priority)
SETTINGS index_granularity = 1024;

-- test_groups: small static lookup table (test_name -> test_group). Join
-- engine has no Replicated variant; ON CLUSTER alone gives every node its
-- own identical copy.
CREATE TABLE ooni.test_groups ON CLUSTER oonidata_cluster (
    `test_name` String,
    `test_group` String
) ENGINE = Join(ANY, LEFT, test_name);

-- accounts: ooniauth-related account role lookup. EmbeddedRocksDB is
-- inherently per-node local storage - no Replicated variant, same as
-- test_groups above.
CREATE TABLE ooni.accounts ON CLUSTER oonidata_cluster (
    `account_id` FixedString(32),
    `role` String
) ENGINE = EmbeddedRocksDB
PRIMARY KEY account_id;

-- msmt_feedback: user feedback on individual measurements (oonimeasurements).
CREATE TABLE ooni.msmt_feedback ON CLUSTER oonidata_cluster (
    `measurement_uid` String,
    `account_id` String,
    `status` String,
    `update_time` DateTime64(3) MATERIALIZED now64()
) ENGINE = ReplicatedReplacingMergeTree(
        '/clickhouse/{cluster}/tables/ooni/msmt_feedback/{shard}',
        '{replica}'
    )
ORDER BY (measurement_uid, account_id)
SETTINGS index_granularity = 4;

-- fingerprints_dns / fingerprints_http: DNS/HTTP blockpage fingerprint
-- databases used by fastpath's scoring logic. EmbeddedRocksDB, as above.
CREATE TABLE ooni.fingerprints_dns ON CLUSTER oonidata_cluster (
    `name` String,
    `scope` Enum8('nat' = 1, 'isp' = 2, 'prod' = 3, 'inst' = 4, 'vbw' = 5, 'fp' = 6),
    `other_names` String,
    `location_found` String,
    `pattern_type` Enum8('full' = 1, 'prefix' = 2, 'contains' = 3, 'regexp' = 4),
    `pattern` String,
    `confidence_no_fp` UInt8,
    `expected_countries` String,
    `source` String,
    `exp_url` String,
    `notes` String
) ENGINE = EmbeddedRocksDB
PRIMARY KEY name;

CREATE TABLE ooni.fingerprints_http ON CLUSTER oonidata_cluster (
    `name` String,
    `scope` Enum8('nat' = 1, 'isp' = 2, 'prod' = 3, 'inst' = 4, 'vbw' = 5, 'fp' = 6, 'injb' = 7, 'prov' = 8),
    `other_names` String,
    `location_found` String,
    `pattern_type` Enum8('full' = 1, 'prefix' = 2, 'contains' = 3, 'regexp' = 4),
    `pattern` String,
    `confidence_no_fp` UInt8,
    `expected_countries` String,
    `source` String,
    `exp_url` String,
    `notes` String
) ENGINE = EmbeddedRocksDB
PRIMARY KEY name;

-- asnmeta: ASN metadata (org name, country) lookup.
CREATE TABLE ooni.asnmeta ON CLUSTER oonidata_cluster (
    `asn` UInt32,
    `org_name` String,
    `cc` String,
    `changed` Date,
    `aut_name` String,
    `source` String
) ENGINE = ReplicatedMergeTree(
        '/clickhouse/{cluster}/tables/ooni/asnmeta/{shard}',
        '{replica}'
    )
ORDER BY (asn, changed);

-- incidents: oonifindings' incident reports.
CREATE TABLE IF NOT EXISTS ooni.incidents ON CLUSTER oonidata_cluster (
    `update_time` DateTime DEFAULT now(),
    `create_time` DateTime DEFAULT now(),
    `start_time` DateTime DEFAULT now(),
    `end_time` Nullable(DateTime),
    `creator_account_id` FixedString(32),
    `reported_by` String,
    `email_address` String,
    `id` String,
    `title` String,
    `text` String,
    `event_type` LowCardinality(String),
    `published` UInt8,
    `deleted` UInt8 DEFAULT 0,
    `CCs` Array(FixedString(2)),
    `ASNs` Array(UInt32),
    `domains` Array(String),
    `tags` Array(String),
    `links` Array(String),
    `test_names` Array(String),
    `short_description` String
) ENGINE = ReplicatedReplacingMergeTree(
        '/clickhouse/{cluster}/tables/ooni/incidents/{shard}',
        '{replica}',
        update_time
    )
ORDER BY (id)
SETTINGS index_granularity = 1;

-- oonirun: oonirun's descriptor storage (distinct from the Postgres
-- OONIRunLink table the oonirun *service* actually reads/writes day to
-- day - this ClickHouse table appears to be an older or parallel store;
-- kept here because it's a real, granted table (ansible), not because
-- its current role has been independently confirmed against the
-- service's current code).
CREATE TABLE IF NOT EXISTS ooni.oonirun ON CLUSTER oonidata_cluster (
    `ooni_run_link_id` UInt64,
    `descriptor_creation_time` DateTime64(3),
    `translation_creation_time` DateTime64(3),
    `creator_account_id` FixedString(32),
    `archived` UInt8 DEFAULT 0,
    `descriptor` String,
    `author` String,
    `name` String,
    `short_description` String,
    `icon` String
) ENGINE = ReplicatedReplacingMergeTree(
        '/clickhouse/{cluster}/tables/ooni/oonirun/{shard}',
        '{replica}',
        translation_creation_time
    )
ORDER BY (ooni_run_link_id, descriptor_creation_time)
SETTINGS index_granularity = 1;

-- obs_web: per-observation (DNS/TCP/TLS/HTTP) breakdown backing
-- analysis_web_measurement. Granted INSERT to fastpath (ansible).
CREATE TABLE ooni.obs_web ON CLUSTER oonidata_cluster (
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
    `probe_analysis` Nullable(String)
) ENGINE = ReplicatedReplacingMergeTree(
        '/clickhouse/{cluster}/tables/ooni/obs_web/{shard}',
        '{replica}'
    )
PRIMARY KEY (measurement_uid, observation_idx)
ORDER BY (
        measurement_uid,
        observation_idx,
        measurement_start_time,
        probe_cc,
        probe_asn
    )
SETTINGS index_granularity = 8192;

-- obs_openvpn: per-observation OpenVPN experiment results. This table's
-- only definition anywhere in ooni/backend is embedded directly in
-- fastpath/fastpath/db.py's click_create_table_obs_openvpn() (that
-- function is currently dead code - setup_clickhouse() has it behind a
-- `# FIXME` and never calls it - but the DDL inside is still the only
-- record of this table's intended shape). Reproduced here with one
-- correction: the source has `last_handshake_transaction_id Uint8`,
-- which is not a valid ClickHouse type (case-sensitive; the real type is
-- `UInt8`) - as written, that CREATE TABLE statement would fail if
-- anyone actually ran it. Worth fixing at the source too.
CREATE TABLE ooni.obs_openvpn ON CLUSTER oonidata_cluster (
    `anomaly` Bool,
    `bootstrap_time` Float32,
    `confirmed` Bool,
    `failure` String,
    `input` String,
    `last_handshake_transaction_id` UInt8,
    `measurement_start_time` DateTime,
    `measurement_uid` String,
    `minivpn_version` String,
    `obfs4_version` String,
    `obfuscation` String,
    `platform` String,
    `probe_asn` Int32,
    `probe_cc` String,
    `probe_network_name` String,
    `provider` String,
    `remote` String,
    `report_id` String,
    `resolver_asn` Int32,
    `resolver_ip` String,
    `resolver_network_name` String,
    `software_name` String,
    `software_version` String,
    `success` Bool,
    `success_handshake` Bool,
    `success_icmp` Bool,
    `success_urlgrab` Bool,
    `test_runtime` Float32,
    `test_start_time` DateTime,
    `transport` String
) ENGINE = ReplicatedReplacingMergeTree(
        '/clickhouse/{cluster}/tables/ooni/obs_openvpn/{shard}',
        '{replica}'
    )
ORDER BY (measurement_start_time, report_id, input)
SETTINGS index_granularity = 8;

-- new_jsonl: named in ansible's grants (fastpath has INSERT on it
-- alongside `jsonl`), and referenced by
-- fastpath/fastpath/reprocessor.py's update_jsonl_clickhouse_table()
-- (itself marked `# FIXME table name`), but there's no CREATE TABLE for
-- it anywhere in ooni/backend. reprocessor.py inserts
-- (report_id, input, measurement_uid, s3path, linenum, date, source) -
-- the same seven columns as this file's own `ooni.jsonl` above (which
-- already has `date`/`source`, unlike backend's default.jsonl fixture,
-- which lacks them) - so this is reproduced as an identical structure to
-- `ooni.jsonl`, on the working assumption `new_jsonl` is an in-progress
-- rename/replacement of it rather than something structurally different.
-- Confirm this against whoever owns the reprocessor.py migration before
-- relying on it.
CREATE TABLE ooni.new_jsonl ON CLUSTER oonidata_cluster (
    `report_id` String,
    `input` String,
    `s3path` String,
    `linenum` Int32,
    `measurement_uid` String,
    `date` Date,
    `source` String,
    `update_time` DateTime64(3) MATERIALIZED now64()
) ENGINE = ReplicatedReplacingMergeTree(
        '/clickhouse/{cluster}/tables/ooni/new_jsonl/{shard}',
        '{replica}',
        update_time
    )
ORDER BY (report_id, input, measurement_uid)
SETTINGS index_granularity = 8192;

-- counters_test_list / counters_asn_test_list: materialized views feeding
-- test-list popularity counters from fastpath x citizenlab joins.
CREATE MATERIALIZED VIEW ooni.counters_test_list ON CLUSTER oonidata_cluster (
    `day` DateTime,
    `probe_cc` String,
    `input` String,
    `msmt_cnt` UInt64
) ENGINE = ReplicatedSummingMergeTree(
        '/clickhouse/{cluster}/tables/ooni/counters_test_list/{shard}',
        '{replica}'
    )
PARTITION BY day
ORDER BY (probe_cc, input)
SETTINGS index_granularity = 8192
AS
SELECT
    toDate(measurement_start_time) AS day,
    probe_cc,
    input,
    count() AS msmt_cnt
FROM ooni.fastpath
INNER JOIN ooni.citizenlab ON fastpath.input = citizenlab.url
WHERE (measurement_start_time < now()) AND (measurement_start_time > (now() - toIntervalDay(8))) AND (test_name = 'web_connectivity')
GROUP BY day, probe_cc, input;

CREATE MATERIALIZED VIEW ooni.counters_asn_test_list ON CLUSTER oonidata_cluster (
    `week` DateTime,
    `probe_cc` String,
    `probe_asn` UInt32,
    `input` String,
    `msmt_cnt` UInt64
) ENGINE = ReplicatedSummingMergeTree(
        '/clickhouse/{cluster}/tables/ooni/counters_asn_test_list/{shard}',
        '{replica}'
    )
ORDER BY (probe_cc, probe_asn, input)
SETTINGS index_granularity = 8192
AS
SELECT
    toStartOfWeek(measurement_start_time) AS week,
    probe_cc,
    probe_asn,
    input,
    count() AS msmt_cnt
FROM ooni.fastpath
INNER JOIN ooni.citizenlab ON fastpath.input = citizenlab.url
WHERE (measurement_start_time < now()) AND (measurement_start_time > (now() - toIntervalDay(8))) AND (test_name = 'web_connectivity')
GROUP BY week, probe_cc, probe_asn, input;

-- faulty_measurements: common/fixtures/initdb/03-faulty-msm-detection.sql
-- has the same columns as this file's existing definition above, plus an
-- async-insert setting this file's version was missing. (That fixture
-- also sets `wait_for_async_insert = 0`, which is a query/session-level
-- setting, not a valid table-level one - confirmed by actually running
-- this against a real clickhouse-server 24.8.6.70, the version this
-- cluster runs per ansible/group_vars/clickhouse/vars.yml's
-- clickhouse_version: MODIFY SETTING wait_for_async_insert fails with
-- Code: 115 UNKNOWN_SETTING.)
ALTER TABLE ooni.faulty_measurements MODIFY SETTING async_insert = 1;
