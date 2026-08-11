-- Schema for the test cluster.
--
-- Sourced from two places:
--  * ooni/devops scripts/cluster-migration/schema.sql -- the actual
--    production DDL for `fastpath`, `citizenlab`, `jsonl`,
--    `analysis_web_measurement`, `event_detector_changepoints` and
--    `faulty_measurements`. These are reproduced close to verbatim
--    (ReplicatedReplacingMergeTree, ON CLUSTER oonidata_cluster, the
--    '/clickhouse/{cluster}/tables/<db>/<table>/{shard}' zk path convention).
--  * ooni/backend column definitions for `obs_web` and `analysis_web_measurement`
--    (ooniapi/services/oonimeasurements/tests/fixtures/initdb/clickhouse.sql)
--    and `fastpath`/`citizenlab`/`jsonl`/`event_detector_changepoints`
--    (ooniapi/services/oonimeasurements/tests/migrations/0_clickhouse_init_tables.sql).
--    The backend repo's copies are plain MergeTree/ReplacingMergeTree because
--    they're used for single-node CI tests; here they're converted to their
--    replicated equivalents so we exercise the same replication path prod
--    uses. `obs_web` does not appear in devops' schema.sql (it's created by
--    a different repo/pipeline not in scope here), so its DDL below is
--    derived from the backend fixture's column list.
--
-- All DDL runs ON CLUSTER so it exercises ClickHouse's distributed_ddl queue
-- (the same mechanism prod uses to apply schema changes to all 3 replicas).

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

CREATE TABLE IF NOT EXISTS ooni.citizenlab ON CLUSTER oonidata_cluster
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
    `tls_ok` Float32
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/analysis_web_measurement/{shard}',
    '{replica}'
)
PARTITION BY substring(measurement_uid, 1, 6)
PRIMARY KEY measurement_uid
ORDER BY (measurement_uid, measurement_start_time, probe_cc, probe_asn, domain)
SETTINGS index_granularity = 8192;

-- Derived from ooni/backend ooniapi/services/oonimeasurements/tests/fixtures/initdb/clickhouse.sql
-- (converted from ReplacingMergeTree to its replicated equivalent).
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
    `probe_analysis` Nullable(String)
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/obs_web/{shard}',
    '{replica}'
)
PRIMARY KEY (measurement_uid, observation_idx)
ORDER BY (measurement_uid, observation_idx, measurement_start_time, probe_cc, probe_asn)
SETTINGS index_granularity = 8192;

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
    `dns_isp_blocked_current_state` String DEFAULT 'ok',
    `dns_isp_blocked_s_pos` Nullable(Float32),
    `dns_isp_blocked_s_neg` Nullable(Float32),
    `dns_other_blocked_current_state` String DEFAULT 'ok',
    `dns_other_blocked_s_pos` Nullable(Float32),
    `dns_other_blocked_s_neg` Nullable(Float32),
    `tcp_blocked_current_state` String DEFAULT 'ok',
    `tcp_blocked_s_pos` Nullable(Float32),
    `tcp_blocked_s_neg` Nullable(Float32),
    `tls_blocked_current_state` String DEFAULT 'ok',
    `tls_blocked_s_pos` Nullable(Float32),
    `tls_blocked_s_neg` Nullable(Float32),
    `change_dir` Nullable(Int8),
    `current_state` String DEFAULT 'ok',
    `s_pos` Nullable(Float32),
    `s_neg` Nullable(Float32),
    `h` Nullable(Float32),
    `block_type` String
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/event_detector_changepoints/{shard}',
    '{replica}'
)
PARTITION BY toYYYYMM(ts)
ORDER BY (probe_asn, probe_cc, ts, domain)
SETTINGS index_granularity = 8192;

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
