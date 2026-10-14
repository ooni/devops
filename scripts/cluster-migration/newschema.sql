CREATE TABLE ooni.`.inner_id.67d6198a-5a25-4b3a-a57b-0d519ca9df7f` ON CLUSTER oonidata_cluster (
    `day` DateTime,
    `probe_cc` String,
    `input` String,
    `msmt_cnt` UInt64
) ENGINE = ReplicatedSummingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/.inner_id.67d6198a-5a25-4b3a-a57b-0d519ca9df7f/{shard}',
    '{replica}'
)
PARTITION BY day
ORDER BY (probe_cc, input)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.`.inner_id.6a72ceec-7e0e-4b65-a3ab-da2809202114` ON CLUSTER oonidata_cluster (
    `week` DateTime,
    `probe_cc` String,
    `probe_asn` UInt64,
    `input` String,
    `msmt_cnt` UInt64
) ENGINE = ReplicatedSummingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/.inner_id.6a72ceec-7e0e-4b65-a3ab-da2809202114/{shard}',
    '{replica}'
)
ORDER BY (probe_cc, probe_asn, input)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.analysis_web_measurement ON CLUSTER oonidata_cluster (
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
    INDEX measurement_start_time_idx (measurement_start_time) TYPE minmax GRANULARITY 2,
    INDEX probe_cc_idx (probe_cc) TYPE minmax GRANULARITY 1,
    INDEX probe_asn_idx (probe_asn) TYPE minmax GRANULARITY 1
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/analysis_web_measurement/{shard}',
    '{replica}'
)
PARTITION BY substring(measurement_uid, 1, 6)
PRIMARY KEY measurement_uid
ORDER BY (measurement_uid, measurement_start_time, probe_cc, probe_asn, domain)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.asnmeta (
    `asn` UInt32,
    `org_name` String,
    `cc` String,
    `changed` Date,
    `aut_name` String,
    `source` String
) ENGINE = MergeTree
ORDER BY (asn, changed)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.asnmeta_tmp (
    `asn` UInt32,
    `org_name` String,
    `cc` String,
    `changed` Date,
    `aut_name` String,
    `source` String
) ENGINE = MergeTree
ORDER BY (asn, changed)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.citizenlab ON CLUSTER oonidata_cluster (
    `domain` String,
    `url` String,
    `cc` FixedString(32),
    `category_code` String
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/citizenlab_flip/{shard}',
    '{replica}'
)
ORDER BY (domain, url, cc, category_code)
SETTINGS index_granularity = 4;

CREATE TABLE ooni.citizenlab_flip ON CLUSTER oonidata_cluster (
    `domain` String,
    `url` String,
    `cc` FixedString(32),
    `category_code` String
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/citizenlab/{shard}',
    '{replica}'
)
ORDER BY (domain, url, cc, category_code)
SETTINGS index_granularity = 4;

CREATE MATERIALIZED VIEW ooni.counters_asn_test_list ON CLUSTER oonidata_cluster (
    `week` DateTime,
    `probe_cc` String,
    `probe_asn` UInt64,
    `input` String,
    `msmt_cnt` UInt64
) ENGINE = ReplicatedSummingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/.inner_id.6a72ceec-7e0e-4b65-a3ab-da2809202114/{shard}',
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
WHERE
    (measurement_start_time < now())
    AND (measurement_start_time > (now() - toIntervalDay(8)))
    AND (test_name = 'web_connectivity')
GROUP BY week, probe_cc, probe_asn, input;

CREATE MATERIALIZED VIEW ooni.counters_test_list ON CLUSTER oonidata_cluster (
    `day` DateTime,
    `probe_cc` String,
    `input` String,
    `msmt_cnt` UInt64
) ENGINE = ReplicatedSummingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/.inner_id.67d6198a-5a25-4b3a-a57b-0d519ca9df7f/{shard}',
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
WHERE
    (measurement_start_time < now())
    AND (measurement_start_time > (now() - toIntervalDay(8)))
    AND (test_name = 'web_connectivity')
GROUP BY day, probe_cc, input;

CREATE TABLE ooni.event_detector_changepoints (
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
) ENGINE = ReplacingMergeTree
ORDER BY (probe_asn, probe_cc, ts, domain)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.event_detector_cusums (
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
) ENGINE = ReplacingMergeTree(ts)
ORDER BY (probe_asn, probe_cc, domain)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.fastpath ON CLUSTER oonidata_cluster (
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
    INDEX fastpath_rid_idx (report_id) TYPE minmax GRANULARITY 1,
    INDEX measurement_uid_idx (measurement_uid) TYPE minmax GRANULARITY 8
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/fastpath/{shard}',
    '{replica}',
    update_time
)
ORDER BY (measurement_start_time, report_id, input, measurement_uid)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.faulty_measurements ON CLUSTER oonidata_cluster (
    `ts` DateTime64(3, 'UTC') DEFAULT now64(),
    `type` String,
    `uid` UUID DEFAULT generateUUIDv4(),
    `probe_cc` String,
    `probe_asn` UInt32,
    `details` String
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/faulty_measurements/{shard}',
    '{replica}'
)
ORDER BY (ts, type, probe_cc, probe_asn, uid)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.fingerprints_dns (
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

CREATE TABLE ooni.fingerprints_dns_tmp (
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

CREATE TABLE ooni.fingerprints_http (
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

CREATE TABLE ooni.fingerprints_http_tmp (
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

CREATE TABLE ooni.jsonl ON CLUSTER oonidata_cluster (
    `report_id` String,
    `input` String,
    `s3path` String,
    `linenum` Int32,
    `measurement_uid` String,
    `date` Date,
    `source` String,
    `update_time` DateTime64(3) MATERIALIZED now64()
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/jsonl/{shard}',
    '{replica}',
    update_time
)
ORDER BY (report_id, input, measurement_uid)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.msmt_feedback ON CLUSTER oonidata_cluster (
    `measurement_uid` String,
    `account_id` String,
    `status` String,
    `update_time` DateTime64(3) DEFAULT now64(),
    `comment` String
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/msmt_feedback_new/{shard}',
    '{replica}'
)
ORDER BY (measurement_uid, account_id, update_time)
SETTINGS index_granularity = 4;

CREATE TABLE ooni.msmt_feedback_old ON CLUSTER oonidata_cluster (
    `measurement_uid` String,
    `account_id` String,
    `status` String,
    `update_time` DateTime64(3) MATERIALIZED now64(),
    `comment` String
) ENGINE = ReplicatedMergeTree(
    '/clickhouse/{cluster}/tables/ooni/msmt_feedback/{shard}',
    '{replica}'
)
ORDER BY (measurement_uid, account_id)
SETTINGS index_granularity = 4;

CREATE TABLE ooni.obs_http_middlebox ON CLUSTER oonidata_cluster (
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
    `created_at` Nullable(DateTime64(3, 'UTC')),
    `hirl_sent_0` Nullable(String),
    `hirl_sent_1` Nullable(String),
    `hirl_sent_2` Nullable(String),
    `hirl_sent_3` Nullable(String),
    `hirl_sent_4` Nullable(String),
    `hirl_received_0` Nullable(String),
    `hirl_received_1` Nullable(String),
    `hirl_received_2` Nullable(String),
    `hirl_received_3` Nullable(String),
    `hirl_received_4` Nullable(String),
    `hirl_failure` Nullable(String),
    `hirl_success` Nullable(UInt8),
    `hfm_diff` Nullable(String),
    `hfm_failure` Nullable(String),
    `hfm_success` Nullable(UInt8)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/obs_http_middlebox/{shard}',
    '{replica}'
)
PARTITION BY concat(substring(bucket_date, 1, 4), substring(bucket_date, 6, 2))
PRIMARY KEY (measurement_uid, observation_idx)
ORDER BY (measurement_uid, observation_idx, measurement_start_time)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.obs_openvpn ON CLUSTER oonidata_cluster (
    `anomaly` Int8,
    `bootstrap_time` Float32,
    `confirmed` Int8,
    `error` String,
    `failure` String,
    `input` String,
    `last_handshake_transaction_id` Int32,
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
    `success` Int8,
    `success_handshake` Int8,
    `success_icmp` Int8,
    `success_urlgrab` Int8,
    `tcp_connect_status_success` Int8,
    `test_runtime` Float32,
    `test_start_time` DateTime,
    `transport` String
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/obs_openvpn/{shard}',
    '{replica}'
)
ORDER BY (measurement_start_time, report_id, input)
SETTINGS index_granularity = 8;

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
    `probe_analysis` Nullable(String),
    INDEX measurement_start_time_idx (measurement_start_time) TYPE minmax GRANULARITY 2,
    INDEX probe_cc_idx (probe_cc) TYPE minmax GRANULARITY 1,
    INDEX probe_asn_idx (probe_asn) TYPE minmax GRANULARITY 1
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/obs_web_repl/{shard}',
    '{replica}'
)
PARTITION BY concat(substring(bucket_date, 1, 4), substring(bucket_date, 6, 2))
PRIMARY KEY (measurement_uid, observation_idx)
ORDER BY (measurement_uid, observation_idx, measurement_start_time, probe_cc, probe_asn)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.obs_web_ctrl ON CLUSTER oonidata_cluster (
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
    `hostname` String,
    `created_at` Nullable(DateTime64(3, 'UTC')),
    `ip` String,
    `port` Nullable(UInt16),
    `ip_asn` Nullable(UInt32),
    `ip_as_org_name` Nullable(String),
    `ip_as_cc` Nullable(String),
    `ip_cc` Nullable(String),
    `ip_is_bogon` Nullable(UInt8),
    `dns_failure` Nullable(String),
    `dns_success` Nullable(UInt8),
    `tcp_failure` Nullable(String),
    `tcp_success` Nullable(UInt8),
    `tls_failure` Nullable(String),
    `tls_success` Nullable(UInt8),
    `tls_server_name` Nullable(String),
    `http_request_url` Nullable(String),
    `http_failure` Nullable(String),
    `http_success` Nullable(UInt8),
    `http_response_body_length` Nullable(Int32)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{cluster}/tables/ooni/obs_web_ctrl/{shard}',
    '{replica}'
)
PARTITION BY concat(substring(bucket_date, 1, 4), substring(bucket_date, 6, 2))
PRIMARY KEY (measurement_uid, observation_idx)
ORDER BY (measurement_uid, observation_idx, measurement_start_time, hostname)
SETTINGS index_granularity = 8192;

CREATE TABLE ooni.session_expunge (
    `account_id` FixedString(32),
    `threshold` DateTime DEFAULT now()
) ENGINE = EmbeddedRocksDB
PRIMARY KEY account_id;

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
