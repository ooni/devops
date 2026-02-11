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
    `time` DateTime DEFAULT now(),
    `type` String,
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
ORDER BY (time, type, probe_cc, probe_asn);
