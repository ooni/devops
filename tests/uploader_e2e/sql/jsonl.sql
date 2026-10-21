-- production-shaped definition (as in ooni/backend ooniapi/common/fixtures), used by the uploader end-to-end test
CREATE TABLE default.jsonl
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
ENGINE = ReplacingMergeTree(update_time)
ORDER BY (report_id, input, measurement_uid)
SETTINGS index_granularity = 8192
