-- Give counters_asn_test_list an explicit target table, counters_asn_test_list_data, instead of the
-- hidden .inner_id.<uuid> table it made itself, and add week to its sorting key. The hidden table is
-- sorted by (probe_cc, probe_asn, input) only, so merges add up the weeks of each key and keep one
-- arbitrary week: the reader, ooniprobe's test-list/urls (common/prio.py), sums the current and previous
-- week and misses every count whose merged row says an older week. The new table keeps one row per
-- week, can be backed up and restored by name, and lets the view be dropped or changed without losing
-- its rows.
-- In production: not a mutation. The old rows are wrong, so they aren't copied: the two weeks the
-- reader uses are counted again from fastpath, from rows inserted before the new view existed (the
-- view counts the rest). Unlike the view, this also counts uploads that came more than 8 days after
-- their measurement. Queries on counters_asn_test_list fail between the DROP and the RENAME, for about
-- a second; test-list/urls returns the corrected counts from then on.

CREATE TABLE IF NOT EXISTS counters_asn_test_list_data ON CLUSTER oonidata_cluster
(
    `week` DateTime,
    `probe_cc` String,
    `probe_asn` UInt64,
    `input` String,
    `msmt_cnt` UInt64
)
ENGINE = ReplicatedSummingMergeTree('/clickhouse/{cluster}/tables/{database}/counters_asn_test_list_data/{shard}', '{replica}')
ORDER BY (probe_cc, probe_asn, input, week)
SETTINGS index_granularity = 8192;

-- Count fastpath's new rows from now on, alongside the old view
CREATE MATERIALIZED VIEW IF NOT EXISTS counters_asn_test_list_new ON CLUSTER oonidata_cluster TO counters_asn_test_list_data
(
    `week` DateTime,
    `probe_cc` String,
    `probe_asn` UInt64,
    `input` String,
    `msmt_cnt` UInt64
)
AS SELECT
    toStartOfWeek(measurement_start_time) AS week,
    probe_cc,
    probe_asn,
    input,
    count() AS msmt_cnt
FROM fastpath
INNER JOIN citizenlab ON fastpath.input = citizenlab.url
WHERE (measurement_start_time < now()) AND (measurement_start_time > (now() - toIntervalDay(8))) AND (test_name = 'web_connectivity')
GROUP BY
    week,
    probe_cc,
    probe_asn,
    input;

-- Count the two weeks the reader sums, from the rows the new view didn't see
INSERT INTO counters_asn_test_list_data SELECT
    toStartOfWeek(measurement_start_time) AS week,
    probe_cc,
    probe_asn,
    input,
    count() AS msmt_cnt
FROM fastpath
INNER JOIN citizenlab ON fastpath.input = citizenlab.url
WHERE (measurement_start_time >= toStartOfWeek(now() - toIntervalWeek(1))) AND (test_name = 'web_connectivity') AND (update_time < (
    SELECT metadata_modification_time
    FROM system.tables
    WHERE (database = currentDatabase()) AND (name = 'counters_asn_test_list_new')
))
GROUP BY
    week,
    probe_cc,
    probe_asn,
    input;

-- The old view and its hidden table. They exist only on data1 and data3, hence IF EXISTS.
DROP TABLE IF EXISTS counters_asn_test_list ON CLUSTER oonidata_cluster SYNC;

RENAME TABLE counters_asn_test_list_new TO counters_asn_test_list ON CLUSTER oonidata_cluster;
