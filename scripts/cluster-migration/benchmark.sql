SELECT
    countIf (
        anomaly = 't'
        AND confirmed = 'f'
        AND msm_failure = 'f'
    ) AS anomaly_count,
    countIf (
        confirmed = 't'
        AND msm_failure = 'f'
    ) AS confirmed_count,
    countIf (msm_failure = 't') AS failure_count,
    countIf (
        anomaly = 'f'
        AND confirmed = 'f'
        AND msm_failure = 'f'
    ) AS ok_count,
    COUNT(*) AS measurement_count,
    domain
FROM
    fastpath
WHERE
    measurement_start_time >= '2024-11-01'
    AND measurement_start_time < '2024-11-10'
    AND probe_cc = 'IT'
GROUP BY
    domain;

SELECT
    COUNT(*) AS measurement_count,
    domain
FROM
    analysis_web_measurement
WHERE
    measurement_start_time >= '2024-11-01'
    AND measurement_start_time < '2024-11-10'
    AND probe_cc = 'IT'
GROUP BY
    domain;

ALTER TABLE ooni.analysis_web_measurement ON CLUSTER oonidata_cluster MODIFY
ORDER BY
    (
        measurement_start_time,
        probe_cc,
        probe_asn,
        domain,
        measurement_uid
    )
ALTER TABLE ooni.analysis_web_measurement ON CLUSTER oonidata_cluster ADD INDEX IF NOT EXISTS measurement_start_time_idx measurement_start_time TYPE minmax GRANULARITY 2;

ALTER TABLE ooni.analysis_web_measurement ON CLUSTER oonidata_cluster MATERIALIZE INDEX measurement_start_time_idx;

ALTER TABLE ooni.analysis_web_measurement ON CLUSTER oonidata_cluster ADD INDEX IF NOT EXISTS probe_cc_idx probe_cc TYPE minmax GRANULARITY 1;

ALTER TABLE ooni.analysis_web_measurement ON CLUSTER oonidata_cluster MATERIALIZE INDEX probe_cc_idx;