-- Weekly anomaly/confirmed/ok counts per country, ASN and domain.
-- {start} and {end} are filled in by datadumps.py (UTC, end exclusive).
SELECT
    countIf(anomaly = 't' AND confirmed = 'f') AS anomaly_cnt,
    countIf(confirmed = 't') AS confirmed_cnt,
    countIf(anomaly = 'f' AND confirmed = 'f') AS ok_cnt,
    count() AS total_cnt,
    probe_cc,
    probe_asn,
    domain
FROM fastpath
WHERE measurement_start_time >= toDateTime({start:String}, 'UTC')
  AND measurement_start_time < toDateTime({end:String}, 'UTC')
  AND msm_failure = 'f'
GROUP BY probe_cc, probe_asn, domain
ORDER BY probe_cc, probe_asn, domain
