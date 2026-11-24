# Services check

Do the ooniapi services and fastpath still work, and give the same answers, after a ClickHouse
upgrade? `run.sh` runs the published images of all six services (`docker.io/ooni/api-*`),
fastpath's daemon, Postgres and Valkey against a ClickHouse that holds OONI data, and checks
them before and after you upgrade that ClickHouse:

    ./run.sh up
    ./run.sh submit 3          # a probe's path: ooniprobe -> fastpath -> ClickHouse -> API
    ./run.sh record before     # 55 requests to the ClickHouse-backed endpoints
    # ... upgrade the ClickHouse (same volume, same network) ...
    ./run.sh record after
    ./run.sh record after2     # a second run tells changes from noise
    ./run.sh compare before after after2
    ./run.sh submit 3
    ./run.sh s3feed 2026-11-08 IS   # fastpath's S3 feeder: one day of one country
    ./run.sh down

`compare` gives each request one of:

- **same**: identical, apart from timings and generated ids;
- **reordered**: the same rows in another order;
- **varies**: differs between the runs on the new version too, so not caused by the upgrade
  (ties in ORDER BY, approximate functions, random choices);
- **CHANGED** or **BROKEN**: look at it.

It exits 1 for CHANGED or BROKEN.

`submit` keeps the order above because its rows stay in `fastpath` (report ids with collector
id `999`): before the upgrade it runs before recording, after the upgrade after recording, so
that its rows are in both recordings or in neither. It doesn't delete them, since a DELETE on
`fastpath` can rewrite a part of tens of GB. `s3feed` adds a real day of one country.

The ClickHouse is `CLICKHOUSE_CONTAINER` on `CLICKHOUSE_NETWORK` (default `realdata-ch` on
`realdata`, the local copy of real data from the ooni-backend-data skill), as
`CLICKHOUSE_USER`/`CLICKHOUSE_PASSWORD`. `values.env` holds the measurements, country and dates
the requests use; set them from your dataset. `IMAGE_TAG` picks the images (default `latest`).

Expected without AWS: ooniprobe's `/health` reports the anonymous credentials manifest (S3), and
ooniauth's AWS SES; the requests to their ClickHouse endpoints still work.

## 24.8.6.70 -> 25.3.14.14, 2026-11-10

On the local copy (360 GB, 302 million `fastpath` rows), with the images of 2026-11-06/09:
the same 50 of 55 requests answered 200 on both versions (the other 5: `quotas_summary` needs a
login, the two health checks above, and the circumvention endpoints below). Every difference
was timings, ids, row order, or `aggregation/analysis`, whose Loni values use `quantile(0.95)`,
an approximation that gives other values on 25.3 (but the same on every 25.3 run). Probe
submissions reached ClickHouse in 0.1 s and the API in 0.2 s on both; fastpath's daemon
reconnected by itself after the upgrade; the S3 feeder wrote Iceland's 2,740 measurements of
2026-11-08 in 75 s on 25.3.

Found on the way, on both versions, in ooni/backend: `/api/_/circumvention_stats_by_country`
and `circumvention_runtime_stats` answer 400 when their window has a Kosovo (`XK`)
measurement, as their response model rejects `XK` as a country code.
