# ClickHouse schema migrations

`../schema.sql` is the schema as it is now: read it to see a table, and load it to build a new
cluster. A change to an existing cluster's schema goes in a numbered file here, applied once, in
order, on one node (its DDL uses `ON CLUSTER`):

    clickhouse-client --database ooni --multiquery < migrations/NNN_description.sql

- Every schema change updates `schema.sql` and adds a migration. `../test/check.sh`, which CI runs,
  fails unless `schema.sql` gives the same tables as all the migrations in order.
- `000_baseline.sql` is `schema.sql` as of ooni/devops#521. Don't edit it, or a migration that has
  been applied: fix forward with a new one.
- Start each file with what it does to production: whether it rewrites data (a mutation, e.g.
  `MODIFY COLUMN` or `MATERIALIZE`), how long it took on a copy, and what readers see meanwhile.
- Say in the PR when it was applied to production.

## Rebuilding counters_asn_test_list

Nothing rebuilds the view's counts by itself: it only counts new fastpath inserts. Restore
`counters_asn_test_list_data` from a backup before the view (a view without its table makes every
fastpath insert fail). If the table is lost with no backup, recreate it from `schema.sql` and count the
two weeks that test-list/urls reads again from fastpath, from the rows inserted before the table
existed (the view counts the rest):

```sql
INSERT INTO ooni.counters_asn_test_list_data
SELECT toStartOfWeek(measurement_start_time) AS week, probe_cc, probe_asn, input, count() AS msmt_cnt
FROM ooni.fastpath INNER JOIN ooni.citizenlab ON fastpath.input = citizenlab.url
WHERE measurement_start_time >= toStartOfWeek(now() - INTERVAL 1 WEEK) AND test_name = 'web_connectivity'
  AND update_time < (SELECT metadata_modification_time FROM system.tables
                     WHERE database = 'ooni' AND name = 'counters_asn_test_list_data')
GROUP BY week, probe_cc, probe_asn, input
```
