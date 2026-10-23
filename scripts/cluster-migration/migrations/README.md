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
