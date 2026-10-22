# Tests for the clickhouse_backup role

`./run.sh` runs them all, in about nine minutes:

- `alert_rules_test.yml`: promtool unit tests of the backup alerts in
  `roles/prometheus/files/alert_rules.yml`, then amtool checks that
  Alertmanager's config is valid and routes them to the right receivers.
- `test_schedule.py`: which runs start a full backup and what gets pruned,
  over months of daily and weekly runs with failures, ClickHouse and the
  bucket stubbed.
- `test_job.py`: how a job runs and what it reports, ClickHouse stubbed.
- `test_e2e.py`: the real thing, in the containers of `compose.yml`:
  two ClickHouse nodes at production's version (`data3`, where the backups
  run, and `data1`, in one test cluster), MinIO standing in for R2, the script
  on Debian bookworm with its python3-boto3, as on the hosts, node_exporter,
  Prometheus with the repo's alert rules, Alertmanager with the repo's
  routes, and a stand-in for Slack. Full and incremental backups, and
  restoring the full and each incremental of a chain, and an
  EmbeddedRocksDB table with its exported rows; a table created on `data1`
  only, which ClickHouseTableNotBackedUp must name; a failed run; an
  interrupted full, the month's new full, pruning and restoring what's
  left; and the Slack messages and emails each one causes.

The configs are rendered from the role's templates into `work/` by
`render.yml`, with the variables in `vars.yml`.

Needs docker compose, python3 with boto3, and ansible-core. With rootless
podman:

```bash
DOCKER_HOST=unix:///run/user/$(id -u)/podman/podman.sock ./run.sh
```

`KEEP=1 ./run.sh` leaves the containers up afterwards (Prometheus on
127.0.0.1:19990, Alertmanager on 19993); remove them with
`docker compose -f compose.yml down -v`.

GitHub runs it (`.github/workflows/test_clickhouse_backup.yml`) when a pull
request or a push to main changes this role, the alert rules or
Alertmanager's role.
