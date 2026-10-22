# Tests for the clickhouse_backup role

`./run.sh` runs them all, in about seven minutes:

- `alert_rules_test.yml`: promtool unit tests of the backup alerts in
  `roles/prometheus/files/alert_rules.yml`, then amtool checks that
  Alertmanager's config is valid and routes them to the right receivers.
- `test_schedule.py`: which runs start a full backup and what gets pruned,
  over months of daily and weekly runs with failures, ClickHouse and the
  bucket stubbed.
- `test_e2e.py`: the real thing, in the containers of `compose.yml`:
  ClickHouse at production's version, MinIO standing in for R2, the script
  in a Debian bookworm Python with bookworm's boto3, node_exporter,
  Prometheus with the repo's alert rules, Alertmanager with the repo's
  routes, and a stand-in for Slack. Full and incremental backups, a
  restore, a failed run, an interrupted full, the month's new full and
  pruning, and the Slack messages and emails each one causes.

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
