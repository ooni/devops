# Tests

`run.sh` (`test_replicas.py`) adds a replica to the cluster and removes it again the way the
runbook says (docs/Runbooks.md, "Adding and removing a replica"): by editing the cluster in
`ansible/group_vars/clickhouse/vars.yml` and rerunning the roles. It uses the real group and
host vars (secrets replaced by test values) and the configs the clickhouse role renders from
them, with one ClickHouse 24.8.6.70 container per production host, named and aliased like it
(`compose.yml`). It checks that:

- data1-3 form the Keeper ensemble and `oonidata_cluster`, and `oonidata_clickhouse` creates
  the `ooni` database from `scripts/cluster-migration/schema.sql` on each, but not on notebook1
  (in `[clickhouse]`, not a replica), and leaves existing databases alone;
- with data4 added to `clickhouse_remote_servers` and `clickhouse_macros`, and data1-3
  restarted one at a time, every node sees four replicas, data4 gets the database and catches
  up, and inserts and `ON CLUSTER` DDL reach it;
- with data4 removed and dropped from Keeper, every node sees three replicas, Keeper has no
  trace of it, `ON CLUSTER` DDL doesn't wait for it, and data1-3 still replicate;
- a re-imaged data4 (empty disk, same replica name) can be added again.

Needs docker compose (or rootless podman with
`DOCKER_HOST=unix:///run/user/$(id -u)/podman/podman.sock`), ansible-playbook and PyYAML.
`KEEP=1` leaves the containers running. The ansible output of each run is in `out/`.
