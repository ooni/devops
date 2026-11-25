# Tests

`run.sh` checks what the role's README says it does, against ClickHouse 24.8.6.70
(production's version) in containers, using the real
`ansible/group_vars/clickhouse/vars.yml` with its secrets replaced by test values:

- `test_sql_objects.py` runs the role's SQL tasks against an empty node and three
  nodes seeded like production's data1-3 (`seed/`), and checks that every node ends up
  like the empty one; that each user logs in with its password from vars, can do what
  its grants allow and nothing else, and has its settings; that ids, quota assignments,
  roles granted by hand and objects not in vars are kept, and the objects dropped with
  `clickhouse_sql_objects_drop_unlisted`;
  that a second run changes nothing; that queries running during the role never fail;
  and that task output shows errors but no password or hash.
- `apt_pin.sh` checks, on Debian 12 against packages.clickhouse.com, that with the
  role's pin file apt installs `clickhouse_version` and not the newest release.

Needs docker compose (or rootless podman with
`DOCKER_HOST=unix:///run/user/$(id -u)/podman/podman.sock`), ansible-playbook and PyYAML.
`KEEP=1` leaves the containers running; `SKIP_APT_PIN=1` skips the apt test. The
ansible output of each run is in `out/`.
