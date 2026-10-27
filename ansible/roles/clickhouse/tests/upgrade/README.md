# Upgrade test

`run.sh` (`test_upgrade.py`) rolls a ClickHouse version bump out across the cluster with the
role, one host at a time, the way it's done in production:

1. Installs `FROM_VERSION` (default: production's `clickhouse_version`) on three Debian 12
   hosts with systemd, named like the production replicas (`compose.yml`), with the real
   group and host vars (secrets replaced by test values) and `deploy.yml`, which is what
   `deploy-clickhouse.yml` does to a replica without the nftables rules. As for a new cluster,
   the hosts are deployed with `--skip-tags clickhouse_schema` first, and the `ooni` database is
   created once Keeper has a quorum.
2. Sets `clickhouse_version` to `TO_VERSION` (default: `next_version`, the next hop of the
   upgrade plan in ooni/devops#477), then deploys each host with `--limit`, in turn, while a
   writer inserts a row every half second, on each node in turn. The hosts start with the
   apt source line the role's upstream version left, as production's do.

After each host it checks that the role succeeded, which includes the role's own check that
the server runs `clickhouse_version`; that the host's `clickhouse-server` is active under
systemd and its packages are `TO_VERSION`, pinned; and that every node answers and reaches
Keeper. It prints each node's version and Keeper role (leader or follower) and how many inserts
failed meanwhile: errors while versions are mixed are expected for some hops (see #477). At
the end every node must run `TO_VERSION`, take inserts, have no read-only or failing
replicated tables, and have every row whose insert succeeded.

    FROM_VERSION=25.3.14.14 TO_VERSION=25.8.29.51 ./run.sh

Needs docker compose (or rootless podman with
`DOCKER_HOST=unix:///run/user/$(id -u)/podman/podman.sock`), ansible-playbook (the
community.docker collection is installed into `cache/` if missing) and PyYAML, and network
access to packages.clickhouse.com. Downloaded packages are kept in `cache/debs` and copied
into each host's own apt cache before it's deployed, so each version is downloaded once.
`KEEP=1` leaves the hosts running. The ansible output of each deploy is in `out/`.

In CI (`.github/workflows/test_clickhouse_upgrade.yml`) it runs when a PR changes
`clickhouse_version` (from the base's version to the PR's) or how the role installs or
restarts ClickHouse, and by hand with any two versions.
