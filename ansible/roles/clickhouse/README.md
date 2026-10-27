# clickhouse

Installs and configures ClickHouse on Debian.

Vendored from [idealista/clickhouse_role](https://github.com/idealista/clickhouse_role)
by Idealista S.A.U. and contributors, tag `3.5.2`
(`5ca82f11c0bd554c4b52045a57cb0e0bc6addb61`, the last upstream release, December 2024),
under the Apache License 2.0, kept unchanged in `LICENSE`. OONI has modified the files
in this directory: the changes are listed below and in this repo's git history. Edit it
here like any other role in this repo.

## Changes from upstream

- Removed what this repo doesn't use: the JDBC bridge, clickhouse-copier, SQL
  databases, config/users files copied from the playbook, the `clickhouse_install_db`
  toggle, Galaxy metadata and the standalone repo's scaffolding.
