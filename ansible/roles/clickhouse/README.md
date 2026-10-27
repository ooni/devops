# clickhouse

Installs and configures ClickHouse on Debian, and manages SQL-driven users,
quotas and grants.

Vendored from [idealista/clickhouse_role](https://github.com/idealista/clickhouse_role)
by Idealista S.A.U. and contributors, tag `3.5.2`
(`5ca82f11c0bd554c4b52045a57cb0e0bc6addb61`, the last upstream release, December 2024),
under the Apache License 2.0, kept unchanged in `LICENSE`. OONI has modified the files
in this directory: the changes are listed below and in this repo's git history. Edit it
here like any other role in this repo.

## What it does

1. Installs ClickHouse `clickhouse_version` from packages.clickhouse.com, with the
   repository key pinned in `files/clickhouse-repo-keyring.asc`, and pins the
   `clickhouse-*` packages to that version in `/etc/apt/preferences.d/clickhouse`, so
   `apt upgrade` can't move them (`tasks/install-Debian.yml`). To upgrade or
   downgrade, change `clickhouse_version` and rerun the role.
2. Writes `config.xml` and `users.xml` from `templates/` (`tasks/config/clickhouse.yml`)
   and the systemd unit (`tasks/service/clickhouse.yml`).
3. Applies `clickhouse_custom_users`, `clickhouse_custom_quotas` and
   `clickhouse_custom_grants` as SQL (`tasks/config/{users,quotas,grants}.yml`,
   `templates/DDL/`), each behind its `clickhouse_role_manage_*` toggle:
   - users and quotas are created if missing and `ALTER`ed if they exist, so changes
     in vars apply to existing objects too; `ALTER` keeps grants and assignments;
   - each grantee's privileges are replaced in one `GRANT ... WITH REPLACE OPTION`,
     so privileges it keeps are never revoked, even briefly; roles granted by hand are
     left alone;
   - users and quotas that aren't in vars are dropped when
     `clickhouse_sql_objects_drop_unlisted` is true.

   The SQL runs through `clickhouse-client --config-file
   {{ clickhouse_admin_client_config }}`, a root-only file with `clickhouse_admin_user`'s
   credentials, and the statements go in on stdin, so task output isn't hidden. Only at
   `-vvv` does ansible show the statements, and with them the users' password hashes.

## Changes from upstream

- Removed what this repo doesn't use: the JDBC bridge, clickhouse-copier, SQL
  databases, SQL roles and settings profiles, config/users files copied from the
  playbook, the `clickhouse_install_db` toggle, LDAP/Kerberos/`GRANTEES`/`DEFAULT
  ROLE` in `CREATE USER`, Galaxy metadata and the standalone repo's scaffolding.
- Existing SQL objects were never updated: upstream only ran `CREATE ... IF NOT
  EXISTS`, and listed existing objects by `storage = 'local directory'` while
  ClickHouse 24.8 says `local_directory`, so it never saw them.
- Upstream started its grants with `REVOKE ALL ON *.* FROM ALL EXCEPT <XML users>`,
  so every SQL-driven user lost its privileges on every run until they were granted
  again.
- Upstream put `--password` on every command line and hid all SQL task output with
  `no_log`.
- Upstream installed `clickhouse_packages` at `clickhouse_version` but didn't pin them,
  so `apt upgrade` would install the newest release in the repo (26.8.36.3 instead of
  24.8.6.70, checked 2026-10-27).
- Debian 12+ apt keyring (`signed-by`, from upstream PR #80) with the key pinned; the
  entry upstream added without it is removed, as apt refuses both.

## Vars for SQL-driven objects

```yaml
clickhouse_custom_users:
  - name: user1
    password_type: sha256_hash
    password: "<sha256 hex of the password>"
    networks: ["IP '10.0.0.0/8'"]      # HOST clause, ANY when omitted
    settings:                          # SETTINGS clause, NONE when omitted
      - "readonly = 0"
      - "max_execution_time = 30 CONST"

clickhouse_custom_quotas:
  - name: user1
    intervals:                         # FOR clause, limits kept when omitted
      - "INTERVAL 600 second MAX queries = 12000"
    to: [user1]                        # TO clause, assignment kept when omitted

clickhouse_custom_grants:
  - databases: [db1]
    tables: ["*"]
    privileges: [SELECT]
    to: [user1]
```

XML users, profiles and quotas (`clickhouse_default_users`, `clickhouse_admin_users`,
`clickhouse_default_profiles`, `clickhouse_default_quotas`) go into `users.xml`; see
`templates/users.xml.j2`.
