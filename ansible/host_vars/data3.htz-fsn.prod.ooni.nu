non_admin_usernames: []
clickhouse_base_path: /data/clickhouse

# The replicated tables, minus the ones only data1 holds data for. Private
# tables go to their own bucket: R2 tokens grant access per bucket, and
# researchers may be given read access to the measurement tables.
clickhouse_backup_jobs:
  - name: measurements
    s3_bucket: ooni-clickhouse-backup
    include_tables: []
    exclude_tables: "{{ clickhouse_backup_private_tables + clickhouse_backup_data1_tables }}"
  - name: private
    s3_bucket: ooni-clickhouse-backup-private
    include_tables: "{{ clickhouse_backup_private_tables }}"
    exclude_tables: []
