non_admin_usernames: []
clickhouse_base_path: /data/clickhouse

# The replicated tables, minus the ones only data1 holds data for. Private
# tables go to their own bucket: R2 tokens grant access per bucket, and
# researchers may be given read access to the measurement tables.
clickhouse_backup_jobs:
  - name: measurements
    s3_bucket: ooni-clickhouse-backup
    include_tables: ["*"]
    exclude_tables: "{{ clickhouse_backup_private_tables + clickhouse_backup_data1_tables }}"
  - name: private
    s3_bucket: ooni-clickhouse-backup-private
    include_tables: "{{ clickhouse_backup_private_tables }}"
    exclude_tables: []

# After each run, report the tables on data1-3 that no backup covers;
# data1's own tables are backed up by data1
clickhouse_backup_check_cluster: oonidata_cluster
clickhouse_backup_backed_up_elsewhere: "{{ clickhouse_backup_data1_tables }}"
