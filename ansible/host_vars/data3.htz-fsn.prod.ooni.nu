non_admin_usernames: []
clickhouse_base_path: /data/clickhouse

# The replicated tables (group_vars)
clickhouse_backup_jobs: "{{ clickhouse_backup_replicated_jobs }}"

# After each run, report the tables on data1-3 that no backup covers;
# data1's own tables are backed up by data1
clickhouse_backup_check_cluster: oonidata_cluster
clickhouse_backup_backed_up_elsewhere: "{{ clickhouse_backup_data1_tables }}"
