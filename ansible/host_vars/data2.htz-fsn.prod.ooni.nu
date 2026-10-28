# data2 takes no backups: data3 backs up the replicated tables. The role is here
# for restore, which reads data3's buckets when data2 is lost or re-imaged
# (docs/Runbooks.md, "ClickHouse backup").
clickhouse_backup_enabled: false
clickhouse_backup_jobs: "{{ clickhouse_backup_replicated_jobs }}"
