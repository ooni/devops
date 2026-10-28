tls_cert_dir: /var/lib/dehydrated/certs
ssl_domains:
   - "data1.htz-fsn.prod.ooni.nu"
   - "airflow.prod.ooni.io"

# Only the tables whose data only data1 holds; data3 backs up the rest
clickhouse_backup_jobs:
  - name: data1
    s3_bucket: ooni-clickhouse-backup
    include_tables: "{{ clickhouse_backup_data1_tables }}"
    exclude_tables: []
