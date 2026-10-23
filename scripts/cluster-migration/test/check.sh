#!/bin/bash
# Checks that schema.sql and the migrations agree: loads schema.sql into one database and every
# migrations/NNN_*.sql, in order, into another, then compares each table's definition and Keeper path.
# Needs docker compose; set COMPOSE="podman compose" to use podman.
set -euo pipefail
cd "$(dirname "$0")"
compose=${COMPOSE:-docker compose}
q() { $compose exec -T clickhouse clickhouse-client -u admin --password admin "$@"; }
work=$(mktemp -d)
trap '$compose down -v >/dev/null 2>&1; rm -rf "$work"' EXIT

$compose up -d
for _ in $(seq 60); do
    q -q "SELECT 1 FROM system.zookeeper WHERE path = '/'" </dev/null >/dev/null 2>&1 && break
    sleep 1
done

for db in from_schema from_migrations; do
    q -q "CREATE DATABASE $db ON CLUSTER oonidata_cluster FORMAT Null" </dev/null
done
q --database from_schema --multiquery <../schema.sql >/dev/null
for f in ../migrations/[0-9][0-9][0-9]_*.sql; do
    echo "applying $(basename "$f")"
    q --database from_migrations --multiquery <"$f" >/dev/null
done

# each table's definition and Keeper path, with the database name and UUIDs blanked
snapshot() {
    q -q "
        SELECT t.name,
               replaceAll(replaceAll(replaceRegexpAll(t.create_table_query, '[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', '<uuid>'),
                          '$1.', '<db>.'), '/$1/', '/<db>/'),
               replaceAll(r.zookeeper_path, '/$1/', '/<db>/')
        FROM system.tables AS t
        LEFT JOIN system.replicas AS r ON r.database = t.database AND r.table = t.name
        WHERE t.database = '$1'
        ORDER BY t.name
        FORMAT TSV" </dev/null
}
snapshot from_schema >"$work/schema.tsv"
snapshot from_migrations >"$work/migrations.tsv"
if ! diff -u "$work/schema.tsv" "$work/migrations.tsv"; then
    echo "schema.sql and the migrations disagree: the diff above is schema.sql (-) against the migrations (+)"
    exit 1
fi
echo "schema.sql and the migrations agree on all $(wc -l <"$work/schema.tsv") tables"
