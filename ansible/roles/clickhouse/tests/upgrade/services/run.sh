#!/bin/bash
# Checks the ooniapi services and fastpath against a ClickHouse holding OONI data, before and
# after upgrading it (README.md):
#   ./run.sh up                  the six services (published images), fastpath's daemon,
#                                Postgres and Valkey, on the ClickHouse container's network
#   ./run.sh record NAME         every request in requests.txt -> out/NAME.json
#   ./run.sh submit [N]          N measurements through ooniprobe -> fastpath -> ClickHouse -> API
#   ./run.sh s3feed DAY CC       fastpath's S3 feeder: one day of one country into ClickHouse
#   ./run.sh compare BEFORE AFTER [AFTER2...]
#   ./run.sh down
# CLICKHOUSE_CONTAINER, CLICKHOUSE_NETWORK, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD: the ClickHouse
# (default: realdata-ch, the ooni-backend-data skill's local copy); values.env: the dataset.
# IMAGE_TAG picks the services' images (default latest). Uses podman.
set -euo pipefail
cd "$(dirname "$0")"
set -a; . ./values.env; set +a
export CLICKHOUSE_CONTAINER=${CLICKHOUSE_CONTAINER:-realdata-ch} CLICKHOUSE_USER=${CLICKHOUSE_USER:-testuser}
export CLICKHOUSE_PASSWORD=${CLICKHOUSE_PASSWORD:-testuser}
NET=${CLICKHOUSE_NETWORK:-realdata}
TAG=${IMAGE_TAG:-latest}
CH_URL="clickhouse://$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD@$CLICKHOUSE_CONTAINER:9000/ooni"
SVCS=(oonimeasurements ooniprobe oonirun testlists ooniauth oonifindings)
export SERVICE_PORTS=oonimeasurements=18101,ooniprobe=18102,oonirun=18103,testlists=18104,ooniauth=18105,oonifindings=18106
PG=postgresql://postgres:postgres@svccheck-pg:5432/ooni
ENVS=(-e CLICKHOUSE_URL=$CH_URL -e POSTGRESQL_URL=$PG -e VALKEY_URL=valkey://svccheck-valkey:6379
      -e JWT_ENCRYPTION_KEY=0123456789abcdef -e ACCOUNT_ID_HASHING_KEY=0123456789abcdef
      -e PROMETHEUS_METRICS_PASSWORD=testme -e S3_BUCKET_NAME=ooni-data-eu-fra -e COLLECTOR_ID=999
      -e "RATE_LIMITS=100000/minute;10000000/day;10000000/7day" -e 'FASTPATH_URLS=["http://svccheck-fastpath:8472"]')
mkdir -p out/fastpath/lib out/fastpath/data
chmod a+rwX out/fastpath/lib out/fastpath/data  # fastpath runs as uid 1420, and makes its own subdirectories
sed "s#CLICKHOUSE_URL#$CH_URL#" fastpath.conf > out/fastpath/fastpath.conf
FP=(-v $PWD/out/fastpath/fastpath.conf:/etc/ooni/fastpath.conf:ro,Z -v $PWD/out/fastpath/lib:/var/lib/fastpath:Z
    -v $PWD/out/fastpath/data:/data:Z)

down() {
  for s in "${SVCS[@]}" fastpath pg valkey; do podman rm -f -v svccheck-$s >/dev/null 2>&1 || true; done
}
up() {
  down
  podman run -d --name svccheck-pg --network $NET --memory 1g -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=ooni \
    docker.io/library/postgres:17 >/dev/null
  podman run -d --name svccheck-valkey --network $NET --memory 512m docker.io/valkey/valkey:8.1-alpine >/dev/null
  for i in $(seq 60); do podman exec svccheck-pg pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
  sleep 2
  # The services share one set of Postgres migrations
  podman run --rm --network $NET -e OONI_PG_URL=$PG docker.io/ooni/api-oonirun:$TAG alembic upgrade head >out/migrations.log 2>&1
  # fastpath as in production: a daemon that ooniprobe sends measurements to
  podman run -d --name svccheck-fastpath --network $NET --memory 2g "${FP[@]}" docker.io/ooni/fastpath:$TAG \
    ./run_fastpath --clickhouse-url "$CH_URL" --stdout --write-to-disk >/dev/null
  port=18101
  for s in "${SVCS[@]}"; do
    podman run -d --name svccheck-$s --network $NET -p 127.0.0.1:$port:80 --memory 1g "${ENVS[@]}" \
      docker.io/ooni/api-$s:$TAG >/dev/null
    port=$((port + 1))
  done
  sleep 10
  port=18101
  for s in "${SVCS[@]}"; do
    echo "$s: $(curl -s -m 10 http://127.0.0.1:$port/health)"
    port=$((port + 1))
  done
  echo "(ooniprobe's health needs the anonymous credentials manifest in S3, ooniauth's AWS SES: both report errors here)"
}
record() { python3 record.py "out/$1.json"; }
submit() { python3 submit.py "${1:-3}"; }
s3feed() {
  podman run --rm --name svccheck-fastpath-s3 --network $NET --memory 2g "${FP[@]}" docker.io/ooni/fastpath:$TAG \
    ./run_fastpath --clickhouse-url "$CH_URL" --stdout --noapi --start-day "$1" \
    --end-day "$(date -d "$1 + 1 day" +%F)" --ccs "$2" >out/s3feed.log 2>&1
  podman exec $CLICKHOUSE_CONTAINER clickhouse-client -u $CLICKHOUSE_USER --password $CLICKHOUSE_PASSWORD -q \
    "SELECT count(), countIf(anomaly = 't'), countIf(confirmed = 't'), countIf(msm_failure = 't') FROM ooni.fastpath
     WHERE probe_cc = '$2' AND toDate(measurement_start_time) = '$1' FORMAT Vertical"
}
compare() { python3 compare.py $(for f in "$@"; do echo "out/$f.json"; done); }
cmd=$1; shift
$cmd "$@"
