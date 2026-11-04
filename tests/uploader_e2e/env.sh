#!/bin/bash
# Test environment for the uploader: MinIO (versioned buckets, like ooni-data-eu-fra), ClickHouse 24.8.6.70
# (production's version) and the fastpath image production runs.
# usage: env.sh up|down     needs FASTPATH_IMAGE; DOCKER (docker|podman), WORKERS, QUEUE optional
set -eu
T=$(cd "$(dirname "$0")" && pwd); WORK=${WORK:-$T/work}; DOCKER=${DOCKER:-docker}; NET=uploader-e2e
MINIO_IMAGE=${MINIO_IMAGE:-docker.io/pgsty/minio:RELEASE.2026-08-04T00-00-00Z}
CH_IMAGE=${CH_IMAGE:-docker.io/clickhouse/clickhouse-server:24.8.6.70}
ch() { $DOCKER exec -i uploader-e2e-ch clickhouse-client -u test --password test "$@"; }
up() {
  : "${FASTPATH_IMAGE:?set FASTPATH_IMAGE, e.g. ooni/fastpath:<tag> from ansible/host_vars}"
  mkdir -p $WORK/spool && chmod 0777 $WORK/spool
  $DOCKER network inspect $NET >/dev/null 2>&1 || $DOCKER network create $NET >/dev/null
  $DOCKER run -d --name uploader-e2e-minio --network $NET -p 127.0.0.1:19900:9000 \
    -e MINIO_ROOT_USER=e2eadmin -e MINIO_ROOT_PASSWORD=e2esecret123 $MINIO_IMAGE server /data >/dev/null
  $DOCKER run -d --name uploader-e2e-ch --network $NET -p 127.0.0.1:19901:9000 \
    -e CLICKHOUSE_USER=test -e CLICKHOUSE_PASSWORD=test $CH_IMAGE >/dev/null
  for i in $(seq 90); do ch -q "SELECT 1" >/dev/null 2>&1 && break; sleep 1; done
  for f in $T/sql/*.sql; do ch --multiquery < $f; done
  python3 $T/buckets.py
  $DOCKER run -d --name uploader-e2e-fastpath --network $NET -p 127.0.0.1:19903:8472 --user root \
    -e FASTPATH_QUEUE_PUT_TIMEOUT=-1 -e FASTPATH_NUM_WORKERS=${WORKERS:-2} -e FASTPATH_QUEUE_SIZE=${QUEUE:-100} \
    -v $T/conf/fastpath.conf:/etc/ooni/fastpath.conf:ro,z -v $WORK/spool:/var/lib/ooniapi/measurements:z \
    $FASTPATH_IMAGE python /home/fastpath/app/run_fastpath --write-to-disk --stdout >/dev/null
  for i in $(seq 60); do curl -s -o /dev/null http://127.0.0.1:19903/ && break; sleep 1; done
}
down() {
  $DOCKER rm -f uploader-e2e-fastpath uploader-e2e-minio uploader-e2e-ch >/dev/null 2>&1 || true
  $DOCKER network rm $NET >/dev/null 2>&1 || true
}
case ${1:-} in up) up;; down) down;; *) echo "usage: $0 up|down"; exit 1;; esac
