#!/bin/bash
# End-to-end test of the measurement uploader against the fastpath, a versioned S3 and ClickHouse.
# usage: scenario.sh LABEL
#   UPLOADER        the ooni_api_uploader.py to test (default: ansible/roles/fastpath/templates/ooni_api_uploader.py)
#   FASTPATH_IMAGE  e.g. ooni/fastpath:<tag> (default: the tag in ansible/host_vars/fastpath.prod.ooni.io/vars.yml)
#   REUPLOADER_NEW  ooni/backend reuploader/src/reuploader/main.py at master (scenario 4; skipped if unset)
#   REUPLOADER_OLD  the same file at the version production runs (optional)
#   DOCKER          docker (default) or podman
# The uploader runs every 20 s (the hourly timer, sped up) with quiet_minutes = 1. Fastpath workers are
# suspended (SIGSTOP) to make backlogs. Exits 1 if any measurement is not found the way Explorer finds it,
# if any S3 object was replaced, or if anything is left in the spool or the failed bucket.
set -u
python3 -c "import boto3, requests, clickhouse_driver" 2>/dev/null || { echo "needs: pip install boto3 requests clickhouse-driver"; exit 2; }
T=$(cd "$(dirname "$0")" && pwd); REPO=$(cd $T/../.. && pwd); LABEL=${1:-run}
export WORK=${WORK:-$T/work}; export DOCKER=${DOCKER:-docker}
export UPLOADER=${UPLOADER:-$REPO/ansible/roles/fastpath/templates/ooni_api_uploader.py}
export FASTPATH_IMAGE=${FASTPATH_IMAGE:-$(sed -n 's/^fastpath_image: *"\(.*\)"/\1/p' $REPO/ansible/host_vars/fastpath.prod.ooni.io/vars.yml)}
L=$WORK/logs/$LABEL; mkdir -p $L $WORK/cans; WORKERS=2; export WORKERS
CAN=raw/20261008/00/IT/webconnectivity/2026100800_IT_webconnectivity.n1.2.tar.gz   # public, 663 measurements
[ -s $WORK/cans/test.tar.gz ] || curl -sf -o $WORK/cans/test.tar.gz "https://ooni-data-eu-fra.s3.eu-central-1.amazonaws.com/$CAN"
workers() { $DOCKER exec uploader-e2e-fastpath sh -c "for p in /proc/[0-9]*/status; do awk '/^Pid/{p=\$2} /^PPid/{if (\$2==1) print p}' \$p; done" | sort -n | head -$WORKERS; }
stop_workers() { for p in $(workers); do $DOCKER exec uploader-e2e-fastpath sh -c "kill -STOP $p"; done; echo "   fastpath workers suspended"; }
cont_workers() { for p in $(workers); do $DOCKER exec uploader-e2e-fastpath sh -c "kill -CONT $p"; done; echo "   fastpath workers resumed"; }
step() { echo "== $(date -u +%T) $*"; }
post() { python3 $T/poster.py "$@"; }

echo "uploader: $UPLOADER"; echo "fastpath: $FASTPATH_IMAGE"
$T/env.sh down; rm -rf $WORK/spool $WORK/ledger.tsv $WORK/poster.offset $WORK/STOP_LOOP $WORK/PAUSE_LOOP; $T/env.sh up
(while [ ! -e $WORK/STOP_LOOP ]; do [ -e $WORK/PAUSE_LOOP ] || $T/uploader.sh >> $L/uploader.log 2>&1; sleep 20; done) &
LOOP=$!

step "S1 normal hour (5 h ago)"; post 5 40; sleep 100

step "S2 measurements written after their hour was uploaded (4 h ago), as on 2026-07-14"
post 4 30; sleep 100
stop_workers; post 4 40; sleep 80
cont_workers; sleep 120

step "S3 full fastpath queue: timeouts, failover to the failed bucket (3 h ago)"
stop_workers; post 3 140 --timeout 3 --threads 8; sleep 10; cont_workers; sleep 120

step "S4 reuploader re-sending into hours already uploaded"
if [ -n "${REUPLOADER_OLD:-}" ]; then
  for i in 1 2; do $T/reuploader.sh $REUPLOADER_OLD > $L/reuploader-old-$i.log 2>&1; echo "   old reuploader run $i: $(grep -c 'Successfully submitted' $L/reuploader-old-$i.log) submitted"; sleep 100; done
fi
if [ -n "${REUPLOADER_NEW:-}" ]; then
  $T/reuploader.sh $REUPLOADER_NEW > $L/reuploader-new.log 2>&1; echo "   reuploader: $(grep -c 'Submitted' $L/reuploader-new.log) submitted, $(grep -c 'Failed to process' $L/reuploader-new.log) failed"; sleep 100
fi

step "S5 interruptions (2 h ago): S3 unreachable during an upload, two uploaders at once"
touch $WORK/PAUSE_LOOP; sleep 25; post 2 20; sleep 70
S3_ENDPOINT=http://uploader-e2e-minio:9999 $T/uploader.sh > $L/uploader-s3down.log 2>&1; echo "   uploader with S3 unreachable: exit $?"
$T/uploader.sh > $L/uploader-concurrent-a.log 2>&1 & A=$!; $T/uploader.sh > $L/uploader-concurrent-b.log 2>&1 & B=$!; wait $A $B
echo "   concurrent runs: $(grep -l 'Another uploader is running' $L/uploader-concurrent-*.log 2>/dev/null | wc -l) exited on the lock"
rm -f $WORK/PAUSE_LOOP

step "final: wait until quiet, last upload, check"
sleep 90; touch $WORK/STOP_LOOP; wait $LOOP; $T/uploader.sh >> $L/uploader.log 2>&1
$DOCKER logs uploader-e2e-fastpath > $L/fastpath.log 2>&1
echo "   fastpath 'Failed to upload measurement' errors: $(grep -c 'Failed to upload measurement' $L/fastpath.log)"
python3 $T/check.py $LABEL; RC=$?
[ -n "${KEEP_ENV:-}" ] || $T/env.sh down
exit $RC
