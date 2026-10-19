#!/bin/bash
# Test repair_cans.py on a bucket damaged the way ooni-data-eu-fra was.
#  1. tests/uploader_e2e/scenario.sh with the uploader as it was before the fix (ooni_api_uploader_before_fix.py):
#     its cans get overwritten (measurements written after their hour was uploaded, the reuploader re-sending)
#  2. snapshot the bucket and the jsonl table, run every repair step (dry run, then --apply), snapshot again
#  3. compare.py: only proven-redundant noncurrent versions deleted, nothing else changed, every measurement
#     that reached S3 served with its own body
# Same requirements as tests/uploader_e2e (FASTPATH_IMAGE, REUPLOADER_NEW/OLD, DOCKER, the uploader image).
set -u
H=$(cd "$(dirname "$0")" && pwd); D=$(cd $H/.. && pwd); REPO=$(cd $D/../.. && pwd); E2E=$REPO/tests/uploader_e2e
export WORK=${WORK:-$H/work}; mkdir -p $WORK
export AWS_ACCESS_KEY_ID=e2eadmin AWS_SECRET_ACCESS_KEY=e2esecret123
step() { echo "== $(date -u +%T) $*"; }

step "damage the test bucket with the uploader as it was before the fix"
KEEP_ENV=1 UPLOADER=$H/ooni_api_uploader_before_fix.py $E2E/scenario.sh before-fix > $WORK/damage.log 2>&1
grep -E "^   (ok|WRONG|jsonl row|not found|S3 objects)" $WORK/damage.log

python3 - > $WORK/prefixes.txt <<'PY'
import boto3
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:19900", region_name="us-east-1")
keys = {o["Key"] for p in s3.get_paginator("list_object_versions").paginate(Bucket="e2e-raw") for o in p.get("Versions", [])}
print("\n".join(sorted({k.rsplit("/", 1)[0] + "/" for k in keys})))
PY
python3 $H/snapshot.py $WORK/before.json

rm -rf $WORK/state
A="--bucket e2e-raw --s3-endpoint http://127.0.0.1:19900 --region us-east-1 --db-uri clickhouse://test:test@127.0.0.1:19901/default
   --state $WORK/state --prefixes-from $WORK/prefixes.txt"
for s in inventory restore "restore --apply" fix-jsonl "fix-jsonl --apply" "verify --check-api" prune "prune --apply"; do
  step "repair_cans.py $s"; python3 $D/repair_cans.py $s $A 2>&1 | tail -4
done

python3 $H/snapshot.py $WORK/after.json
step "measurements as Explorer finds them, after the repair"
python3 $E2E/check.py repaired | tail -6   # fails for measurements that never reached S3; compare.py judges that
step "what the repair changed"
python3 $H/compare.py $WORK/before.json $WORK/after.json $WORK/state $WORK/result-repaired.json; RC=$?
[ -n "${KEEP_ENV:-}" ] || $E2E/env.sh down
exit $RC
