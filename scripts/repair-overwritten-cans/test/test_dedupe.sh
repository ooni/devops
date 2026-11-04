#!/bin/bash
# Test dedupe_postcans.py: before the reuploader runs, set aside the postcans whose measurement fastpath already has.
#  1. tests/uploader_e2e environment; control traffic through fastpath (poster.py), then make_cases.py:
#     postcans whose retry reached fastpath, whose own uid did, that were saved twice, held (retried after the
#     uploader's last run, so no jsonl row), still missing, and unreadable
#  2. plan, compared with $WORK/expected.tsv; apply (dry run, then --apply)
#  3. the reuploader (it walks the whole failed bucket), the uploader, verify
#  4. the held ones once their jsonl rows exist: plan and apply on hold/postcans/ in the dedup bucket
#  5. tests/uploader_e2e/check.py: every submitted measurement found with its own body
# Needs FASTPATH_IMAGE, DOCKER (docker|podman), the uploader image (tests/uploader_e2e/README.md), and
# REUPLOADER: ooni/backend reuploader/src/reuploader/main.py (default: $REUPLOADER_OLD, the version production
# runs, as the CI workflow sets it; else ~/backend-cp's origin/master).
set -u
python3 -c "import boto3, requests, clickhouse_driver" 2>/dev/null || { echo "needs: pip install boto3 requests clickhouse-driver"; exit 2; }
H=$(cd "$(dirname "$0")" && pwd); D=$(cd $H/.. && pwd); REPO=$(cd $D/../.. && pwd); E2E=$REPO/tests/uploader_e2e
export WORK=${WORK:-$H/work/dedupe}; export DOCKER=${DOCKER:-docker} PYTHONDONTWRITEBYTECODE=1
export UPLOADER=${UPLOADER:-$REPO/ansible/roles/fastpath/templates/ooni_api_uploader.py}
export FASTPATH_IMAGE=${FASTPATH_IMAGE:-$(sed -n 's/^fastpath_image: *"\(.*\)"/\1/p' $REPO/ansible/host_vars/fastpath.prod.ooni.io/vars.yml)}
export AWS_ACCESS_KEY_ID=e2eadmin AWS_SECRET_ACCESS_KEY=e2esecret123
REUPLOADER=${REUPLOADER:-${REUPLOADER_OLD:-}}
if [ -z "$REUPLOADER" ]; then
  REUPLOADER=$WORK/reuploader.py; mkdir -p $WORK
  git -C ~/backend-cp show origin/master:reuploader/src/reuploader/main.py > $REUPLOADER || exit 2
fi
step() { echo "== $(date -u +%T) $*"; }
fail() { echo "FAIL: $*"; RC=1; }
ch() { $DOCKER exec -i uploader-e2e-ch clickhouse-client -u test --password test -q "$1"; }
RC=0
A="--failed-bucket e2e-failed --raw-bucket e2e-raw --s3-endpoint http://127.0.0.1:19900 --region us-east-1
   --dedup-bucket e2e-dedup --db-uri clickhouse://test:test@127.0.0.1:19901/default --threads 4"
dedupe() { python3 $D/dedupe_postcans.py "$@" $A; }
count() { python3 -c "
import boto3; s3 = boto3.client('s3', endpoint_url='http://127.0.0.1:19900', region_name='us-east-1')
print(sum(len(p.get('Contents', [])) for p in s3.get_paginator('list_objects_v2').paginate(Bucket='$1', Prefix='$2')))"; }
wait_fastpath() { for i in $(seq 60); do [ "$(ch "SELECT count() FROM fastpath")" -ge $1 ] && return; sleep 2; done; fail "fastpath has fewer than $1 rows"; }

step "environment"
$E2E/env.sh down; rm -rf $WORK/spool $WORK/ledger.tsv $WORK/poster.offset $WORK/state $WORK/state-hold; mkdir -p $WORK/cans
CAN=raw/20261008/00/IT/webconnectivity/2026100800_IT_webconnectivity.n1.2.tar.gz
[ -s $WORK/cans/test.tar.gz ] || curl -sf -o $WORK/cans/test.tar.gz "https://ooni-data-eu-fra.s3.eu-central-1.amazonaws.com/$CAN"
$E2E/env.sh up
python3 -c "import boto3; boto3.client('s3', endpoint_url='http://127.0.0.1:19900', region_name='us-east-1').create_bucket(Bucket='e2e-dedup')"

step "control traffic, then the outage's postcans and retries"
python3 $E2E/poster.py 3 40; python3 $E2E/poster.py 2 20
python3 $H/make_cases.py setup || exit 1
wait_fastpath $((40 + 20 + 15 + 8 + 4))
sleep 65; $E2E/uploader.sh > $WORK/uploader-1.log 2>&1 || fail "uploader run 1"
echo "   jsonl rows: $(ch "SELECT count() FROM jsonl")"
python3 $H/make_cases.py late; wait_fastpath $((40 + 20 + 15 + 8 + 4 + 4))

step "plan"
dedupe plan --state $WORK/state || { fail "plan"; exit 1; }
python3 - $WORK/state/plan.tsv $WORK/expected.tsv <<'PY' || RC=1
import csv, sys
got = {r["uid"]: r["class"] for r in csv.DictReader(open(sys.argv[1]), delimiter="\t")}
exp = dict(l.split() for l in open(sys.argv[2]))
bad = [(u, exp.get(u), got.get(u)) for u in sorted(set(got) | set(exp)) if exp.get(u) != got.get(u)]
print(f"   plan vs expected: {len(exp) - len(bad)}/{len(exp)} as expected")
for b in bad:
    print("   MISMATCH uid=%s expected=%s got=%s" % b)
sys.exit(1 if bad else 0)
PY
[ $RC = 0 ] || exit 1   # don't reupload on a wrong plan

step "apply"
dedupe apply --state $WORK/state
before=$(count e2e-failed postcans/); dedupe apply --state $WORK/state --apply
echo "   failed bucket $before -> $(count e2e-failed ''), dedup/ $(count e2e-dedup dedup/), hold/ $(count e2e-dedup hold/)"
dedupe apply --state $WORK/state --apply | grep -q " moved:" && fail "a second apply moved postcans again"
[ "$(count e2e-failed '')" = 30 ] && [ "$(count e2e-dedup dedup/)" = 39 ] && [ "$(count e2e-dedup hold/)" = 4 ] || fail "expected 30 / 39 / 4"

step "reuploader, then the uploader"
$E2E/reuploader.sh $REUPLOADER > $WORK/reuploader.log 2>&1
echo "   reuploader: $(grep -c 'Submitted' $WORK/reuploader.log) submitted, $(grep -c 'Failed to process' $WORK/reuploader.log) failed"
[ "$(count e2e-dedup dedup/)" = 39 ] && [ "$(count e2e-dedup hold/)" = 4 ] || fail "the dedup bucket changed"
wait_fastpath $((40 + 20 + 15 + 8 + 4 + 4 + 28))
sleep 65; $E2E/uploader.sh > $WORK/uploader-2.log 2>&1 || fail "uploader run 2"

step "verify"
dedupe verify --state $WORK/state || fail "verify"

step "the held postcans, now that their retries' jsonl rows exist"
dedupe plan --state $WORK/state-hold --prefix hold/postcans/ || fail "plan on hold/"
dedupe apply --state $WORK/state-hold --prefix hold/postcans/ --apply
[ "$(count e2e-dedup hold/)" = 0 ] && [ "$(count e2e-dedup dedup/)" = 43 ] || fail "hold/ not empty, or dedup/ not 43"
echo "   left in the failed bucket: $(count e2e-failed '') (the reuploader sent all 30, the unreadable ones too)"

step "every measurement under its own uid (control traffic, already_ingested, reuploaded), as Explorer finds it"
awk -F'\t' '$2 == "reupload" || $2 == "already_ingested" {print $1 "\tfailed_bucket"}' $WORK/expected.tsv >> $WORK/ledger.tsv
python3 $E2E/check.py dedupe | grep -v RESULT
python3 - $WORK/result-dedupe.json $WORK/ledger.tsv <<'PY2' || RC=1
import json, sys
r = json.load(open(sys.argv[1])); n = len({l.split()[0] for l in open(sys.argv[2])})
ok = r["results"].get("ok", 0) == n and not r["replaced"] and not r["spool_left"]
print(f"   {r['results'].get('ok', 0)}/{n} found with their own body; skipped ones are in the dedup bucket")
sys.exit(0 if ok else 1)
PY2

[ -n "${KEEP_ENV:-}" ] || $E2E/env.sh down
echo "== $([ $RC = 0 ] && echo PASS || echo FAIL)"
exit $RC
