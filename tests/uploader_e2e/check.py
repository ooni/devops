"""Check that every submitted measurement can be found the way Explorer finds it, and that no S3 object
was ever replaced.

The lookup copies ooni/backend oonimeasurements (routers/v1/measurements.py): measurement_uid_to_s3path_linenum
(the same SQL on the jsonl table) and _fetch_jsonl_measurement_body_from_s3 (line `linenum` of the gzipped
jsonl at s3path). Exit status 1 on any failure.  usage: check.py LABEL"""
import collections, gzip, io, json, os, sys
import boto3, requests
from clickhouse_driver import Client

work = os.environ.get("WORK") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "work")
label = sys.argv[1] if len(sys.argv) > 1 else "run"
db = Client.from_url("clickhouse://test:test@127.0.0.1:19901/default")
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:19900", aws_access_key_id="e2eadmin",
                  aws_secret_access_key="e2esecret123", region_name="us-east-1")
LOOKUP = """SELECT s3path, linenum FROM jsonl
    PREWHERE (report_id, input) IN (
        SELECT report_id, input FROM fastpath WHERE measurement_uid = %(uid)s
    )
    LIMIT 1"""

def body(s3path, linenum):
    r = requests.get(f"http://127.0.0.1:19900/e2e-raw/{s3path}", timeout=30)
    r.raise_for_status()
    for n, line in enumerate(gzip.GzipFile(fileobj=io.BytesIO(r.content))):
        if n == linenum:
            return json.loads(line)
    raise LookupError(f"{s3path} has no line {linenum}")

uids = {}
for line in open(os.path.join(work, "ledger.tsv")):
    uid, outcome = line.split()
    uids.setdefault(uid, outcome)
res, bad = collections.Counter(), collections.defaultdict(list)
for uid in sorted(uids):
    rows = db.execute(LOOKUP, {"uid": uid})
    if not rows:
        res["not found (no jsonl row)"] += 1; bad["not_found"].append(uid); continue
    s3path, linenum = rows[0]
    try:
        got = body(s3path, linenum).get("e2e_uid")
    except Exception as e:
        res["jsonl row points at a missing file or line"] += 1; bad["missing"].append((uid, s3path, linenum, repr(e)[:80])); continue
    if got == uid:
        res["ok"] += 1
    else:
        res["WRONG BODY (another measurement)"] += 1; bad["wrong_body"].append((uid, s3path, linenum, got))

replaced = sorted({v["Key"] for p in s3.get_paginator("list_object_versions").paginate(Bucket="e2e-raw")
                   for v in p.get("Versions", []) if not v["IsLatest"]})
spool = os.path.join(work, "spool", "incoming")
spool_left = [os.path.join(d, f) for d, _, fs in os.walk(spool) for f in fs if f.endswith(".post")]
failed_left = sum(len(p.get("Contents", [])) for p in s3.get_paginator("list_objects_v2").paginate(Bucket="e2e-failed"))
cans = sum(1 for p in s3.get_paginator("list_objects_v2").paginate(Bucket="e2e-raw")
           for o in p.get("Contents", []) if o["Key"].endswith(".jsonl.gz"))

print(f"== {label}: {len(uids)} measurements submitted ({dict(collections.Counter(uids.values()))}), {cans} jsonl cans")
for k, v in res.most_common():
    print(f"   {k}: {v}")
print(f"   S3 objects replaced (have older versions): {len(replaced)} {replaced[:4]}")
print(f"   .post left in the spool: {len(spool_left)}   objects left in the failed bucket: {failed_left}")
json.dump({"label": label, "results": res, "replaced": replaced, "spool_left": spool_left, "failed_left": failed_left,
           "bad": bad}, open(os.path.join(work, f"result-{label}.json"), "w"), indent=1, default=str)
passed = res["ok"] == len(uids) and not replaced and not spool_left and failed_left == 0
print("   RESULT:", "PASS" if passed else "FAIL")
sys.exit(0 if passed else 1)
