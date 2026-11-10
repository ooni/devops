"""Snapshot the test bucket and the jsonl table: every object version (key, VersionId, ETag, latest),
the measurement uids in every .tar.gz version, and every jsonl row.  usage: snapshot.py OUT.json"""
import io, json, sys, tarfile
import boto3
from clickhouse_driver import Client

s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:19900", aws_access_key_id="e2eadmin",
                  aws_secret_access_key="e2esecret123", region_name="us-east-1")
versions = []
for p in s3.get_paginator("list_object_versions").paginate(Bucket="e2e-raw"):
    for v in p.get("Versions", []):
        rec = dict(key=v["Key"], vid=v["VersionId"], etag=v["ETag"].strip('"'), latest=v["IsLatest"])
        if v["Key"].endswith(".tar.gz"):
            body = s3.get_object(Bucket="e2e-raw", Key=v["Key"], VersionId=v["VersionId"])["Body"].read()
            with tarfile.open(fileobj=io.BytesIO(body)) as t:
                rec["uids"] = [m.name.rsplit("/", 1)[-1][:-5] for m in t.getmembers() if m.name.endswith(".post")]
        versions.append(rec)
    for d in p.get("DeleteMarkers", []):
        versions.append(dict(key=d["Key"], vid=d["VersionId"], delete_marker=True, latest=d["IsLatest"]))
db = Client.from_url("clickhouse://test:test@127.0.0.1:19901/default")
rows = [list(r) for r in db.execute("SELECT report_id, input, s3path, linenum, measurement_uid FROM jsonl FINAL ORDER BY measurement_uid, s3path")]
json.dump({"versions": versions, "jsonl": rows}, open(sys.argv[1], "w"))
print(f"snapshot: {len(versions)} object versions, {len(rows)} jsonl rows -> {sys.argv[1]}")
