#!/usr/bin/env python3
"""
Read-only checks of the ooniprobe failed-reports bucket and the reuploader, for the can overwrites
found in ooni-data-eu-fra (see README.md next to this script). Never writes or deletes anything.

Needs AWS credentials that can read the failed-reports bucket (s3:ListBucket, s3:GetObject) and, for
`logs`, the reuploader's CloudWatch log group (logs:FilterLogEvents). Public reads of ooni-data-eu-fra
are made without credentials.

  python3 failed_bucket_check.py inventory                 # what is still in the failed bucket
  python3 failed_bucket_check.py stuck --day 20260423      # delivered (in a current n5 can) but not deleted
  python3 failed_bucket_check.py stuck --prefix raw/20260423/18/BY/webconnectivity/
  python3 failed_bucket_check.py logs --since 2026-10-14T00:00 --until 2026-10-15T06:00 [--uid UID ...]

Options: --bucket (default ooniprobe-failed-reports-eu-central-1-1d24426a), --profile, --region.
Output: a summary on stdout and a TSV per mode in the current directory.
"""
import argparse
import collections
import concurrent.futures as cf
import csv
import datetime as dt
import io
import re
import sys
import tarfile

import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

RAW_BUCKET = "ooni-data-eu-fra"
FAILED_BUCKET = "ooniprobe-failed-reports-eu-central-1-1d24426a"
LOG_GROUP = "ooni-ecs-group/scheduled-service-reuploader"
REUPLOADER_COLLECTOR = "n5"  # reuploaderfastpath.prod.ooni.io collector_id 5


def failed_key(uid: str) -> str:
    """The key ooniprobe's submit_measurement writes a measurement to when fastpath is unreachable:
    postcans/<YYYYMMDDHH>/<YYYYMMDDHH>_<cc>_<testname>/<uid>.post"""
    ts, cc, test, _h = uid.split("_")
    hour = ts[:10]
    return f"postcans/{hour}/{hour}_{cc}_{test}/{uid}.post"


def inventory(s3, bucket):
    by_group = collections.Counter()
    size = collections.Counter()
    oldest = newest = None
    n = 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="postcans/"):
        for o in page.get("Contents", []):
            parts = o["Key"].split("/")
            group = parts[2] if len(parts) >= 4 else "(unexpected key)"
            by_group[group] += 1
            size[group] += o["Size"]
            lm = o["LastModified"]
            oldest = lm if oldest is None or lm < oldest else oldest
            newest = lm if newest is None or lm > newest else newest
            n += 1
    with open("failed_inventory.tsv", "w") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["hour_cc_test", "objects", "bytes"])
        for g in sorted(by_group):
            w.writerow([g, by_group[g], size[g]])
    by_day = collections.Counter()
    for g, c in by_group.items():
        by_day[g[:8]] += c
    print(f"{bucket}: {n} objects in {len(by_group)} hour/cc/test groups"
          + (f", written {oldest:%Y-%m-%d %H:%M} .. {newest:%Y-%m-%d %H:%M} UTC" if n else ""))
    for day in sorted(by_day):
        print(f"  {day}: {by_day[day]} objects")
    print("details: failed_inventory.tsv")


def current_reuploader_uids(raw, prefix):
    """uids in the current (latest) versions of the reuploader's cans under a raw/ prefix"""
    uids = set()
    for page in raw.get_paginator("list_objects_v2").paginate(Bucket=RAW_BUCKET, Prefix=prefix):
        for o in page.get("Contents", []):
            k = o["Key"]
            if k.endswith(".tar.gz") and f".{REUPLOADER_COLLECTOR}." in k.rsplit("/", 1)[-1]:
                body = raw.get_object(Bucket=RAW_BUCKET, Key=k)["Body"].read()
                with tarfile.open(fileobj=io.BytesIO(body)) as t:
                    uids |= {m.name.rsplit("/", 1)[-1][:-5] for m in t.getmembers() if m.name.endswith(".post")}
    return uids


def group_prefixes(raw, day):
    """raw/<day>/<HH>/<cc>/<test>/ prefixes that contain a reuploader can"""
    out = set()
    for page in raw.get_paginator("list_objects_v2").paginate(Bucket=RAW_BUCKET, Prefix=f"raw/{day}/"):
        for o in page.get("Contents", []):
            if f".{REUPLOADER_COLLECTOR}." in o["Key"].rsplit("/", 1)[-1]:
                out.add(o["Key"].rsplit("/", 1)[0] + "/")
    return sorted(out)


def exists(s3, bucket, key):
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
            return False
        raise


def stuck(s3, raw, bucket, prefixes):
    rows = []
    with cf.ThreadPoolExecutor(8) as ex:
        for prefix in prefixes:
            uids = sorted(current_reuploader_uids(raw, prefix))
            present = list(ex.map(lambda u: exists(s3, bucket, failed_key(u)), uids))
            n_stuck = sum(present)
            rows += [(prefix, u, failed_key(u)) for u, p in zip(uids, present) if p]
            print(f"{prefix}: {len(uids)} measurements in current {REUPLOADER_COLLECTOR} cans,"
                  f" {n_stuck} still in the failed bucket (will be re-sent and re-canned)")
    with open("stuck.tsv", "w") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["raw_prefix", "measurement_uid", "failed_bucket_key"])
        w.writerows(rows)
    print(f"total stuck: {len(rows)}; details: stuck.tsv")


def logs(session, since, until, uids):
    client = session.client("logs")
    start = int(dt.datetime.fromisoformat(since).replace(tzinfo=dt.timezone.utc).timestamp() * 1000)
    end = int(dt.datetime.fromisoformat(until).replace(tzinfo=dt.timezone.utc).timestamp() * 1000)
    kinds = collections.Counter()
    hits = []
    pattern = '"Failed to process"'
    for page in client.get_paginator("filter_log_events").paginate(
        logGroupName=LOG_GROUP, startTime=start, endTime=end, filterPattern=pattern
    ):
        for e in page["events"]:
            msg = e["message"].strip()
            if uids and not any(u in msg for u in uids):
                continue
            # "Failed to process <key>: <error>" -> group by the error with ids and numbers removed
            err = msg.split(": ", 2)[-1] if ": " in msg else msg
            kinds[re.sub(r"[0-9a-f]{16}|\d+", "#", err)[:160]] += 1
            hits.append((dt.datetime.fromtimestamp(e["timestamp"] / 1000, dt.timezone.utc).isoformat(), msg))
    with open("reuploader_failures.tsv", "w") as f:
        csv.writer(f, delimiter="\t").writerows(hits)
    print(f"{LOG_GROUP}: {len(hits)} 'Failed to process' lines {since} .. {until}")
    for k, n in kinds.most_common(15):
        print(f"  {n:7}  {k}")
    print("details: reuploader_failures.tsv")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["inventory", "stuck", "logs"])
    ap.add_argument("--bucket", default=FAILED_BUCKET)
    ap.add_argument("--profile")
    ap.add_argument("--region", default="eu-central-1")
    ap.add_argument("--day", help="stuck: every raw/<day>/ group with a reuploader can, e.g. 20260423")
    ap.add_argument("--prefix", action="append", help="stuck: raw/<day>/<HH>/<cc>/<test>/ (repeatable)")
    ap.add_argument("--since", help="logs: UTC start, e.g. 2026-10-14T00:00")
    ap.add_argument("--until", help="logs: UTC end")
    ap.add_argument("--uid", action="append", default=[], help="logs: only lines mentioning these uids")
    a = ap.parse_args()

    session = boto3.Session(profile_name=a.profile, region_name=a.region)
    s3 = session.client("s3")
    raw = boto3.client("s3", region_name=a.region, config=Config(signature_version=UNSIGNED))

    if a.mode == "inventory":
        inventory(s3, a.bucket)
    elif a.mode == "stuck":
        prefixes = a.prefix or (group_prefixes(raw, a.day) if a.day else None)
        if not prefixes:
            sys.exit("stuck needs --day or --prefix")
        stuck(s3, raw, a.bucket, prefixes)
    else:
        if not (a.since and a.until):
            sys.exit("logs needs --since and --until")
        logs(session, a.since, a.until, a.uid)


if __name__ == "__main__":
    main()
