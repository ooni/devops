#!/usr/bin/env python3
"""
Migrate S3 measurement files from legacy formats to postcan format.

Source formats:
  2. {REPORT_ID}                         (root-level, e.g. 20250829T134949Z_webconnectivity_ES_15704_n4_iVF3...)
  3. {YYYYMMDDHH}/{ts}_{CC}_{TN}_{HASH}  (e.g. 2026041103/20260411030243.834270_DE_webconnectivity_47712...)

Target format:
  postcans/{YYYYMMDDHH}/{YYYYMMDDHH}_{CC}_{TN}/{MEASUREMENT_UID}.post

For format 2, measurement_uid is recomputed from file content:
  h = sha512(data).hexdigest()[:16]
  ts = <timestamp from report_id>.strftime("%Y%m%d%H%M%S.%f")
  msmt_uid = f"{ts}_{cc}_{test_name}_{h}"

For format 3, measurement_uid is taken directly from the filename (appending .post).
"""

import argparse
import hashlib
import re
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# Format 2: root-level REPORT_ID (no slashes)
# YYYYMMDDTHHMMSSZ_{TN}_{CC}_{ASN}_{ID}_{HASH}
FORMAT2_RE = re.compile(
    r'^(\d{8}T\d{6}Z)_([^_]+)_([A-Z]{2,3})_(\d+)_([^_]+)_([A-Za-z0-9]+)$'
)

# Format 3: {YYYYMMDDHH}/{YYYYMMDDHHMMSS.ffffff}_{CC}_{TN}_{HASH}
FORMAT3_RE = re.compile(
    r'^(\d{10})/(\d{14}\.\d+)_([A-Z]{2,3})_([^_]+)_([a-f0-9]+)$'
)


def compute_msmt_uid(data: bytes, ts: datetime, cc: str, test_name: str) -> str:
    h = hashlib.sha512(data).hexdigest()[:16]
    ts_str = ts.strftime("%Y%m%d%H%M%S.%f")
    return f"{ts_str}_{cc}_{test_name}_{h}"


def list_all_objects(s3_client, bucket: str, prefix: str = ""):
    paginator = s3_client.get_paginator('list_objects_v2')
    kwargs = {"Bucket": bucket}
    if prefix:
        kwargs["Prefix"] = prefix
    for page in paginator.paginate(**kwargs):
        for obj in page.get("Contents", []):
            yield obj["Key"]


def key_exists(s3_client, bucket: str, key: str) -> bool:
    try:
        s3_client.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            return False
        raise


def move_object(s3_client, bucket: str, src_key: str, dst_key: str):
    s3_client.copy_object(
        Bucket=bucket,
        CopySource={"Bucket": bucket, "Key": src_key},
        Key=dst_key,
    )
    s3_client.delete_object(Bucket=bucket, Key=src_key)


def process_bucket(
    bucket: str,
    dry_run: bool = True,
    profile: str = None,
    prefix: str = "",
):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    s3 = session.client("s3")

    counts = {"moved": 0, "skipped": 0, "errors": 0, "conflict": 0}

    for key in list_all_objects(s3, bucket, prefix=prefix):
        # Skip already-migrated postcans
        if key.startswith("postcans/"):
            continue

        # ── Format 3: {YYYYMMDDHH}/{ts}_{CC}_{TN}_{HASH} ──────────────────
        m3 = FORMAT3_RE.match(key)
        if m3:
            yyyymmddhh, ts_part, cc, test_name, hash_part = m3.groups()
            msmt_uid = f"{ts_part}_{cc}_{test_name}_{hash_part}"
            dst_key = f"postcans/{yyyymmddhh}/{yyyymmddhh}_{cc}_{test_name}/{msmt_uid}.post"

            if dry_run:
                print(f"[DRY] fmt3: {key!r}\n       -> {dst_key!r}")
            else:
                try:
                    if key_exists(s3, bucket, dst_key):
                        print(f"CONFLICT (fmt3): {dst_key!r} already exists, skipping {key!r}",
                              file=sys.stderr)
                        counts["conflict"] += 1
                    else:
                        move_object(s3, bucket, key, dst_key)
                        print(f"MOVED (fmt3): {key!r} -> {dst_key!r}")
                        counts["moved"] += 1
                except ClientError as e:
                    print(f"ERROR (fmt3): {key!r}: {e}", file=sys.stderr)
                    counts["errors"] += 1
            continue

        # ── Format 2: root-level REPORT_ID (no slash) ──────────────────────
        if "/" in key:
            # Unrecognised path with slashes — skip silently
            counts["skipped"] += 1
            continue

        m2 = FORMAT2_RE.match(key)
        if not m2:
            print(f"SKIP (unrecognised): {key!r}", file=sys.stderr)
            counts["skipped"] += 1
            continue

        ts_str, test_name, cc, _asn, _id, _old_hash = m2.groups()
        ts = datetime.strptime(ts_str, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        yyyymmddhh = ts.strftime("%Y%m%d%H")

        # Read file to compute new measurement uid
        try:
            response = s3.get_object(Bucket=bucket, Key=key)
            data = response["Body"].read()
        except ClientError as e:
            print(f"ERROR reading (fmt2): {key!r}: {e}", file=sys.stderr)
            counts["errors"] += 1
            continue

        msmt_uid = compute_msmt_uid(data, ts, cc, test_name)
        dst_key = f"postcans/{yyyymmddhh}/{yyyymmddhh}_{cc}_{test_name}/{msmt_uid}.post"

        if dry_run:
            print(f"[DRY] fmt2: {key!r}\n       -> {dst_key!r}")
        else:
            try:
                if key_exists(s3, bucket, dst_key):
                    print(f"CONFLICT (fmt2): {dst_key!r} already exists, skipping {key!r}",
                          file=sys.stderr)
                    counts["conflict"] += 1
                else:
                    move_object(s3, bucket, key, dst_key)
                    print(f"MOVED (fmt2): {key!r} -> {dst_key!r}")
                    counts["moved"] += 1
            except ClientError as e:
                print(f"ERROR (fmt2): {key!r}: {e}", file=sys.stderr)
                counts["errors"] += 1

    print(
        f"\nDone — moved: {counts['moved']}, conflicts: {counts['conflict']}, "
        f"skipped: {counts['skipped']}, errors: {counts['errors']}",
        file=sys.stderr,
    )
    return counts["errors"]


def main():
    parser = argparse.ArgumentParser(
        description="Migrate S3 measurements (fmt2/fmt3) to postcan layout"
    )
    parser.add_argument("bucket", help="S3 bucket name")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually perform the moves (default: dry-run)",
    )
    parser.add_argument(
        "--prefix",
        default="",
        help="Only process keys with this prefix (e.g. '2026041103/' for a single hour)",
    )
    parser.add_argument("--profile", help="AWS profile name", default="default")
    args = parser.parse_args()

    if not args.execute:
        print("DRY RUN — pass --execute to perform actual moves.\n", file=sys.stderr)

    sys.exit(process_bucket(
        bucket=args.bucket,
        dry_run=not args.execute,
        profile=args.profile,
        prefix=args.prefix,
    ))


if __name__ == "__main__":
    main()
