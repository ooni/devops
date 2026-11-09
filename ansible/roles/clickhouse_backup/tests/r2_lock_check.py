"""Checks, against real R2, what test_e2e.py's lockproxy stands in for: a bucket lock rule on prod/ refuses deletes
and overwrites with ObjectLockedByBucketPolicy until the objects are old enough, and the backup script's move
(staging/ to prod/, multipart copies included) works there. Run by hand, not in CI:

1. Create a scratch bucket, e.g. ooni-clickhouse-backup-lockcheck, with a bucket lock rule: prefix prod/, Age of a
   few minutes (the --lock-seconds below), and an R2 API token with Object Read & Write on that bucket only.
2. python3 r2_lock_check.py --endpoint https://<account id>.r2.cloudflarestorage.com \\
       --bucket ooni-clickhouse-backup-lockcheck --key-id ... --secret ... --lock-seconds 300
   (needs python3-boto3). With --big it also moves a 300 MiB object (uploaded from here), to check R2's
   multipart copy.
3. Delete the bucket's lock rule, then the bucket.

Prints each check; exits 1 at the first failure."""
import argparse
import importlib.util
import os
import sys
import time

spec = importlib.util.spec_from_file_location(
    "backup", os.path.join(os.path.dirname(__file__), "..", "files", "ooni_clickhouse_backup.py")
)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


def check(ok, what):
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        sys.exit(1)


def refused(f):
    """The error code if f() is refused, else None"""
    try:
        f()
    except Exception as e:
        return getattr(e, "response", {}).get("Error", {}).get("Code") or str(e)
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for a in ("--endpoint", "--bucket", "--key-id", "--secret"):
        ap.add_argument(a, required=True)
    ap.add_argument("--lock-seconds", type=int, required=True, help="the rule's Age")
    ap.add_argument("--big", action="store_true", help="also move a 300 MiB object")
    args = ap.parse_args()
    store = backup.Store({"s3_bucket": args.bucket, "s3_prefix": "prod", "s3_endpoint": args.endpoint,
                          "s3_region": "auto", "s3_access_key_id": args.key_id, "s3_secret_access_key": args.secret})
    s3, b = store.s3, args.bucket
    run = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    src, dst = f"staging/prod/ooni/t/{run}/{run}/", f"prod/ooni/t/{run}/{run}/"

    print(f"== a backup under {src}, moved to {dst}")
    files = {"data/default/t/all_1_1_0/data.bin": os.urandom(1 << 20), "metadata/default/t.sql": b"CREATE TABLE t",
             ".lock": b"uuid", ".backup": b"<config/>"}
    if args.big:
        files["data/default/t/all_2_2_0/big.bin"] = os.urandom(300 << 20)
    for name, data in files.items():
        s3.put_object(Bucket=b, Key=src + name, Body=data)
    check(refused(lambda: s3.delete_object(Bucket=b, Key=src + ".lock")) is None,
          "staging/ isn't locked: ClickHouse can remove its .lock there")
    del files[".lock"]
    t0 = time.time()
    n = store.move(src, dst)
    check(n == len(files), f"moved {n} objects in {time.time() - t0:.1f}s")
    check(not store.objects(src) and set(store.objects(dst)) == {dst + k for k in files}, "all under prod/, none left in staging/")
    if args.big:
        size = s3.head_object(Bucket=b, Key=dst + "data/default/t/all_2_2_0/big.bin")["ContentLength"]
        check(size == 300 << 20, "the 300 MiB object arrived whole (multipart copy)")

    print("== the token against prod/, under the lock")
    key = dst + ".backup"
    code = refused(lambda: s3.delete_object(Bucket=b, Key=key))
    check(code == "ObjectLockedByBucketPolicy", f"DeleteObject refused: {code}")
    code = refused(lambda: s3.put_object(Bucket=b, Key=key, Body=b"x"))
    check(code == "ObjectLockedByBucketPolicy", f"overwrite refused: {code}")
    resp = s3.delete_objects(Bucket=b, Delete={"Objects": [{"Key": k} for k in store.objects(dst)]})
    codes = {e["Code"] for e in resp.get("Errors", [])}
    check(codes == {"ObjectLockedByBucketPolicy"} and len(store.objects(dst)) == len(files),
          f"DeleteObjects refused for every key: {codes}")
    check(s3.get_object(Bucket=b, Key=key)["Body"].read() == b"<config/>", "the .backup is unchanged")

    newest = store.newest(dst)
    wait = newest.timestamp() + args.lock_seconds + 5 - time.time()
    print(f"== waiting {wait:.0f}s for the lock to expire")
    time.sleep(max(0, wait))
    removed = store.delete_prefix(dst)
    check(removed == len(files) and not store.objects(dst), f"past the lock, the token deletes it: {removed} objects")
    print("PASS")


if __name__ == "__main__":
    main()
