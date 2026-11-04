#!/usr/bin/env python3
"""
Before re-enabling the reuploader: set aside the measurements in the failed-reports bucket that already
reached fastpath, so the reupload adds only missing measurements and no duplicates.

ooniprobe's submit_measurement gives every submission a new report_id and measurement_uid, and the hash
in the uid covers the body with that report_id. So when a submission timed out at the load balancer
after the fallback had saved it to the failed-reports bucket (2026-10-13/14), and the probe submitted
again, fastpath got the same measurement under other ids. A postcan's measurement is identified by its
content without report_id, hashed like repair_cans.py's content_hash.

Each postcan gets one class:

  already_ingested  fastpath has a row with the postcan's own measurement_uid
  retried           fastpath has the same measurement under another uid: its columns match (probe_cc,
                    probe_asn, test_name, input, measurement_start_time, test_start_time, test_runtime),
                    and the body its jsonl row points to has the same content
  unconfirmed       fastpath's columns match but the body couldn't be checked (no jsonl row yet, or the
                    can isn't readable). Almost surely a retry too, so it is held, not reuploaded
  repeat_postcan    another postcan holds the same measurement (the retry failed too); the earliest is kept
  reupload          none of the above: the reuploader should send it
  unreadable        the body isn't a measurement: left in place, listed

Steps, each a dry run unless --apply is given; state goes to --state:

  plan     read every postcan under --prefix (postcans/ by default), classify, write plan.tsv
  apply    move the already_ingested, retried and repeat_postcan ones to dedup/<key> and the unconfirmed
           ones to hold/<key> in --dedup-bucket: copy, check the copy, then delete the original. Nothing is
           deleted outright. It has to be another bucket: the reuploader walks the whole bucket (it reads
           S3_PREFIX but doesn't use it) and deletes whatever fastpath accepts.
           Once the jsonl rows exist (uploader caught up, repair_cans.py fix-jsonl), run plan and apply
           again with --prefix hold/postcans/ and a new --state: confirmed ones go to dedup/, the ones
           that turn out not to be in fastpath go back to the failed-reports bucket.
  verify   after the reupload: each reupload measurement is in fastpath once, its jsonl row points at
           its own body, and no measurement from the plan is in fastpath more than once

Needs boto3 and clickhouse-driver, read access to the raw bucket, read and write access to the
failed-reports and dedup buckets, and a ClickHouse with the fastpath and jsonl tables (production: data3).
"""
import argparse, collections, concurrent.futures as cf, csv, datetime as dt, gzip, json, os, sys, threading

import boto3
from botocore.exceptions import ClientError

from repair_cans import content_hash

SKIP = ("already_ingested", "retried", "repeat_postcan")
HOLD = "hold/"
DEDUP = "dedup/"
COLS = "postcan uid identity probe_cc probe_asn test_name input measurement_start_time test_start_time test_runtime".split()


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def original_key(key: str) -> str:
    return key[len(HOLD):] if key.startswith(HOLD) else key


def identity(content: dict) -> str:
    """The measurement, whatever report_id the API gave this submission"""
    return content_hash({k: v for k, v in content.items() if k != "report_id"})


def fastpath_input(content: dict) -> str:
    """input as fastpath stores it (fastpath/db.py extract_input_domain)"""
    inp = content.get("input")
    if content.get("test_name") == "meek_fronted_requests_test" and isinstance(inp, list):
        return "{" + ",".join(inp) + "}"
    return inp if isinstance(inp, str) else ""


def postcan_content(raw: bytes):
    """The measurement in a .post body (submit_measurement and /report both keep it in "content"), or None"""
    try:
        post = json.loads(raw)
        c = post.get("content")
        if isinstance(c, str):
            c = json.loads(c)
        return c if isinstance(c, dict) and c.get("measurement_start_time") else None
    except Exception:
        return None


def asn_int(asn) -> int:
    try:
        return int(str(asn).upper().lstrip("AS"))
    except ValueError:
        return -1


def same_runtime(a: float, b: float) -> bool:
    # fastpath stores test_runtime as Float32
    return abs(float(a) - float(b)) <= 1e-4 * max(1.0, abs(float(a)))


class Ctx:
    def __init__(self, a):
        self.a = a
        self.s3 = boto3.client("s3", endpoint_url=a.s3_endpoint or None, region_name=a.region)
        os.makedirs(a.state, exist_ok=True)
        self._local = threading.local()

    @property
    def db(self):
        # one connection per thread: clickhouse_driver clients are not thread-safe
        if getattr(self._local, "db", None) is None:
            from clickhouse_driver import Client
            self._local.db = Client.from_url(self.a.db_uri)
        return self._local.db

    def path(self, name):
        return os.path.join(self.a.state, name)

    def log(self, name, *fields):
        with open(self.path(name), "a") as f:
            f.write("\t".join(str(x) for x in (now(),) + fields) + "\n")

    def bucket_of(self, key):
        """Postcans are in the failed-reports bucket, held ones in the dedup bucket"""
        return self.a.dedup_bucket if key.startswith(HOLD) else self.a.failed_bucket

    def keys(self):
        out = []
        for prefix in self.a.prefix:
            for page in self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket_of(prefix), Prefix=prefix):
                out += [o["Key"] for o in page.get("Contents", []) if o["Key"].endswith(".post")]
        return sorted(out)

    def exists(self, bucket, key):
        try:
            return self.s3.head_object(Bucket=bucket, Key=key)
        except ClientError as e:
            if e.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
                return None
            raise


# ---------------------------------------------------------------- plan
def read_postcan(ctx, key):
    uid = key.rsplit("/", 1)[-1][: -len(".post")]
    c = postcan_content(ctx.s3.get_object(Bucket=ctx.bucket_of(key), Key=key)["Body"].read())
    if c is None:
        return dict(postcan=key, uid=uid, identity="")
    return dict(postcan=key, uid=uid, identity=identity(c), probe_cc=c.get("probe_cc") or "",
                probe_asn=asn_int(c.get("probe_asn")), test_name=c.get("test_name") or "", input=fastpath_input(c),
                measurement_start_time=c["measurement_start_time"], test_start_time=c.get("test_start_time") or "",
                test_runtime=float(c.get("test_runtime") or 0))


def load_postcans(ctx):
    """Read every postcan once; later runs reuse postcans.tsv"""
    p = ctx.path("postcans.tsv")
    if os.path.exists(p) and not ctx.a.reread:
        rows = list(csv.DictReader(open(p), delimiter="\t"))
        for r in rows:
            r["probe_asn"] = int(r["probe_asn"] or -1)
            r["test_runtime"] = float(r["test_runtime"] or 0)
        return rows
    keys = ctx.keys()
    print(f"reading {len(keys)} postcans")
    with cf.ThreadPoolExecutor(ctx.a.threads) as ex:
        rows = list(ex.map(lambda k: read_postcan(ctx, k), keys))
    with open(p, "w") as f:
        w = csv.DictWriter(f, COLS, delimiter="\t", extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    return rows


def fetch_body(ctx, cache, s3path, linenum):
    if s3path not in cache:
        obj = ctx.s3.get_object(Bucket=ctx.a.raw_bucket, Key=s3path)["Body"].read()
        cache[s3path] = gzip.decompress(obj).split(b"\n")
    lines = cache[s3path]
    return json.loads(lines[linenum]) if 0 <= linenum < len(lines) and lines[linenum] else None


def match_batch(ctx, batch):
    """{uid: (class, matched uid)} for one batch of readable postcans"""
    out = {}
    lo = min(r["measurement_start_time"] for r in batch)
    hi = max(r["measurement_start_time"] for r in batch)
    uids = [r["uid"] for r in batch]
    have = {u for (u,) in ctx.db.execute(
        "SELECT measurement_uid FROM fastpath WHERE measurement_start_time BETWEEN %(lo)s AND %(hi)s"
        " AND measurement_uid IN %(u)s", {"lo": lo, "hi": hi, "u": uids})}
    keys = [(r["probe_cc"], r["probe_asn"], r["test_name"], r["input"], r["measurement_start_time"]) for r in batch]
    cands = collections.defaultdict(list)
    for row in ctx.db.execute(
            "SELECT probe_cc, probe_asn, test_name, input, toString(measurement_start_time),"
            " toString(test_start_time), test_runtime, measurement_uid, report_id FROM fastpath"
            " WHERE measurement_start_time BETWEEN %(lo)s AND %(hi)s"
            " AND (probe_cc, probe_asn, test_name, input, measurement_start_time) IN %(k)s",
            {"lo": lo, "hi": hi, "k": keys}):
        cands[row[:5]].append(row[5:])
    cache = {}
    for r in batch:
        if r["uid"] in have:
            out[r["uid"]] = ("already_ingested", r["uid"])
            continue
        k = (r["probe_cc"], r["probe_asn"], r["test_name"], r["input"], r["measurement_start_time"])
        found = [c for c in cands.get(k, []) if c[0] == r["test_start_time"] and same_runtime(c[1], r["test_runtime"])
                 and c[2] != r["uid"]]
        if not found:
            continue
        cls = ("unconfirmed", found[0][2])
        for _, _, fuid, rid in found:
            jr = ctx.db.execute(
                "SELECT argMax(s3path, update_time), argMax(linenum, update_time) FROM jsonl"
                " WHERE (report_id, input, measurement_uid) IN %(k)s GROUP BY measurement_uid",
                {"k": [(rid, r["input"], fuid)]})
            if not jr:
                continue
            try:
                body = fetch_body(ctx, cache, jr[0][0], jr[0][1])
            except Exception:
                body = None
            if body is not None and identity(body) == r["identity"]:
                cls = ("retried", fuid)
                break
        out[r["uid"]] = cls
    return out


def cmd_plan(ctx):
    rows = load_postcans(ctx)
    readable = [r for r in rows if r["identity"]]
    readable.sort(key=lambda r: r["measurement_start_time"])
    batches = [readable[i:i + ctx.a.batch] for i in range(0, len(readable), ctx.a.batch)]
    found = {}
    with cf.ThreadPoolExecutor(ctx.a.threads) as ex:
        for res in ex.map(lambda b: match_batch(ctx, b), batches):
            found.update(res)

    # Several postcans of one measurement: if fastpath has it, all are skipped; otherwise keep the earliest
    by_identity = collections.defaultdict(list)
    for r in readable:
        by_identity[r["identity"]].append(r)
    plan = []
    for r in rows:
        if not r["identity"]:
            plan.append((r["postcan"], r["uid"], "unreadable", ""))
            continue
        cls, other = found.get(r["uid"], ("", ""))
        if cls in ("already_ingested", "retried"):
            plan.append((r["postcan"], r["uid"], cls, other))
            continue
        group = by_identity[r["identity"]]
        ingested = [found[g["uid"]] for g in group if found.get(g["uid"], ("",))[0] in ("already_ingested", "retried")]
        keep = min(g["uid"] for g in group)
        if ingested:
            plan.append((r["postcan"], r["uid"], "repeat_postcan", ingested[0][1]))
        elif r["uid"] != keep:
            plan.append((r["postcan"], r["uid"], "repeat_postcan", keep))
        else:
            plan.append((r["postcan"], r["uid"], cls or "reupload", other))

    with open(ctx.path("plan.tsv"), "w") as f:
        f.write("postcan\tuid\tclass\tmatched_uid\n")
        for p in plan:
            f.write("\t".join(p) + "\n")
    by_class = collections.Counter(p[2] for p in plan)
    by_hour = collections.Counter((original_key(p[0]).split("/")[1], p[2]) for p in plan)
    with open(ctx.path("plan_by_hour.tsv"), "w") as f:
        f.write("hour\tclass\tpostcans\n")
        for (h, c), n in sorted(by_hour.items()):
            f.write(f"{h}\t{c}\t{n}\n")
    print(f"plan: {len(plan)} postcans: {dict(by_class)} -> {ctx.a.state}/plan.tsv, plan_by_hour.tsv")


def load_plan(ctx):
    p = ctx.path("plan.tsv")
    if not os.path.exists(p):
        sys.exit("no plan: run plan first")
    return list(csv.DictReader(open(p), delimiter="\t"))


# ---------------------------------------------------------------- apply
def destination(ctx, key, cls):
    if cls in SKIP:
        return ctx.a.dedup_bucket, DEDUP + original_key(key)
    if cls == "unconfirmed":
        return ctx.a.dedup_bucket, HOLD + original_key(key)
    return ctx.a.failed_bucket, original_key(key)  # reupload: back to the failed-reports bucket if it was held


def move(ctx, key, dst):
    bucket, (dbucket, dest) = ctx.bucket_of(key), dst
    if (dbucket, dest) == (bucket, key):
        return "stays"
    src = ctx.exists(bucket, key)
    if src is None:
        return "already_moved" if ctx.exists(dbucket, dest) else "missing"
    if not ctx.a.apply:
        return "would_move"
    ctx.s3.copy_object(Bucket=dbucket, Key=dest, CopySource={"Bucket": bucket, "Key": key})
    copy = ctx.exists(dbucket, dest)
    if copy is None or copy["ContentLength"] != src["ContentLength"] or copy["ETag"] != src["ETag"]:
        ctx.log("apply_failures.tsv", key, "copy_mismatch")
        return "copy_mismatch"
    ctx.s3.delete_object(Bucket=bucket, Key=key)
    ctx.log("moved.tsv", bucket, key, dbucket, dest)
    return "moved"


def cmd_apply(ctx):
    if not ctx.a.dedup_bucket:
        sys.exit("apply needs --dedup-bucket")
    todo = [(p["postcan"], p["class"]) for p in load_plan(ctx) if p["class"] != "unreadable"]
    with cf.ThreadPoolExecutor(ctx.a.threads) as ex:
        res = collections.Counter(ex.map(lambda t: (t[1], move(ctx, t[0], destination(ctx, *t))), todo))
    print(f"apply{'' if ctx.a.apply else ' (dry run)'}: " + ", ".join(f"{c} {r}: {n}" for (c, r), n in sorted(res.items())))


# ---------------------------------------------------------------- verify
def cmd_verify(ctx):
    plan = load_plan(ctx)
    rows = {r["uid"]: r for r in load_postcans(ctx)}
    res, cache = collections.Counter(), {}
    open(ctx.path("verify_failures.tsv"), "w").close()
    for p in plan:
        if p["class"] == "unconfirmed":
            res["held"] += 1
            continue
        if p["class"] != "reupload":
            continue
        r, uid = rows[p["uid"]], p["uid"]
        if ctx.exists(ctx.a.failed_bucket, original_key(p["postcan"])):
            res["not_reuploaded_yet"] += 1; ctx.log("verify_failures.tsv", "still_in_failed_bucket", uid); continue
        n = ctx.db.execute("SELECT count() FROM fastpath WHERE measurement_start_time = %(t)s AND measurement_uid = %(u)s",
                           {"t": r["measurement_start_time"], "u": uid})[0][0]
        if n == 0:
            res["not_in_fastpath"] += 1; ctx.log("verify_failures.tsv", "not_in_fastpath", uid); continue
        jr = ctx.db.execute("SELECT DISTINCT s3path, linenum FROM jsonl FINAL WHERE measurement_uid = %(u)s", {"u": uid})
        if len(jr) != 1:
            res[f"jsonl_rows_{min(len(jr), 2)}"] += 1; ctx.log("verify_failures.tsv", f"jsonl_rows_{len(jr)}", uid); continue
        try:
            body = fetch_body(ctx, cache, jr[0][0], jr[0][1])
        except Exception:
            body = None
        if body is None or identity(body) != r["identity"]:
            res["wrong_or_missing_body"] += 1; ctx.log("verify_failures.tsv", "bad_body", uid, *jr[0]); continue
        res["ok"] += 1
    # No measurement of the plan may now be in fastpath more than once
    seen = {}
    for p in plan:
        r = rows[p["uid"]]
        if r["identity"]:
            seen.setdefault(r["identity"], r)
    dups = 0
    for r in seen.values():
        n = sum(1 for row in ctx.db.execute(
            # distinct uids: rows of one uid are one measurement, until ReplacingMergeTree merges them
            "SELECT DISTINCT toString(test_start_time), test_runtime, measurement_uid FROM fastpath"
            " WHERE measurement_start_time = %(t)s"
            " AND probe_cc = %(cc)s AND probe_asn = %(asn)s AND test_name = %(tn)s AND input = %(inp)s",
            {"t": r["measurement_start_time"], "cc": r["probe_cc"], "asn": r["probe_asn"], "tn": r["test_name"],
             "inp": r["input"]})
            if row[0] == r["test_start_time"] and same_runtime(row[1], r["test_runtime"]))
        if n > 1:
            dups += 1; ctx.log("verify_failures.tsv", "duplicate_in_fastpath", r["uid"], n)
    res["measurements_in_fastpath_more_than_once"] = dups
    ok = dups == 0 and all(k in ("ok", "held") for k in res if k != "measurements_in_fastpath_more_than_once" and res[k])
    print(f"verify: {dict(res)} -> {'PASS' if ok else 'FAIL'} (failures in {ctx.a.state}/verify_failures.tsv)")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["plan", "apply", "verify"])
    ap.add_argument("--failed-bucket", default="ooniprobe-failed-reports-eu-central-1-1d24426a")
    ap.add_argument("--raw-bucket", default="ooni-data-eu-fra")
    ap.add_argument("--s3-endpoint", help="S3 endpoint (tests); default AWS")
    ap.add_argument("--region", default="eu-central-1")
    ap.add_argument("--db-uri", default="clickhouse://localhost/ooni", help="ClickHouse with the fastpath and jsonl tables")
    ap.add_argument("--state", default="dedupe-state")
    ap.add_argument("--prefix", action="append", help="prefixes to read, under postcans/ or hold/postcans/ (repeatable; default postcans/)")
    ap.add_argument("--dedup-bucket", help="apply: where skipped (dedup/) and held (hold/) postcans go; not the failed-reports bucket")
    ap.add_argument("--reread", action="store_true", help="plan: read the bucket again instead of postcans.tsv")
    ap.add_argument("--batch", type=int, default=500, help="postcans per fastpath lookup")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    a.prefix = a.prefix or ["postcans/"]
    assert all(original_key(p).startswith("postcans/") for p in a.prefix), "prefixes are under postcans/ or hold/postcans/"
    assert a.dedup_bucket != a.failed_bucket, "the reuploader would send everything in the failed-reports bucket"
    assert a.dedup_bucket or not any(p.startswith(HOLD) for p in a.prefix), "hold/ prefixes are in --dedup-bucket"
    ctx = Ctx(a)
    {"plan": cmd_plan, "apply": cmd_apply, "verify": cmd_verify}[a.command](ctx)


if __name__ == "__main__":
    main()
