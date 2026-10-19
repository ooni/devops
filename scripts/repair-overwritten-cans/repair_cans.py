#!/usr/bin/env python3
"""
Repair raw cans that ooni_api_uploader.py overwrote, without losing measurements.

An overwritten can is still in the bucket as a noncurrent version (versioning is on), but the measurements
that were only in it are missing from the current view and their jsonl rows point at other measurements.

Steps, each a dry run unless --apply is given; state (inventory, plan, logs) goes to --state:

  inventory   list every version of each prefix and the measurements in each tar.gz version
  restore     publish the measurements found only in noncurrent versions as new cans
              (<hour>_<cc>_<test>.<identity>.<k>.tar.gz / .jsonl.gz, identity n9 by default, k after the
              highest index already there), never overwriting a key
  fix-jsonl   for the restored measurements: delete their stale jsonl rows, insert rows for the new cans
  verify      for every measurement in every version: look it up in jsonl (by uid, and the way the API does)
              and check the body served is that measurement's content
  prune       delete noncurrent versions whose every measurement is in the current view with the same
              content (optionally copying them to --archive-bucket first); refuses unless verify passed
              after the last restore

Prefixes are raw/<YYYYMMDD>/<HH>/<cc>/<test>/, from --prefix (repeatable) or --prefixes-from FILE.
Needs boto3 and clickhouse-driver; write access to the bucket and the jsonl table for --apply.
"""
import argparse, collections, concurrent.futures as cf, datetime as dt, gzip, hashlib, io, json, os, re, sys, tarfile, threading, time

import boto3
from botocore.exceptions import ClientError

CAN_RE = re.compile(r"^(?P<base>\d{10}_[A-Z0-9]{2}_[a-z0-9]+)\.(?P<ident>n\d+)\.(?P<idx>\d+)\.(?P<ext>tar|jsonl)\.gz$")
MAX_CAN_BYTES = 20 * 1000 * 1000  # the uploader's postcan threshold

try:
    import ujson  # the uploader writes jsonl lines with ujson.dumps

    def dumps(obj):
        return ujson.dumps(obj)
except ImportError:
    def dumps(obj):
        return json.dumps(obj)


def content_hash(content) -> str:
    return hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


class Ctx:
    def __init__(self, a):
        self.a = a
        self.s3 = boto3.client("s3", endpoint_url=a.s3_endpoint or None, region_name=a.region)
        self.state = a.state
        os.makedirs(os.path.join(self.state, "inventory"), exist_ok=True)
        self._local = threading.local()

    @property
    def db(self):
        # one connection per thread: clickhouse_driver clients are not thread-safe
        if getattr(self._local, "db", None) is None:
            from clickhouse_driver import Client
            self._local.db = Client.from_url(self.a.db_uri)
        return self._local.db

    def log(self, name, *fields):
        with open(os.path.join(self.state, name), "a") as f:
            f.write("\t".join(str(x) for x in (now(),) + fields) + "\n")

    def prefixes(self):
        out = list(self.a.prefix or [])
        if self.a.prefixes_from:
            out += [l.strip() for l in open(self.a.prefixes_from) if l.strip()]
        if not out:
            sys.exit("give --prefix or --prefixes-from")
        assert all(re.match(r"^raw/\d{8}/\d{2}/[A-Z0-9]{2}/[a-z0-9]+/$", p) for p in out), "prefixes look like raw/YYYYMMDD/HH/CC/test/"
        return sorted(set(out))

    def inv_path(self, prefix):
        return os.path.join(self.state, "inventory", prefix.strip("/").replace("/", "_") + ".json")

    def versions(self, prefix):
        out = []
        for page in self.s3.get_paginator("list_object_versions").paginate(Bucket=self.a.bucket, Prefix=prefix):
            for v in page.get("Versions", []):
                out.append(dict(key=v["Key"], vid=v["VersionId"], etag=v["ETag"].strip('"'), size=v["Size"],
                                lm=v["LastModified"].isoformat(), latest=v["IsLatest"]))
            for d in page.get("DeleteMarkers", []):
                out.append(dict(key=d["Key"], vid=d["VersionId"], delete_marker=True, lm=d["LastModified"].isoformat(), latest=d["IsLatest"]))
        return out

    def get(self, key, vid):
        return self.s3.get_object(Bucket=self.a.bucket, Key=key, VersionId=vid)["Body"].read()

    def exists(self, key):
        try:
            self.s3.head_object(Bucket=self.a.bucket, Key=key)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
                return False
            raise


def tar_members(data):
    """[(member name, uid, post bytes)] in can order"""
    out = []
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        for m in t.getmembers():
            if m.isfile() and m.name.endswith(".post"):
                out.append((m.name, m.name.rsplit("/", 1)[-1][:-5], t.extractfile(m).read()))
    return out


def post_content(raw):
    """the measurement as the uploader writes it to jsonl (post["content"] for format json), or None"""
    try:
        post = json.loads(raw)
    except Exception:
        return None
    return post.get("content") if post.get("format", "").lower() == "json" else None


# ---------------------------------------------------------------- inventory
def inventory_prefix(ctx, prefix):
    vs = ctx.versions(prefix)
    for v in vs:
        if v.get("delete_marker") or not v["key"].endswith(".tar.gz"):
            continue
        members = tar_members(ctx.get(v["key"], v["vid"]))
        v["uids"] = [uid for _, uid, _ in members]
        v["hashes"], v["meta"] = {}, {}
        for _, uid, raw in members:
            c = post_content(raw)
            if c is not None:
                v["hashes"][uid] = content_hash(c)
                inp = c.get("input") or ""
                v["meta"][uid] = [c.get("report_id") or "", inp if isinstance(inp, str) else str(inp)]
    json.dump({"prefix": prefix, "taken": now(), "versions": vs}, open(ctx.inv_path(prefix), "w"))
    return prefix, vs


def cmd_inventory(ctx):
    n = collections.Counter()
    with cf.ThreadPoolExecutor(ctx.a.threads) as ex:
        for prefix, vs in ex.map(lambda p: inventory_prefix(ctx, p), ctx.prefixes()):
            n["prefixes"] += 1
            n["versions"] += len(vs)
            n["noncurrent"] += sum(1 for v in vs if not v["latest"])
            n["delete_markers"] += sum(1 for v in vs if v.get("delete_marker"))
    print(f"inventory: {dict(n)} -> {ctx.state}/inventory/")


def load_inv(ctx, prefix):
    p = ctx.inv_path(prefix)
    if not os.path.exists(p):
        sys.exit(f"no inventory for {prefix}: run inventory first")
    return json.load(open(p))["versions"]


META = {}  # uid -> [report_id, input], filled by view()


def view(vs):
    """(uids in current tar versions, {uid: [(lm, key, vid)] of noncurrent tar versions holding it}, hashes)"""
    current, holders, hashes = set(), collections.defaultdict(list), collections.defaultdict(set)
    for v in vs:
        if v.get("delete_marker") or "uids" not in v:
            continue
        for uid in v["uids"]:
            if uid in v["hashes"]:
                hashes[uid].add(v["hashes"][uid])
                META.setdefault(uid, v["meta"][uid])
        if v["latest"]:
            current |= set(v["uids"])
        else:
            for uid in v["uids"]:
                holders[uid].append((v["lm"], v["key"], v["vid"]))
    return current, holders, hashes


# ---------------------------------------------------------------- restore
def next_index(vs, base, identity):
    idx = [int(m.group("idx")) for v in vs if (m := CAN_RE.match(v["key"].rsplit("/", 1)[-1]))
           and m.group("base") == base and m.group("ident") == identity]
    return max(idx) + 1 if idx else 0


def plan_prefix(ctx, prefix):
    vs = load_inv(ctx, prefix)
    current, holders, hashes = view(vs)
    missing = sorted(set(holders) - current)
    if not missing:
        return None
    conflicting = [u for u in missing if len(hashes.get(u, ())) > 1]
    base = prefix.split("/")[1] + prefix.split("/")[2] + "_" + prefix.split("/")[3] + "_" + prefix.split("/")[4]
    # each missing measurement from its most recent noncurrent version
    source = {u: max(holders[u])[1:] for u in missing}
    return dict(prefix=prefix, base=base, missing=missing, source=source, conflicting=conflicting,
                start=next_index(vs, base, ctx.a.identity))


def build_cans(ctx, plan):
    """yield (tar bytes, jsonl bytes, rows) for the new cans of one prefix"""
    cache = {}
    def members(key, vid):
        if (key, vid) not in cache:
            cache[(key, vid)] = {uid: (name, raw) for name, uid, raw in tar_members(ctx.get(key, vid))}
        return cache[(key, vid)]

    pending = list(plan["missing"])
    while pending:
        tbuf, jlines, rows, size = io.BytesIO(), [], [], 0
        with tarfile.open(fileobj=tbuf, mode="w:gz") as tar:
            while pending and size < MAX_CAN_BYTES:
                uid = pending.pop(0)
                name, raw = members(*plan["source"][uid])[uid]
                ti = tarfile.TarInfo(name)
                ti.size, ti.mtime, ti.mode = len(raw), int(time.time()), 0o644
                tar.addfile(ti, io.BytesIO(raw))
                size += len(raw)
                content = post_content(raw)
                linenum = len(jlines)
                jlines.append(dumps(content).encode() + b"\n" if content is not None else b"{}\n")
                if content is not None:
                    inp = content.get("input") or ""
                    rows.append(dict(report_id=content.get("report_id") or "", input=inp if isinstance(inp, str) else str(inp),
                                     measurement_uid=uid, linenum=linenum))
        jbuf = io.BytesIO()
        with gzip.GzipFile(fileobj=jbuf, mode="wb") as g:
            g.write(b"".join(jlines))
        yield tbuf.getvalue(), jbuf.getvalue(), rows


def cmd_restore(ctx):
    done = os.path.join(ctx.state, "restore.done")
    if ctx.a.apply and os.path.exists(done) and any(os.path.getmtime(ctx.inv_path(x)) < os.path.getmtime(done) for x in ctx.prefixes()):
        sys.exit("restore already applied: take a new inventory first (it will see the restored cans)")
    plans = [p for p in (plan_prefix(ctx, x) for x in ctx.prefixes()) if p]
    total = sum(len(p["missing"]) for p in plans)
    conflicts = sum(len(p["conflicting"]) for p in plans)
    print(f"restore: {total} measurements only in noncurrent versions, in {len(plans)} prefixes"
          f"{f'; {conflicts} have different content in different versions (newest used)' if conflicts else ''}")
    json.dump(plans, open(os.path.join(ctx.state, "restore_plan.json"), "w"), indent=1)
    if not ctx.a.apply:
        for p in plans[:10]:
            print(f"   {p['prefix']}: {len(p['missing'])} measurements -> {p['base']}.{ctx.a.identity}.{p['start']}.* ...")
        print(f"dry run: plan in {ctx.state}/restore_plan.json; run with --apply to publish")
        return
    for p in plans:
        k = p["start"]
        for tar_b, jsonl_b, rows in build_cans(ctx, p):
            while True:
                tkey = f"{p['prefix']}{p['base']}.{ctx.a.identity}.{k}.tar.gz"
                jkey = f"{p['prefix']}{p['base']}.{ctx.a.identity}.{k}.jsonl.gz"
                if not (ctx.exists(tkey) or ctx.exists(jkey)):
                    break
                k += 1
            ctx.s3.put_object(Bucket=ctx.a.bucket, Key=tkey, Body=tar_b)
            ctx.s3.put_object(Bucket=ctx.a.bucket, Key=jkey, Body=jsonl_b)
            for r in rows:
                ctx.log("restored.tsv", r["measurement_uid"], r["report_id"], r["input"], jkey, r["linenum"])
            ctx.log("restore.log", "published", tkey, jkey, len(rows))
            print(f"   published {tkey} ({len(rows)} measurements)")
            k += 1
    open(os.path.join(ctx.state, "restore.done"), "w").write(now())


# ---------------------------------------------------------------- fix-jsonl
def cmd_fix_jsonl(ctx):
    path = os.path.join(ctx.state, "restored.tsv")
    if not os.path.exists(path):
        sys.exit("nothing restored yet")
    rows = {}
    for line in open(path):
        _, uid, rid, inp, s3path, linenum = line.rstrip("\n").split("\t")
        rows[uid] = dict(report_id=rid, input=inp, s3path=s3path, linenum=int(linenum), measurement_uid=uid)
    uids = sorted(rows)
    keys = lambda chunk: [(rows[u]["report_id"], rows[u]["input"], u) for u in chunk]
    # jsonl is ordered by (report_id, input, measurement_uid): filter on all three to use the primary key
    stale = sum(ctx.db.execute("SELECT count() FROM jsonl WHERE (report_id, input, measurement_uid) IN %(k)s",
                               {"k": keys(uids[i:i + 1000])})[0][0] for i in range(0, len(uids), 1000))
    print(f"fix-jsonl: {len(uids)} restored measurements; {stale} existing jsonl rows for them")
    if not ctx.a.apply:
        print("dry run: run with --apply to delete those rows and insert rows for the restored cans")
        return
    for i in range(0, len(uids), 1000):
        chunk = uids[i:i + 1000]
        ctx.db.execute("DELETE FROM jsonl WHERE (report_id, input, measurement_uid) IN %(k)s", {"k": keys(chunk)})
        ctx.db.execute("INSERT INTO jsonl (report_id, input, s3path, linenum, measurement_uid) VALUES", [rows[u] for u in chunk])
        ctx.log("fix_jsonl.log", "replaced", len(chunk))
    print(f"   {len(uids)} jsonl rows replaced")


# ---------------------------------------------------------------- verify
API_LOOKUP = """SELECT s3path, linenum FROM jsonl
    PREWHERE (report_id, input) IN (SELECT report_id, input FROM fastpath WHERE measurement_uid = %(uid)s)
    LIMIT 1"""


def fetch_line(ctx, cache, s3path, linenum):
    if s3path not in cache:
        cache[s3path] = gzip.decompress(ctx.s3.get_object(Bucket=ctx.a.bucket, Key=s3path)["Body"].read()).split(b"\n")
    lines = cache[s3path]
    return json.loads(lines[linenum]) if 0 <= linenum < len(lines) and lines[linenum] else None


def check(ctx, cache, res, how, uid, hs, row):
    if not row:
        res[f"{how}:no_row"] += 1; ctx.log("verify_failures.tsv", how, "no_row", uid); return
    try:
        body = fetch_line(ctx, cache, row[0], row[1])
    except Exception:
        body = None
    if body is not None and content_hash(body) in hs:
        res[f"{how}:ok"] += 1
    else:
        res[f"{how}:wrong_or_missing_body"] += 1; ctx.log("verify_failures.tsv", how, "bad_body", uid, row[0], row[1])


def verify_prefix(ctx, prefix, restored):
    vs = load_inv(ctx, prefix)
    _, _, hashes = view(vs)
    res, cache = collections.Counter(), {}
    uids = sorted(hashes)
    for i in range(0, len(uids), 1000):
        chunk = uids[i:i + 1000]
        keys = [(META[u][0], META[u][1], u) for u in chunk]
        found = {r[0]: (r[1], r[2]) for r in ctx.db.execute(
            "SELECT measurement_uid, argMax(s3path, update_time), argMax(linenum, update_time) FROM jsonl"
            " WHERE (report_id, input, measurement_uid) IN %(k)s GROUP BY measurement_uid", {"k": keys})}
        for u in chunk:
            check(ctx, cache, res, "uid", u, hashes[u], found.get(u))
    if ctx.a.check_api:  # the API's own lookup, for the measurements this repair restored
        for u in uids:
            if u in restored:
                r = ctx.db.execute(API_LOOKUP, {"uid": u})
                check(ctx, cache, res, "api", u, hashes[u], r[0] if r else None)
    return res


def cmd_verify(ctx):
    open(os.path.join(ctx.state, "verify_failures.tsv"), "w").close()
    total = collections.Counter()
    rpath = os.path.join(ctx.state, "restored.tsv")
    restored = {l.split("\t")[1] for l in open(rpath)} if os.path.exists(rpath) else set()
    with cf.ThreadPoolExecutor(ctx.a.threads) as ex:
        for res in ex.map(lambda p: verify_prefix(ctx, p, restored), ctx.prefixes()):
            total += res
    print(f"verify: {dict(sorted(total.items()))}")
    bad = sum(v for k, v in total.items() if k.startswith("uid:") and not k.endswith(":ok"))
    if bad:
        print(f"   {bad} measurements not served correctly by uid; see {ctx.state}/verify_failures.tsv")
        sys.exit(1)
    open(os.path.join(ctx.state, "verify.ok"), "w").write(now())
    print("   every measurement is served with its own content (lookup by uid)")


# ---------------------------------------------------------------- prune
def cmd_prune(ctx):
    ok = os.path.join(ctx.state, "verify.ok")
    done = os.path.join(ctx.state, "restore.done")
    if not os.path.exists(ok) or (os.path.exists(done) and os.path.getmtime(done) > os.path.getmtime(ok)):
        sys.exit("run verify (successfully) after the last restore before pruning")
    deletable, kept = [], collections.Counter()
    for prefix in ctx.prefixes():
        vs = [v for v in ctx.versions(prefix) if not v.get("delete_marker")]  # fresh: includes restored cans
        inv = {(v["key"], v["vid"]): v for v in load_inv(ctx, prefix) if "uids" in v}
        # what the current view serves: uid -> content hashes, from every current tar.gz
        cur_uids, cur_hash = set(), collections.defaultdict(set)
        for v in vs:
            if v["latest"] and v["key"].endswith(".tar.gz"):
                info = inv.get((v["key"], v["vid"]))
                if info is None:  # published after the inventory (a restored can)
                    members = tar_members(ctx.get(v["key"], v["vid"]))
                    info = {"uids": [u for _, u, _ in members],
                            "hashes": {u: content_hash(c) for _, u, raw in members if (c := post_content(raw)) is not None}}
                cur_uids |= set(info["uids"])
                for u, h in info["hashes"].items():
                    cur_hash[u].add(h)
        # a noncurrent tar.gz is redundant when every measurement in it is served with the same content
        tars = []
        for v in vs:
            if v["latest"] or not v["key"].endswith(".tar.gz"):
                continue
            info = inv.get((v["key"], v["vid"]))
            ok = info is not None and set(info["uids"]) <= cur_uids and all(h in cur_hash[u] for u, h in info["hashes"].items())
            tars.append((v, ok))
            if ok:
                deletable.append(v)
            else:
                kept["tar.gz with measurements not served from the current view" if info else "tar.gz not in the inventory"] += 1
        # a noncurrent jsonl.gz is redundant when every measurement body in it is served from the current
        # view with the same content (lines the uploader wrote as {} for unparseable POSTs carry nothing)
        served = set().union(*cur_hash.values()) if cur_hash else set()
        for v in vs:
            if v["latest"] or not v["key"].endswith(".jsonl.gz"):
                continue
            lines = gzip.decompress(ctx.get(v["key"], v["vid"])).split(b"\n")
            bodies = [json.loads(l) for l in lines if l.strip() and l.strip() != b"{}"]
            if all(content_hash(b) in served for b in bodies):
                deletable.append(v)
            else:
                kept["jsonl.gz with measurements not served from the current view"] += 1
    nbytes = sum(v["size"] for v in deletable)
    print(f"prune: {len(deletable)} noncurrent versions redundant ({nbytes / 1e9:.2f} GB); kept: {dict(kept)}")
    json.dump(deletable, open(os.path.join(ctx.state, "prune_plan.json"), "w"), indent=1)
    if not ctx.a.apply:
        print(f"dry run: list in {ctx.state}/prune_plan.json; run with --apply"
              + (f" (copies go to {ctx.a.archive_bucket} first)" if ctx.a.archive_bucket else ""))
        return
    for v in deletable:
        if ctx.a.archive_bucket:
            ctx.s3.copy_object(Bucket=ctx.a.archive_bucket, Key=f"{v['key']}.{v['vid']}",
                               CopySource={"Bucket": ctx.a.bucket, "Key": v["key"], "VersionId": v["vid"]})
        ctx.s3.delete_object(Bucket=ctx.a.bucket, Key=v["key"], VersionId=v["vid"])
        ctx.log("prune.log", "deleted", v["key"], v["vid"], v["etag"], v["size"], v["lm"])
    print(f"   deleted {len(deletable)} noncurrent versions")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["inventory", "restore", "fix-jsonl", "verify", "prune"])
    ap.add_argument("--bucket", default="ooni-data-eu-fra")
    ap.add_argument("--s3-endpoint", help="S3 endpoint (tests); default AWS")
    ap.add_argument("--region", default="eu-central-1")
    ap.add_argument("--db-uri", default="clickhouse://localhost/default", help="ClickHouse with the jsonl and fastpath tables")
    ap.add_argument("--state", default="repair-state")
    ap.add_argument("--prefix", action="append")
    ap.add_argument("--prefixes-from")
    ap.add_argument("--identity", default="n9", help="collector identity for restored cans (no uploader uses it)")
    ap.add_argument("--archive-bucket", help="prune: copy each version here before deleting it")
    ap.add_argument("--check-api", action="store_true", help="verify: also look up the way the API does (report_id, input)")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    ctx = Ctx(a)
    {"inventory": cmd_inventory, "restore": cmd_restore, "fix-jsonl": cmd_fix_jsonl, "verify": cmd_verify, "prune": cmd_prune}[a.command](ctx)


if __name__ == "__main__":
    main()
