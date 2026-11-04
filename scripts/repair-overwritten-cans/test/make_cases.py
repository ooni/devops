"""Fill the e2e failed-reports bucket and fastpath the way the 2026-10-13/14 outage left them, for
test_dedupe.sh. Every case gets the class dedupe_postcans.py plan should give it, in $WORK/expected.tsv.

usage: make_cases.py setup   postcans (hour 3 ago) and, for some, their retry or the postcan itself in fastpath
       make_cases.py late    retries posted after the uploader's last run (no jsonl row yet: unconfirmed)

Measurements come from $WORK/cans like tests/uploader_e2e/poster.py, starting at offset 300 so they
don't overlap poster.py's control traffic. A submission is minted like poster.py's: uid from the time,
report_id "e2e-<uid>", and e2e_uid (the original uid) in the content, so a retry with a new uid and
report_id keeps the measurement's identity."""
import datetime as dt, glob, hashlib, json, os, random, sys, tarfile
import boto3, requests

work = os.environ["WORK"]
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:19900", aws_access_key_id="e2eadmin",
                  aws_secret_access_key="e2esecret123", region_name="us-east-1")
FASTPATH = "http://127.0.0.1:19903"
random.seed(1013)

posts = []
for fn in sorted(glob.glob(os.path.join(work, "cans", "*.tar.gz"))):
    with tarfile.open(fn) as t:
        posts += [t.extractfile(m).read() for m in t.getmembers() if m.name.endswith(".post")]


def mint(post, t, e2e_uid=None):
    """(uid, body) for a submission of post at time t"""
    c = post["content"]
    ts = t.strftime("%Y%m%d%H%M%S.%f")
    cc, test = c.get("probe_cc", "ZZ"), (c.get("test_name") or "x").replace("_", "")
    uid = f"{ts}_{cc}_{test}_" + hashlib.sha512(json.dumps(c).encode() + ts.encode()).hexdigest()[:16]
    c = dict(c, e2e_uid=e2e_uid or uid, report_id=f"e2e-{uid}")
    return uid, json.dumps(dict(post, content=c)).encode()


def key(uid):
    ts, cc, test, _ = uid.split("_", 3)
    return f"postcans/{ts[:10]}/{ts[:10]}_{cc}_{test}/{uid}.post"


def to_fastpath(uid, body):
    requests.post(f"{FASTPATH}/{uid}", data=body, timeout=30).raise_for_status()


def at(hours_ago):
    h = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours_ago)).replace(minute=0, second=0, microsecond=0)
    return h + dt.timedelta(seconds=random.randrange(3600), microseconds=random.randrange(10**6))


def expect(rows):
    with open(os.path.join(work, "expected.tsv"), "a") as f:
        for uid, cls in rows:
            f.write(f"{uid}\t{cls}\n")


cases = [("retried", 15), ("already_ingested", 8), ("repeat_not_ingested", 8), ("repeat_and_retried", 4),
         ("unconfirmed", 4), ("reupload", 20)]
if sys.argv[1] == "setup":
    open(os.path.join(work, "expected.tsv"), "w").close()
    msmts = [json.loads(p) for p in posts[300:300 + sum(n for _, n in cases)]]
    late, rows = [], []
    for cls, n in cases:
        for post in [msmts.pop(0) for _ in range(n)]:
            t = at(3)
            uid, body = mint(post, t)
            s3.put_object(Bucket="e2e-failed", Key=key(uid), Body=body)
            retry = lambda: mint(json.loads(body), at(1), e2e_uid=uid)  # same measurement, new uid and report_id
            if cls in ("retried", "repeat_and_retried"):
                to_fastpath(*retry())
            if cls == "already_ingested":
                to_fastpath(uid, body)  # fastpath took it, the API timed out anyway
            if cls in ("repeat_not_ingested", "repeat_and_retried"):
                # the retry failed as well: a second postcan, later, so the first one is the one kept
                ruid, rbody = mint(json.loads(body), t + dt.timedelta(minutes=30), e2e_uid=uid)
                s3.put_object(Bucket="e2e-failed", Key=key(ruid), Body=rbody)
                rows.append((ruid, "retried" if cls == "repeat_and_retried" else "repeat_postcan"))
            if cls == "unconfirmed":
                late.append(retry())
            rows.append((uid, {"repeat_not_ingested": "reupload", "repeat_and_retried": "retried"}.get(cls, cls)))
    for i in range(2):
        uid = at(3).strftime("%Y%m%d%H%M%S.%f") + "_IT_webconnectivity_garbage00000" + str(i)
        s3.put_object(Bucket="e2e-failed", Key=key(uid), Body=b"not a measurement")
        rows.append((uid, "unreadable"))
    expect(rows)
    json.dump([[u, b.decode()] for u, b in late], open(os.path.join(work, "late.json"), "w"))
    print(f"setup: {len(rows)} postcans, {len(late)} retries for later")
elif sys.argv[1] == "late":
    late = json.load(open(os.path.join(work, "late.json")))
    for uid, body in late:
        to_fastpath(uid, body.encode())
    print(f"late: {len(late)} retries posted")
