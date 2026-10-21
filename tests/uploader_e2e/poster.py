"""Submit measurements the way the ooniprobe service does: mint a measurement_uid from the submission time,
POST to the fastpath, and on failure put the measurement in the failed-reports bucket. Uses real
measurements from the cans in $WORK/cans, each tagged with its uid so the check can tell them apart.
usage: poster.py HOURS_AGO COUNT [--timeout S] [--threads N]     appends uid<TAB>outcome to $WORK/ledger.tsv"""
import argparse, concurrent.futures as cf, datetime as dt, glob, hashlib, json, os, random, tarfile, threading
import boto3, requests

ap = argparse.ArgumentParser()
ap.add_argument("hours_ago", type=int)
ap.add_argument("count", type=int)
ap.add_argument("--timeout", type=float, default=10)
ap.add_argument("--threads", type=int, default=4)
a = ap.parse_args()
work = os.environ.get("WORK") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "work")

# take the next COUNT measurements from the cans, so every submission is a different measurement
offset_f = os.path.join(work, "poster.offset")
offset = int(open(offset_f).read()) if os.path.exists(offset_f) else 0
posts = []
for fn in sorted(glob.glob(os.path.join(work, "cans", "*.tar.gz"))):
    with tarfile.open(fn) as t:
        posts += [t.extractfile(m).read() for m in t.getmembers() if m.name.endswith(".post")]
batch = posts[offset:offset + a.count]
assert len(batch) == a.count, f"not enough measurements in {work}/cans"
open(offset_f, "w").write(str(offset + len(batch)))

s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:19900", aws_access_key_id="e2eadmin",
                  aws_secret_access_key="e2esecret123", region_name="us-east-1")
hour = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=a.hours_ago)).replace(minute=0, second=0, microsecond=0)
lock = threading.Lock()
ledger = open(os.path.join(work, "ledger.tsv"), "a")

def submit(raw):
    post = json.loads(raw)
    c = post["content"]
    t = hour + dt.timedelta(seconds=random.randrange(3600), microseconds=random.randrange(10**6))
    ts = t.strftime("%Y%m%d%H%M%S.%f")
    cc = c.get("probe_cc", "ZZ")
    test = (c.get("test_name") or "x").replace("_", "")
    h = hashlib.sha512(raw + ts.encode()).hexdigest()[:16]
    uid = f"{ts}_{cc}_{test}_{h}"
    c["e2e_uid"] = uid
    c["report_id"] = f"e2e-{uid}"  # unique (report_id, input): the API looks measurements up by those
    data = json.dumps(post).encode()
    try:
        r = requests.post(f"http://127.0.0.1:19903/{uid}", data=data, timeout=a.timeout)
        r.raise_for_status()
        outcome = "fastpath"
    except Exception:
        key = f"postcans/{ts[:10]}/{ts[:10]}_{cc}_{test}/{uid}.post"
        s3.put_object(Bucket="e2e-failed", Key=key, Body=data)
        outcome = "failed_bucket"
    with lock:
        ledger.write(f"{uid}\t{outcome}\n")
        ledger.flush()
    return outcome

with cf.ThreadPoolExecutor(a.threads) as ex:
    res = list(ex.map(submit, batch))
print(f"posted {len(res)} for hour {hour:%Y%m%d%H}: {res.count('fastpath')} to fastpath, "
      f"{res.count('failed_bucket')} to the failed bucket")
