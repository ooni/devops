"""End-to-end test of the backup in compose.yml's environment, after run.sh has rendered work/ and started it.
In order:
  1. a first run takes a full backup of every table, each job to its own bucket
  2. ClickHouseBackupCompleted reaches Slack once per job, as a notice, without email
  3. two more runs take incrementals; restoring the full and each incremental returns the rows of
     its moment, and an EmbeddedRocksDB table comes back with its exported rows
  4. a table created on the cluster's other node only: ClickHouseTableNotBackedUp names it
  5. a run whose bucket is missing fails, and ClickHouseBackupFailed reaches Slack and email
  6. a new month's full interrupted by killing ClickHouse deletes nothing; the next run
     removes what it left, takes the full and prunes the oldest chain, and the full restores
Prints each check; exits 1 at the first failure."""
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

import boto3

HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE = shlex.split(os.environ.get("COMPOSE", "docker compose")) + ["-f", os.path.join(HERE, "compose.yml")]
MEASUREMENTS, PRIVATE = "ooni-clickhouse-backup", "ooni-clickhouse-backup-private"
DATA3 = "data3.htz-fsn.prod.ooni.nu"  # the instance label prometheus.yml gives the textfile
s3 = boto3.client(
    "s3", endpoint_url="http://127.0.0.1:19910", region_name="us-east-1",
    aws_access_key_id="testkey", aws_secret_access_key="testsecret123",
)


def check(ok, what, output=""):
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        if output:
            print("  the script said:\n" + output[-3000:])
        sys.exit(1)


def http(url, data=None):
    with urllib.request.urlopen(url, data=data, timeout=30) as r:
        return r.read().decode()


def ch(sql, port=19911):
    """a query on data3, or with port=19912 on the cluster's other node, data1"""
    return http(f"http://127.0.0.1:{port}/?user=admin&password=admin", sql.encode()).strip()


def backup(config, *args):
    """Run the backup script in the runner container, as the timer runs it on data3"""
    cmd = COMPOSE + ["exec", "-T", "runner", "python3", "/role/ooni_clickhouse_backup.py",
                     "--config", f"/work/{config}.json", *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def keys(bucket, prefix):
    pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
    return [o["Key"] for page in pages for o in page.get("Contents", [])]


def chains(bucket, table):
    """{chain: {backup: complete}} under prod/ooni/<table>/"""
    out = {}
    for key in keys(bucket, f"prod/ooni/{table}/"):
        chain, name = key.split("/")[3:5]
        backups = out.setdefault(chain, {})
        backups[name] = backups.get(name, False) or key.endswith(f"/{name}/.backup")
    return out


def copy_prefix(bucket, src, dst):
    for key in keys(bucket, src):
        s3.copy_object(Bucket=bucket, Key=dst + key[len(src):], CopySource={"Bucket": bucket, "Key": key})


def delete_prefix(bucket, prefix):
    for key in keys(bucket, prefix):
        s3.delete_object(Bucket=bucket, Key=key)


def wait_for(what, get, timeout=150):
    """Poll get() until it returns something truthy"""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            value = get()
        except OSError:
            value = None
        if value:
            return value
        time.sleep(2)
    check(False, f"{what}, within {timeout}s")


def slack():
    """(title, text) of every message the Slack stand-in has received"""
    return [(a["title"].strip(), a.get("text", "").strip()) for m in json.loads(http("http://127.0.0.1:19980/"))
            for a in m.get("attachments", [])]


def email_attempts():
    lines = http("http://127.0.0.1:19993/metrics").splitlines()
    return sum(float(l.split()[-1]) for l in lines
               if l.startswith('alertmanager_notifications_total{integration="email"'))


def months_ago(n):
    now = datetime.now(timezone.utc)
    y, m = divmod(now.year * 12 + now.month - 1 - n, 12)
    return f"{y}{m + 1:02}01T023000Z"


def setup():
    print("== waiting for the services")
    wait_for("ClickHouse", lambda: ch("SELECT 1") == "1")
    wait_for("ClickHouse's other node", lambda: ch("SELECT 1", port=19912) == "1")
    wait_for("MinIO", lambda: http("http://127.0.0.1:19910/minio/health/live") == "")
    wait_for("Prometheus", lambda: "Ready" in http("http://127.0.0.1:19990/-/ready"))
    wait_for("Alertmanager", lambda: "OK" in http("http://127.0.0.1:19993/-/ready"))
    wait_for("Slack stand-in", lambda: http("http://127.0.0.1:19980/") == "[]")
    for bucket in (MEASUREMENTS, PRIVATE):
        s3.create_bucket(Bucket=bucket)
    for sql in [
        "CREATE DATABASE ooni",
        "CREATE TABLE ooni.fastpath (measurement_uid String, input String, anomaly LowCardinality(String)) "
        "ENGINE = MergeTree ORDER BY measurement_uid",
        "INSERT INTO ooni.fastpath SELECT toString(number), 'https://example.org/' || toString(number % 100), "
        "if(number % 7 = 0, 't', 'f') FROM numbers(200000)",
        # ~20 MB that doesn't compress: takes ~20 s to back up with work/slow.json
        "CREATE TABLE ooni.obs_web (measurement_uid String, blob String) ENGINE = MergeTree ORDER BY measurement_uid",
        "INSERT INTO ooni.obs_web SELECT toString(number), randomString(4096) FROM numbers(5000)",
        "CREATE TABLE ooni.test_groups (name String, pattern String) ENGINE = EmbeddedRocksDB PRIMARY KEY name",
        "INSERT INTO ooni.test_groups VALUES ('a', '1.2.3.4'), ('b', '5.6.7.8')",
        "CREATE TABLE ooni.msmt_feedback (measurement_uid String, comment String) ENGINE = MergeTree ORDER BY measurement_uid",
        "INSERT INTO ooni.msmt_feedback VALUES ('m1', 'blocked?')",
        "CREATE TABLE ooni.labeling_frames (measurement_uid String) ENGINE = MergeTree ORDER BY measurement_uid",
        "INSERT INTO ooni.labeling_frames VALUES ('x')",
        "CREATE TABLE ooni.asnmeta_tmp (asn UInt32) ENGINE = MergeTree ORDER BY asn",  # excluded: *_tmp
    ]:
        ch(sql)
    ch("CREATE DATABASE ooni", port=19912)


def test_first_run():
    print("== 1. first run: a full backup of every table")
    r = backup("backup", "run")
    check(r.returncode == 0, "the run succeeds", r.stderr)
    for bucket, table in [(MEASUREMENTS, "fastpath"), (MEASUREMENTS, "obs_web"),
                          (MEASUREMENTS, "test_groups"), (PRIVATE, "msmt_feedback")]:
        c = chains(bucket, table)
        check(len(c) == 1 and all(all(b.values()) for b in c.values()), f"{table}: one complete chain in {bucket}")
    check(any(k.endswith("/data.native.zst") for k in keys(MEASUREMENTS, "prod/ooni/test_groups/")),
          "test_groups (EmbeddedRocksDB): its rows are exported too")
    check(not keys(MEASUREMENTS, "prod/ooni/msmt_feedback/"), "msmt_feedback isn't in the measurements bucket")
    check(not keys(MEASUREMENTS, "prod/ooni/asnmeta_tmp/"), "asnmeta_tmp (excluded) isn't backed up")
    check(not keys(MEASUREMENTS, "prod/ooni/labeling_frames/"), "labeling_frames (data1's) isn't backed up")


def test_completed_alert(emails_before):
    print("== 2. ClickHouseBackupCompleted")
    for job, tables in (("measurements", 3), ("private", 1)):
        title = f"ClickHouse backup {job} on {DATA3} completed"
        msgs = wait_for(f"a Slack message: {title}", lambda: [m for m in slack() if m[0].startswith(title)])
        check(len(msgs) == 1, f"one Slack message for {job}: {msgs[0][0]!r}")
        check(f"Tables backed up: {tables}, in full: {tables}" in msgs[0][1], f"it says: {msgs[0][1]!r}")
    check(not any(t.startswith("[FIRING]") for t, _ in slack()), "no [FIRING] in the titles")
    check(email_attempts() == emails_before, "no email sent")



def digest(table):
    """row count and a checksum of every row"""
    return ch(f"SELECT count(), sum(cityHash64(*)) FROM {table}")


def backup_url(bucket, table, chain, name):
    return f"http://minio:9000/{bucket}/prod/ooni/{table}/{chain}/{name}"


def test_incremental_and_restore():
    print("== 3. incrementals, and restoring each backup of a chain")
    # for step 4: a table created on data1 alone, which no job backs up
    ch("CREATE TABLE ooni.made_on_data1 (x UInt8) ENGINE = MergeTree ORDER BY x", port=19912)
    # fastpath as at the first run's full, then after each of two more runs
    states = [digest("ooni.fastpath")]
    for first in (200000, 201000):
        ch(f"INSERT INTO ooni.fastpath SELECT toString(number), 'https://example.org/new', 'f' FROM numbers({first}, 1000)")
        r = backup("backup", "run")
        check(r.returncode == 0, "the run succeeds", r.stderr)
        states.append(digest("ooni.fastpath"))
    (chain, backups), = chains(MEASUREMENTS, "fastpath").items()
    names = sorted(backups)
    check(len(names) == 3 and all(backups.values()), f"fastpath: a full and two incrementals in chain {chain}")
    ch("CREATE DATABASE restored")
    for i, (name, state) in enumerate(zip(names, states)):
        what = "the full" if i == 0 else f"incremental {i}"
        ch(f"RESTORE TABLE ooni.fastpath AS restored.fastpath_{i} FROM S3('{backup_url(MEASUREMENTS, 'fastpath', chain, name)}')")
        check(digest(f"restored.fastpath_{i}") == state, f"{what} restores fastpath as it was then ({state.split()[0]} rows)")

    # EmbeddedRocksDB: BACKUP keeps only the schema, the rows are in data.native.zst (the runbook's steps 2 and 3)
    c = chains(MEASUREMENTS, "test_groups")
    chain = max(ch_ for ch_, b in c.items() if any(b.values()))
    url = backup_url(MEASUREMENTS, "test_groups", chain, max(n for n, ok in c[chain].items() if ok))
    ch(f"RESTORE TABLE ooni.test_groups AS restored.test_groups FROM S3('{url}')")
    ch(f"INSERT INTO restored.test_groups SELECT * FROM s3('{url}/data.native.zst', 'Native')")
    check(digest("restored.test_groups") == digest("ooni.test_groups"),
          "test_groups (EmbeddedRocksDB) restores with its exported rows")


def test_not_backed_up_alert():
    print("== 4. a table no backup covers: ClickHouseTableNotBackedUp")
    title = "[FIRING] ClickHouse table made_on_data1 is not backed up (on data1)"
    msgs = wait_for(f"a Slack message: {title}", lambda: [m for m in slack() if m[0] == title])
    check("Add it to a job" in msgs[0][1], f"it says what to do: {msgs[0][1][:90]!r}...")
    others = [t for t, _ in slack() if "is not backed up" in t and t != title]
    check(not others, f"no other table is reported (labeling_frames is data1's, asnmeta_tmp excluded): {others}")


def test_failure_alert(emails_before):
    print("== 5. a run that fails: ClickHouseBackupFailed")
    r = backup("broken", "run")
    check(r.returncode == 1, "the run exits 1", r.stderr)
    title = f"[FIRING] ClickHouse backup of labeling_frames (broken) failed on {DATA3}"
    msgs = wait_for(f"a Slack message: {title}", lambda: [m for m in slack() if m[0] == title])
    check("Nothing was deleted" in msgs[0][1], f"it says what was done: {msgs[0][1]!r}")
    wait_for("an email attempt for it", lambda: email_attempts() > emails_before)
    check(not any(t.startswith("ClickHouse backup broken") for t, _ in slack()), "no 'completed' message for it")


def test_interrupted_full():
    print("== 6. a new month's full, interrupted, then completed")
    (chain, backups), = chains(MEASUREMENTS, "obs_web").items()
    full = f"prod/ooni/obs_web/{chain}/{min(backups)}/"
    old, previous = months_ago(2), months_ago(1)
    # obs_web's chains as at the start of a month: the full of two months ago and of last month
    for c in (old, previous):
        copy_prefix(MEASUREMENTS, full, f"prod/ooni/obs_web/{c}/{c}/")
    delete_prefix(MEASUREMENTS, f"prod/ooni/obs_web/{chain}/")

    run = subprocess.Popen(COMPOSE + ["exec", "-T", "runner", "python3", "/role/ooni_clickhouse_backup.py",
                                      "--config", "/work/slow.json", "run", "--table", "obs_web"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    wait_for("the new full's first files", lambda: set(chains(MEASUREMENTS, "obs_web")) - {old, previous}, 60)
    # killed, not stopped: ClickHouse waits for running backups when it stops
    # (shutdown_wait_backups_and_restores), so a clean stop would finish this one
    subprocess.run(COMPOSE + ["kill", "clickhouse"], check=True, capture_output=True)
    subprocess.run(COMPOSE + ["start", "clickhouse"], check=True, capture_output=True)
    out, _ = run.communicate(timeout=900)
    check(run.returncode == 1, "the interrupted run exits 1", out)
    c = chains(MEASUREMENTS, "obs_web")
    new = sorted(set(c) - {old, previous})
    check(new and not any(c[new[0]].values()), f"the new chain {new[0]} has no .backup")
    check(all(c[x][x] for x in (old, previous)), f"both older chains, {old} and {previous}, are still there")

    wait_for("ClickHouse after it was killed", lambda: ch("SELECT 1") == "1")
    r = backup("backup", "run", "--table", "obs_web")
    check(r.returncode == 0, "the next run succeeds", r.stderr)
    check("removed incomplete chain" in r.stderr, "it removed the interrupted full")
    c = chains(MEASUREMENTS, "obs_web")
    check(previous in c and old not in c and len(c) == 2 and all(all(b.values()) for b in c.values()),
          f"it took the full and pruned {old}: chains {sorted(c)}")
    new = max(c)
    ch(f"RESTORE TABLE ooni.obs_web AS restored.obs_web FROM S3('{backup_url(MEASUREMENTS, 'obs_web', new, new)}')")
    check(digest("restored.obs_web") == digest("ooni.obs_web"), f"the new full {new} restores obs_web")


def main():
    setup()
    emails_before = email_attempts()
    test_first_run()
    test_completed_alert(emails_before)
    test_incremental_and_restore()
    test_not_backed_up_alert()
    test_failure_alert(emails_before)
    test_interrupted_full()
    print("PASS")


if __name__ == "__main__":
    main()
