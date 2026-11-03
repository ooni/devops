"""End-to-end test of the backup in compose.yml's environment, after run.sh has rendered work/ and started it.
In order:
  1. a first run takes a full backup of every table
  2. ClickHouseBackupCompleted reaches Slack once, as a notice, without email
  3. two more runs take incrementals; restoring the full and each incremental returns the rows of
     its moment, and an EmbeddedRocksDB table comes back with its exported rows
  4. a table created on the cluster's other node only: ClickHouseTableNotBackedUp names it
  5. a run whose bucket is missing fails, and ClickHouseBackupFailed reaches Slack and email
  6. a new month's full, cancelled by restarting ClickHouse: the restart doesn't wait for it, and
     the run takes the full again and prunes the oldest chain; the full restores
  7. a full interrupted by killing ClickHouse, as the runbook says to for an urgent reboot: the
     run removes what the killed backup left and takes it again
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
MEASUREMENTS = "ooni-clickhouse-backup"
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
    s3.create_bucket(Bucket=MEASUREMENTS)
    for sql in [
        "CREATE DATABASE ooni",
        "CREATE TABLE ooni.fastpath (measurement_uid String, input String, anomaly LowCardinality(String)) "
        "ENGINE = MergeTree ORDER BY measurement_uid",
        "INSERT INTO ooni.fastpath SELECT toString(number), 'https://example.org/' || toString(number % 100), "
        "if(number % 7 = 0, 't', 'f') FROM numbers(200000)",
        # ~20 MB that doesn't compress: takes ~20 s to back up with work/slow.json. In 40 parts, so
        # that it's more files than ClickHouse uploads at once (backup_threads, 16): a cancelled
        # backup only skips the files not yet started.
        "CREATE TABLE ooni.obs_web (measurement_uid String, blob String) ENGINE = MergeTree "
        "PARTITION BY cityHash64(measurement_uid) % 40 ORDER BY measurement_uid",
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
    # the script runs as the backup user, with production's grants
    with open(os.path.join(HERE, "work", "backup_user.sql")) as f:
        for sql in filter(None, (s.strip() for s in f.read().split(";"))):
            ch(sql)
    ch("CREATE DATABASE ooni", port=19912)


def test_first_run():
    print("== 1. first run: a full backup of every table")
    r = backup("backup", "run")
    check(r.returncode == 0, "the run succeeds", r.stderr)
    for table in ("fastpath", "obs_web", "test_groups", "msmt_feedback"):
        c = chains(MEASUREMENTS, table)
        check(len(c) == 1 and all(all(b.values()) for b in c.values()), f"{table}: one complete chain")
    check(any(k.endswith("/data.native.zst") for k in keys(MEASUREMENTS, "prod/ooni/test_groups/")),
          "test_groups (EmbeddedRocksDB): its rows are exported too")
    check(not keys(MEASUREMENTS, "prod/ooni/asnmeta_tmp/"), "asnmeta_tmp (excluded) isn't backed up")
    check(not keys(MEASUREMENTS, "prod/ooni/labeling_frames/"), "labeling_frames (data1's) isn't backed up")


def test_completed_alert(emails_before):
    print("== 2. ClickHouseBackupCompleted")
    title = f"ClickHouse backup measurements on {DATA3} completed"
    msgs = wait_for(f"a Slack message: {title}", lambda: [m for m in slack() if m[0].startswith(title)])
    check(len(msgs) == 1, f"one Slack message: {msgs[0][0]!r}")
    check("Tables backed up: 4, in full: 4" in msgs[0][1], f"it says: {msgs[0][1]!r}")
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


def run_in_background(config, *args):
    return subprocess.Popen(COMPOSE + ["exec", "-T", "runner", "python3", "/role/ooni_clickhouse_backup.py",
                                       "--config", f"/work/{config}.json", *args],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def test_restart_during_full():
    print("== 6. a new month's full, cancelled by restarting ClickHouse, started again")
    (chain, backups), = chains(MEASUREMENTS, "obs_web").items()
    full = f"prod/ooni/obs_web/{chain}/{min(backups)}/"
    old, previous = months_ago(2), months_ago(1)
    # obs_web's chains as at the start of a month: the full of two months ago and of last month
    for c in (old, previous):
        copy_prefix(MEASUREMENTS, full, f"prod/ooni/obs_web/{c}/{c}/")
    delete_prefix(MEASUREMENTS, f"prod/ooni/obs_web/{chain}/")

    run = run_in_background("slow", "run", "--table", "obs_web")
    wait_for("the new full's first files", lambda: set(chains(MEASUREMENTS, "obs_web")) - {old, previous}, 60)
    t0 = time.monotonic()
    # a clean stop, given time to wait for the backup if it were going to
    subprocess.run(COMPOSE + ["restart", "-t", "300", "clickhouse"], check=True, capture_output=True)
    restart_s = time.monotonic() - t0
    out, _ = run.communicate(timeout=900)
    check(run.returncode == 0, "the run succeeds", out)
    check("starting it again" in out, "the run started obs_web's backup again", out)
    # had ClickHouse waited for it, the backup would be complete and the second one an incremental on it.
    # Cancelled, it's gone: ClickHouse removes a failed backup's files.
    check("incremental" not in out, f"the restart ({restart_s:.0f}s) cancelled the backup rather than wait for it", out)
    c = chains(MEASUREMENTS, "obs_web")
    check(previous in c and old not in c and len(c) == 2 and all(all(b.values()) for b in c.values()),
          f"it took the full and pruned {old}: chains {sorted(c)}")
    new = max(c)
    ch(f"RESTORE TABLE ooni.obs_web AS restored.obs_web FROM S3('{backup_url(MEASUREMENTS, 'obs_web', new, new)}')")
    check(digest("restored.obs_web") == digest("ooni.obs_web"), f"the new full {new} restores obs_web")


def test_killed_during_full():
    print("== 7. ClickHouse killed during a full")
    before = set(chains(MEASUREMENTS, "obs_web"))
    run = run_in_background("slow", "run", "--full", "--table", "obs_web")
    wait_for("obs_web's full under way", lambda: set(chains(MEASUREMENTS, "obs_web")) - before, 60)
    subprocess.run(COMPOSE + ["kill", "clickhouse"], check=True, capture_output=True)
    subprocess.run(COMPOSE + ["start", "clickhouse"], check=True, capture_output=True)
    out, _ = run.communicate(timeout=900)
    check(run.returncode == 0, "the run succeeds", out)
    check("removed incomplete chain" in out, "it removed what the killed backup left", out)
    check("starting it again" in out, "and took obs_web's full again", out)
    c = chains(MEASUREMENTS, "obs_web")
    new = sorted(set(c) - before)
    check(len(new) == 1 and len(c) == 2 and max(before) in c and all(all(b.values()) for b in c.values()),
          f"two complete chains, the new one and the newest from before; the oldest pruned: {sorted(c)}")


def main():
    setup()
    emails_before = email_attempts()
    test_first_run()
    test_completed_alert(emails_before)
    test_incremental_and_restore()
    test_not_backed_up_alert()
    test_failure_alert(emails_before)
    test_restart_during_full()
    test_killed_during_full()
    print("PASS")


if __name__ == "__main__":
    main()
