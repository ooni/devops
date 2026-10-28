"""The whole life of a backup, in compose.yml's environment (run.sh starts it): production's schema
(scripts/cluster-migration/schema.sql) on data1-3, rows in every table, backups by production's jobs
(a full, then an incremental), then a restore with the script's restore command after each of:
  1. data2 is lost or re-imaged: it comes back empty and rejoins the cluster
  2. data1 is: its own tables, which only its backups hold, come back too
  3. the whole cluster is lost, Keeper too: data3, data1 and data2 are restored from the backups alone
  4. a researcher restores the measurement tables on their own one-node cluster, with a read-only key,
     and can't read the private ones
After each one, every table on the restored nodes must have the rows and the definition it had at
the last backup. Prints each check; exits 1 at the first failure."""
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import time

import boto3
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..", "..", "..", "..", "..")
SCHEMA = os.path.join(REPO, "scripts", "cluster-migration", "schema.sql")
COMPOSE = shlex.split(os.environ.get("COMPOSE", "docker compose")) + ["-f", os.path.join(HERE, "compose.yml")]
NODES = ["data1", "data2", "data3"]
MEASUREMENTS, PRIVATE = "ooni-clickhouse-backup", "ooni-clickhouse-backup-private"
s3 = boto3.client(
    "s3", endpoint_url="http://127.0.0.1:19920", region_name="us-east-1",
    aws_access_key_id="testkey", aws_secret_access_key="testsecret123",
)


def check(ok, what, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        if detail:
            print(detail[-4000:])
        sys.exit(1)


def compose(*args, **kw):
    return subprocess.run(COMPOSE + list(args), capture_output=True, text=True, **kw)


def ch(node, sql, stdin=None):
    """A query on node, or with stdin, several (clickhouse-client --multiquery)"""
    args = ["exec", "-T", node, "clickhouse-client", "-u", "admin", "--password", "admin"]
    args += ["--database", "ooni", "--multiquery"] if stdin is not None else ["-q", sql]
    r = compose(*args, input=stdin if stdin is not None else "")
    if r.returncode:
        raise RuntimeError(f"{node}: {r.stderr.strip()[-2000:]}")
    return r.stdout.strip()


def tool(config, *args):
    """The backup script in the runner container, with configs/<config>.json"""
    return compose("exec", "-T", "runner", "python3", "/role/ooni_clickhouse_backup.py",
                   "--config", f"/configs/{config}.json", *args)


def wait_for(what, ok, timeout=120):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            if ok():
                return
        except Exception:
            pass
        time.sleep(1)
    check(False, f"{what} within {timeout}s")


def wipe(*services):
    """Lose these servers and their disks, and start them again empty, as after a re-image"""
    compose("rm", "-s", "-f", "-v", *services)
    compose("up", "-d", *services)
    for s in services:
        if s != "keeper":
            wait_for(f"{s} answering", lambda s=s: ch(s, "SELECT 1") == "1")


# ---- the role's settings, as production sets them

def role_vars():
    group = yaml.safe_load(open(os.path.join(REPO, "ansible", "group_vars", "clickhouse", "vars.yml")))
    defaults = yaml.safe_load(open(os.path.join(HERE, "..", "..", "defaults", "main.yml")))
    return group["clickhouse_backup_private_tables"], group["clickhouse_backup_data1_tables"], defaults["clickhouse_backup_exclude_tables"]


def write_configs():
    """Each node's config as the role renders it, with host_vars' jobs: data3 backs up the replicated
    tables (measurements, private), data1 its own tables; data2 only restores, with data3's jobs"""
    private, data1_tables, excluded = role_vars()
    data3_jobs = [
        {"name": "measurements", "s3_bucket": MEASUREMENTS, "include_tables": ["*"], "exclude_tables": private + data1_tables},
        {"name": "private", "s3_bucket": PRIVATE, "include_tables": private, "exclude_tables": []},
    ]
    jobs = {"data1": [{"name": "data1", "s3_bucket": MEASUREMENTS, "include_tables": data1_tables, "exclude_tables": []}],
            "data2": data3_jobs, "data3": data3_jobs}
    os.makedirs(os.path.join(HERE, "configs"), exist_ok=True)
    for node in NODES + ["researcher"]:
        conf = {
            "database": "ooni", "cluster": "oonidata_cluster",
            "clickhouse_url": f"http://{node}:8123/", "clickhouse_user": "admin", "clickhouse_password": "admin",
            "s3_endpoint": "http://minio:9000", "s3_prefix": "prod",
            "s3_access_key_id": "testkey", "s3_secret_access_key": "testsecret123",
            "exclude_tables": excluded, "keep_chains": 2, "poll_interval_seconds": 1,
            "lock_file": f"/tmp/{node}.lock", "state_file": f"/tmp/{node}.state.json", "metrics_file": f"/tmp/{node}.prom",
            "jobs": jobs.get(node, []),
        }
        if node == "researcher":
            # the published read-only key, for the measurement tables only
            conf.update(s3_access_key_id="researcher", s3_secret_access_key="researchersecret",
                        jobs=[{"name": "measurements", "s3_bucket": MEASUREMENTS, "include_tables": ["*"], "exclude_tables": []}])
        json.dump(conf, open(os.path.join(HERE, "configs", f"{node}.json"), "w"), indent=2)
    tried = dict(json.load(open(os.path.join(HERE, "configs", "researcher.json"))),
                 jobs=[{"name": "private", "s3_bucket": PRIVATE, "include_tables": ["*"], "exclude_tables": []}])
    json.dump(tried, open(os.path.join(HERE, "configs", "researcher-private.json"), "w"), indent=2)
    return private, data1_tables, excluded


# ---- what a node holds

def snapshot(node):
    """{table: (engine, rows, checksum of the rows, definition)}; FINAL where merges change the rows"""
    out = {}
    for line in ch(node, "SELECT name, engine, create_table_query FROM system.tables WHERE database = 'ooni' "
                         "AND NOT startsWith(name, '.inner') ORDER BY name FORMAT TSV").splitlines():
        name, engine, create = line.split("\t", 2)
        final = " FINAL" if re.search(r"(Replacing|Summing|Collapsing|Aggregating)MergeTree", engine) else ""
        # a view's rows are its table's, compared there with FINAL
        rows = "" if engine == "MaterializedView" else ch(node, f"SELECT count(), sum(cityHash64(*)) FROM ooni.`{name}`{final} FORMAT TSV")
        out[name] = (engine, rows, re.sub(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", "<uuid>", create))
    return out


def same(got, want, what, tables=None, empty=()):
    tables = sorted(want) if tables is None else tables
    bad = [t for t in tables if t not in empty and got.get(t) != want.get(t)]
    bad += [t for t in empty if t not in got or not got[t][1].startswith("0\t")]
    detail = "\n".join(f"    {t}:\n      want {want.get(t)}\n      got  {got.get(t)}" for t in bad)
    check(not bad, what, detail)


def all_replicas_active(node):
    rows = ch(node, "SELECT table, active_replicas, total_replicas FROM system.replicas WHERE database = 'ooni' FORMAT TSV")
    bad = [r for r in rows.splitlines() if r.split("\t")[1] != "3" or r.split("\t")[2] != "3"]
    check(rows and not bad, f"{node}: every replicated table has 3 active replicas", "\n".join(bad))


# ---- the steps

def setup(data1_tables):
    print("== production's schema and rows in every table")
    wait_for("MinIO", lambda: s3.list_buckets() is not None)
    for node in NODES + ["researcher"]:
        wait_for(f"{node} answering", lambda n=node: ch(n, "SELECT 1") == "1")
    for bucket in (MEASUREMENTS, PRIVATE):
        s3.create_bucket(Bucket=bucket)
    # a key that can read the measurements bucket and nothing else, as the published one would
    policy = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": [f"arn:aws:s3:::{MEASUREMENTS}/*"]},
        {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"], "Resource": [f"arn:aws:s3:::{MEASUREMENTS}"]}]})
    r = compose("exec", "-T", "minio", "sh", "-c",
                "mc alias set local http://127.0.0.1:9000 testkey testsecret123 >/dev/null"
                " && cat > /tmp/ro.json && mc admin policy create local measurements-read /tmp/ro.json >/dev/null"
                " && mc admin user add local researcher researchersecret >/dev/null"
                " && mc admin policy attach local measurements-read --user researcher >/dev/null", input=policy)
    check(r.returncode == 0, "a read-only key for the measurements bucket", r.stderr)

    ch("data1", "CREATE DATABASE IF NOT EXISTS ooni ON CLUSTER oonidata_cluster")
    ch("data1", None, stdin=open(SCHEMA).read())
    tables = dict(line.split("\t") for line in ch("data1", "SELECT name, engine FROM system.tables WHERE database = 'ooni' "
                                                           "AND NOT startsWith(name, '.inner') FORMAT TSV").splitlines())
    check(all(ch(n, "SELECT count() FROM system.tables WHERE database = 'ooni'") == str(len(tables)) for n in NODES),
          f"schema.sql's {len(tables)} tables on every node")
    for t, engine in sorted(tables.items()):
        # the replicated tables, and the ones only data1 holds: their rows go in on data1. The view
        # fills its table from fastpath's inserts below.
        if (engine.startswith("Replicated") or t in data1_tables) and t != "counters_asn_test_list_data":
            ch("data1", random_rows(t, 200))
    load_lookup_tables(tables, data1_tables)
    add_measurements(100)
    print(f"  ok   rows in {len(tables) - 2} tables, and in counters_asn_test_list through fastpath")
    return tables


def random_rows(table, n):
    """An INSERT of n random rows; a CollapsingMergeTree's sign column must be 1 or -1"""
    create = ch("data1", f"SELECT create_table_query FROM system.tables WHERE database = 'ooni' AND name = '{table}'")
    sign = re.search(r"CollapsingMergeTree\([^)]*?(\w+)\)", create)
    replace = f" REPLACE (1 AS {sign.group(1)})" if sign else ""
    return (f"INSERT INTO ooni.`{table}` SELECT *{replace} FROM generateRandom() LIMIT {n} "
            "SETTINGS max_partitions_per_insert_block = 0")


def structure(node, table):
    return ch(node, f"SELECT arrayStringConcat(groupArray(concat(name, ' ', type)), ', ') FROM system.columns "
                    f"WHERE database = 'ooni' AND table = '{table}' AND default_kind NOT IN ('MATERIALIZED', 'ALIAS')")


def load_lookup_tables(tables, data1_tables):
    """The same rows on every node, as the updaters write them"""
    for t, engine in sorted(tables.items()):
        if engine.startswith("Replicated") or engine == "MaterializedView" or t in data1_tables or t == "counters_asn_test_list_data":
            continue
        cols = structure("data1", t)
        for node in NODES:
            ch(node, f"INSERT INTO ooni.`{t}` SELECT * FROM generateRandom('{cols}', 42) LIMIT 20")


def add_measurements(n, tag="m"):
    """Measurements of a test-list URL, through fastpath on data1 as in production: the view counts them"""
    ch("data1", "INSERT INTO ooni.citizenlab SELECT 'example.org', 'https://example.org/', 'ZZ', 'NEWS' "
                "WHERE (SELECT count() FROM ooni.citizenlab WHERE url = 'https://example.org/') = 0")
    ch("data1", "INSERT INTO ooni.fastpath (measurement_uid, report_id, input, probe_cc, probe_asn, test_name, "
                f"measurement_start_time) SELECT concat('{tag}', toString(number)), 'r', 'https://example.org/', 'IT', "
                f"3269, 'web_connectivity', now() - 3600 FROM numbers({n})")


def backups():
    print("== production's backups: a full, more rows, an incremental")
    for i, kind in enumerate(["full", "incremental"]):
        if i:
            ch("data1", random_rows("obs_web", 50))
            ch("data1", random_rows("labeling_frames", 50))
            add_measurements(30, tag="i")
            time.sleep(1)  # a new backup name: the names are timestamps to the second
        for node in NODES:
            ch(node, "SYSTEM SYNC REPLICA ooni.fastpath")
        for node in ("data3", "data1"):
            r = tool(node, "run")
            check(r.returncode == 0, f"{kind} backup of {node}'s jobs", r.stderr)
    want = {n: snapshot(n) for n in NODES}
    counted = ch("data1", "SELECT sum(msmt_cnt) FROM ooni.counters_asn_test_list")
    check(counted == "130", f"the view counted fastpath's 130 measurements ({counted})")
    return want


def restore(node, config=None):
    r = tool(config or node, "restore")
    check(r.returncode == 0, f"restore on {node}", r.stderr)
    return r.stderr


def lose_data2(want):
    print("== 1. data2 lost or re-imaged, then restored")
    wipe("data2")
    check(ch("data2", "SELECT count() FROM system.tables WHERE database = 'ooni'") in ("0", ""), "data2 comes back empty")
    log = restore("data2")
    check("dropping stale replica data2" in log, "its leftover replicas were removed from Keeper", log)
    same(snapshot("data2"), want["data2"], "data2 has every table, rows and definition, as before")
    all_replicas_active("data3")
    r = tool("data2", "restore")
    check(r.returncode == 0 and "0 tables restored" in r.stderr, "a second restore finds nothing to do", r.stderr)


def lose_data1(want, data1_tables):
    print("== 2. data1 lost or re-imaged, then restored")
    wipe("data1")
    log = restore("data1")
    check(all(f"{t}: restored from" in log for t in data1_tables), "data1's own tables came from its backups", log)
    same(snapshot("data1"), want["data1"], "data1 has every table, rows and definition, as before")
    all_replicas_active("data3")


def lose_cluster(want, excluded_tables):
    print("== 3. the whole cluster lost, Keeper too, then restored from the backups")
    wipe("keeper", "data1", "data2", "data3")
    # data2 first: its SSDs take the backups in and serve the other replicas fastest
    log = restore("data2")
    check("fetching" not in log, "data2 restored every replicated table from the backups", log)
    log = restore("data1")
    check(log.index("restore: tables ready") < log.index(": fetched"), "data1 had every table before its fetches finished", log)
    restore("data3")
    # the tables no backup holds (the fingerprints, rebuilt by their updater) come from schema.sql
    ch("data1", None, stdin=open(SCHEMA).read())
    for node in NODES:
        same(snapshot(node), want[node], f"{node} has every table as at the last backup, the excluded ones empty",
             tables=[t for t in want[node] if t not in excluded_tables], empty=[t for t in want[node] if t in excluded_tables])
    all_replicas_active("data3")
    before = int(ch("data2", "SELECT sum(msmt_cnt) FROM ooni.counters_asn_test_list"))
    add_measurements(5, tag="after")
    wait_for("the new rows on data2", lambda: ch("data2", "SELECT sum(msmt_cnt) FROM ooni.counters_asn_test_list") == str(before + 5), 60)
    check(True, "the view counts new measurements again, and data2 has them")


def researcher(want, private, data1_tables, excluded_tables):
    print("== 4. a researcher's own database, from the measurements bucket with a read-only key")
    ch("researcher", "CREATE DATABASE IF NOT EXISTS ooni")
    restore("researcher")
    got = snapshot("researcher")
    check(not set(private) & set(got), "no private table", ", ".join(sorted(set(private) & set(got))))
    # every table the measurements bucket holds: data3's, and data1's own tables with data1's rows
    expected = [t for t in want["data3"] if t not in private and t not in excluded_tables]
    check(sorted(got) == sorted(expected), f"the {len(expected)} tables in the measurements bucket",
          f"    missing: {sorted(set(expected) - set(got))}\n    extra: {sorted(set(got) - set(expected))}")
    source = {t: want["data1" if t in data1_tables else "data3"][t] for t in expected}
    same(got, source, "each has the rows and definition of the node it was backed up from")
    r = tool("researcher-private", "restore")
    check(r.returncode != 0, "the read-only key can't restore the private tables", r.stderr)


def main():
    private, data1_tables, excluded = write_configs()
    tables = setup(data1_tables)
    excluded_tables = [t for t in tables if any(fnmatch.fnmatchcase(t, p) for p in excluded)]
    want = backups()
    lose_data2(want)
    lose_data1(want, [t for t in data1_tables if t in tables])
    lose_cluster(want, excluded_tables)
    researcher(want, private, data1_tables, excluded_tables)
    print("all passed")


if __name__ == "__main__":
    main()
