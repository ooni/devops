#!/usr/bin/env python3
"""
Back up a ClickHouse database to S3-compatible object storage using
ClickHouse's native BACKUP, with one incremental chain per table.

Configured by /etc/ooni/clickhouse-backup.json (see the clickhouse_backup
Ansible role). Runs from a systemd timer. The config lists one or more jobs,
run one after the other; each job backs up a set of tables to its own bucket
(R2 tokens grant access per bucket, so private tables get a bucket of their
own).

Layout in each bucket:

    <prefix>/<database>/<table>/<chain>/<backup>/          a native backup
    <prefix>/<database>/<table>/<chain>/<backup>/data.native.zst
                                                           data export, for
                                                           EmbeddedRocksDB and
                                                           Join tables only
    <prefix>/<database>/<table>/<chain>/KEEP-<label>       pin, never pruned

<chain> and <backup> are UTC timestamps (20261013T023000Z). The first backup
of a chain is a full backup; every later one is incremental on top of the
previous one. A table starts a new chain at its first backup in each
calendar month (UTC): the 1st with daily runs, the first Sunday with weekly
ones. A backup is complete once ClickHouse has written its .backup file,
which it does last.

Why per table: a new full backup of obs_web takes more than a day at our
bandwidth cap, so one failure shouldn't throw away the other tables' work,
and chains can be restarted one table at a time.

Why the data export: BACKUP writes only the CREATE statement for
EmbeddedRocksDB and Join tables (checked on 24.8.6.70), so their rows are
exported separately in Native format.

ClickHouse reads the bucket credentials from an <s3> endpoint in its config
(config.d/ooni_backup_s3.xml); this script only uses them itself, through
boto3, to list and delete backups.

Commands:
    run [--job J ...] [--full] [--table T ...] [--keep LABEL]
    list [--job J ...] [--table T ...]
    release [--job J ...] LABEL

After each table, the result goes to a Prometheus textfile (metrics_file in
the config) for node_exporter: last success and attempt per table, whether
the last attempt failed, its duration and size, and whether a job is running.
At the end of a run, each job's result: when it finished, how long it took,
and how many tables it backed up, as full backups and in all, and failed.

Monitor with:  sudo journalctl -f --identifier ooni-clickhouse-backup
"""

import argparse
import fcntl
import fnmatch
import json
import logging
import os
import re
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import boto3  # debdeps: python3-boto3
from botocore.config import Config as BotoConfig

log = logging.getLogger("ooni-clickhouse-backup")

DEFAULT_CONFIG = "/etc/ooni/clickhouse-backup.json"
TS_FMT = "%Y%m%dT%H%M%SZ"
SAFE_NAME = re.compile(r"^[A-Za-z0-9_]+$")
# BACKUP stores only the schema of these engines, so their rows are exported
EXPORT_ENGINES = {"EmbeddedRocksDB", "Join"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ts(dt: datetime) -> str:
    return dt.strftime(TS_FMT)


def parse_ts(s: str) -> datetime:
    return datetime.strptime(s, TS_FMT).replace(tzinfo=timezone.utc)


def size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.2f} TiB"


def sql_str(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


class ClickHouse:
    """Minimal client for the HTTP interface"""

    def __init__(self, url: str, user: str, password: str):
        self.url = url.rstrip("/") + "/"
        self.user = user
        self.password = password

    def query(self, sql: str, settings: dict = None, timeout: float = 600) -> str:
        url = self.url
        if settings:
            url += "?" + urllib.parse.urlencode(settings)
        req = urllib.request.Request(url, data=sql.encode(), method="POST")
        req.add_header("X-ClickHouse-User", self.user)
        if self.password:
            req.add_header("X-ClickHouse-Key", self.password)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode()
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace").strip()
            raise RuntimeError(f"ClickHouse error: {body}") from None

    def rows(self, sql: str, **kw) -> list:
        out = self.query(sql + "\nFORMAT JSONEachRow", **kw)
        return [json.loads(line) for line in out.splitlines() if line.strip()]


class Store:
    """The backup bucket, as seen by ClickHouse and by boto3"""

    def __init__(self, conf: dict):
        self.bucket = conf["s3_bucket"]
        self.prefix = conf["s3_prefix"].strip("/")
        self.key_id = conf["s3_access_key_id"]
        self.secret = conf["s3_secret_access_key"]
        endpoint = conf["s3_endpoint"].rstrip("/")
        # ClickHouse may reach the store under another name (e.g. in tests)
        ch_endpoint = conf.get("clickhouse_s3_endpoint", endpoint).rstrip("/")
        self.ch_base = f"{ch_endpoint}/{self.bucket}"
        botoconf = dict(s3={"addressing_style": "path"})
        try:
            # boto3 >= 1.36 adds checksums some S3-compatible stores reject
            cfg = BotoConfig(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
                **botoconf,
            )
        except TypeError:
            cfg = BotoConfig(**botoconf)
        self.s3 = boto3.client(
            "s3",
            endpoint_url=endpoint,
            region_name=conf.get("s3_region", "us-east-1"),
            aws_access_key_id=self.key_id,
            aws_secret_access_key=self.secret,
            config=cfg,
        )

    def table_prefix(self, database: str, table: str) -> str:
        return f"{self.prefix}/{database}/{table}/"

    def ch_s3(self, key: str) -> str:
        """S3(...) argument for BACKUP/RESTORE and the s3 function.

        No credentials: ClickHouse takes them from the <s3> endpoint in its
        own config. An incremental backup records its base_backup argument
        verbatim in its .backup file, so keys passed here would end up in
        the bucket in plain text."""
        return sql_str(f"{self.ch_base}/{key}")

    def subdirs(self, prefix: str) -> list:
        """Names of the "directories" directly below prefix"""
        names = []
        pager = self.s3.get_paginator("list_objects_v2")
        for page in pager.paginate(Bucket=self.bucket, Prefix=prefix, Delimiter="/"):
            for p in page.get("CommonPrefixes", []):
                names.append(p["Prefix"][len(prefix) :].rstrip("/"))
            for o in page.get("Contents", []):
                names.append(o["Key"][len(prefix) :])
        return names

    def exists(self, key: str) -> bool:
        try:
            self.s3.head_object(Bucket=self.bucket, Key=key)
            return True
        except self.s3.exceptions.ClientError as e:
            if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
                return False
            raise

    def put_empty(self, key: str) -> None:
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=b"")

    def delete_key(self, key: str) -> None:
        self.s3.delete_object(Bucket=self.bucket, Key=key)

    def delete_prefix(self, prefix: str) -> int:
        assert prefix.endswith("/") and prefix.startswith(self.prefix + "/")
        n = 0
        pager = self.s3.get_paginator("list_objects_v2")
        for page in pager.paginate(Bucket=self.bucket, Prefix=prefix):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                self.s3.delete_objects(Bucket=self.bucket, Delete={"Objects": keys, "Quiet": True})
                n += len(keys)
        return n

    def chains(self, database: str, table: str) -> dict:
        """{chain: {"backups": {backup: complete}, "keep": [labels]}}"""
        tprefix = self.table_prefix(database, table)
        out = {}
        for chain in self.subdirs(tprefix):
            if not chain:
                continue
            entry = {"backups": {}, "keep": []}
            for name in self.subdirs(f"{tprefix}{chain}/"):
                if name.startswith("KEEP-"):
                    entry["keep"].append(name[len("KEEP-") :])
                elif name:
                    marker = f"{tprefix}{chain}/{name}/.backup"
                    entry["backups"][name] = self.exists(marker)
            out[chain] = entry
        return out


def write_atomically(path: str, text: str) -> None:
    """node_exporter must never read a half-written file"""
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def label_value(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class Metrics:
    """Backup results for Prometheus, as a node_exporter textfile. The job's
    name goes in a "backup" label: the scrape already sets "job".

    The latest result of every table is kept in a JSON state file, so a run
    that backs up some tables doesn't drop the others' metrics."""

    GAUGES = [
        ("last_success_timestamp_seconds", "last_success",
         "When the table's last successful backup finished"),
        ("last_attempt_timestamp_seconds", "last_attempt",
         "When the table's last backup attempt finished"),
        ("last_attempt_failed", "last_failed",
         "1 if the table's last backup attempt failed"),
        ("last_duration_seconds", "duration",
         "How long the table's last successful backup took"),
        ("last_size_bytes", "total_size",
         "Size of the table's last successful backup, as system.backups reports it"),
        ("last_files", "num_files",
         "Files in the table's last successful backup"),
    ]

    RUN_GAUGES = [
        ("last_run_finished_timestamp_seconds", "finished", "When the job's last run finished"),
        ("last_run_duration_seconds", "duration", "How long the job's last run took"),
        ("last_run_tables", "tables", "Tables the job's last run backed up"),
        ("last_run_full_backups", "fulls", "Tables the job's last run backed up in full"),
        ("last_run_failed_tables", "failed", "Tables whose backup failed in the job's last run"),
    ]

    def __init__(self, metrics_file: str = "", state_file: str = ""):
        self.metrics_file = metrics_file
        self.state_file = state_file
        self.state = {"tables": {}, "running": {}}
        if state_file and os.path.exists(state_file):
            with open(state_file) as f:
                self.state = json.load(f)
        self.state.setdefault("runs", {})
        self.state.setdefault("running_since", {})

    def table_result(self, job: str, table: str, ok: bool, st: dict = None, duration_s: float = 0) -> None:
        entry = self.state["tables"].setdefault(f"{job}/{table}", {"job": job, "table": table})
        now = time.time()
        entry["last_attempt"] = now
        entry["last_failed"] = 0 if ok else 1
        if ok:
            entry["last_success"] = now
            entry["duration"] = round(duration_s, 1)
            entry["total_size"] = int(st.get("total_size", 0))
            entry["num_files"] = int(st.get("num_files", 0))
        self.save()

    def job_running(self, job: str, running: bool) -> None:
        self.state["running"][job] = 1 if running else 0
        self.state["running_since"][job] = time.time() if running else 0
        self.save()

    def job_failed(self, job: str) -> None:
        """The job couldn't start: its tables' last attempts failed"""
        for entry in self.state["tables"].values():
            if entry["job"] == job:
                entry["last_attempt"] = time.time()
                entry["last_failed"] = 1
        self.save()

    def run_result(self, job: str, duration_s: float, tables: int, fulls: int, failed: int) -> None:
        self.state["runs"][job] = {
            "finished": time.time(), "duration": round(duration_s, 1),
            "tables": tables, "fulls": fulls, "failed": failed,
        }
        self.save()

    def render(self) -> str:
        p = "ooni_clickhouse_backup_"
        lines = [
            f"# HELP {p}running 1 while the job is backing up tables",
            f"# TYPE {p}running gauge",
        ]
        for job, v in sorted(self.state["running"].items()):
            lines.append(f'{p}running{{backup="{label_value(job)}"}} {v}')
        lines += [
            f"# HELP {p}running_since_timestamp_seconds When the job's current run started, 0 if none",
            f"# TYPE {p}running_since_timestamp_seconds gauge",
        ]
        for job, v in sorted(self.state["running_since"].items()):
            lines.append(f'{p}running_since_timestamp_seconds{{backup="{label_value(job)}"}} {v}')
        for name, field, help_ in self.RUN_GAUGES:
            lines += [f"# HELP {p}{name} {help_}", f"# TYPE {p}{name} gauge"]
            for job, run in sorted(self.state["runs"].items()):
                lines.append(f'{p}{name}{{backup="{label_value(job)}"}} {run[field]}')
        for name, field, help_ in self.GAUGES:
            lines += [f"# HELP {p}{name} {help_}", f"# TYPE {p}{name} gauge"]
            for entry in sorted(self.state["tables"].values(), key=lambda e: (e["job"], e["table"])):
                if field in entry:
                    labels = f'backup="{label_value(entry["job"])}",table="{label_value(entry["table"])}"'
                    lines.append(f"{p}{name}{{{labels}}} {entry[field]}")
        return "\n".join(lines) + "\n"

    def save(self) -> None:
        if self.state_file:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            write_atomically(self.state_file, json.dumps(self.state, indent=1))
        if self.metrics_file:
            write_atomically(self.metrics_file, self.render())


def complete_chains(chains: dict) -> list:
    """Chains holding at least one complete backup, oldest first"""
    return sorted(c for c, e in chains.items() if any(e["backups"].values()))


def latest_backup(chains: dict):
    """(chain, backup) of the newest complete backup, or (None, None)"""
    done = complete_chains(chains)
    if not done:
        return None, None
    chain = done[-1]
    backups = sorted(b for b, ok in chains[chain]["backups"].items() if ok)
    return chain, backups[-1]


class BackupJob:
    def __init__(self, conf: dict, metrics: Metrics = None):
        self.conf = conf
        self.name = conf.get("name", "default")
        self.metrics = metrics or Metrics()
        self.db = conf.get("database", "ooni")
        self.ch = ClickHouse(
            conf.get("clickhouse_url", "http://127.0.0.1:8123/"),
            conf.get("clickhouse_user", "default"),
            conf.get("clickhouse_password", ""),
        )
        self.store = Store(conf)
        self.keep_chains = max(1, int(conf.get("keep_chains", 1)))
        # fnmatch patterns; an empty include list means every table
        self.include = conf.get("include_tables", [])
        self.exclude = conf.get("exclude_tables", [])
        self.poll_s = float(conf.get("poll_interval_seconds", 30))
        self.clickhouse_wait_s = float(conf.get("clickhouse_wait_seconds", 600))
        # Query settings for the uploads, e.g. R2 needs every part of a
        # multipart upload but the last to be the same size
        self.settings = {k: str(v) for k, v in conf.get("s3_settings", {}).items()}
        bw = int(conf.get("max_backup_bandwidth", 0))
        if bw:
            # A query setting, not a BACKUP setting: 24.8 rejects it inside
            # BACKUP ... SETTINGS. Against MinIO in testing, the throughput
            # was about a third of this value.
            self.settings["max_backup_bandwidth"] = str(bw)

    def tables(self, only: list) -> tuple:
        """([(name, engine)] to back up, smallest first; [missing names])"""
        rows = self.ch.rows(
            f"""
            SELECT t.name AS name, t.engine AS engine,
                   coalesce(p.bytes, 0) AS bytes
            FROM system.tables AS t
            LEFT JOIN (
                SELECT table, sum(bytes_on_disk) AS bytes
                FROM system.parts
                WHERE active AND database = {sql_str(self.db)}
                GROUP BY table
            ) AS p ON p.table = t.name
            WHERE t.database = {sql_str(self.db)} AND NOT t.is_temporary
            ORDER BY bytes, name
            """
        )
        out = []
        for r in rows:
            name, engine = r["name"], r["engine"]
            if only and name not in only:
                continue
            if name.startswith(".inner"):
                continue  # backed up together with its materialized view
            if not self.includes(name):
                continue  # another job's table
            if self.excludes(name):
                log.info(f"{self.name}: {name}: excluded")
                continue
            if not SAFE_NAME.match(name):
                log.error(f"{name}: unsupported characters in table name, skipping")
                continue
            out.append((name, engine))
        # Tables asked for with --table that are this job's but don't exist
        missing = sorted(
            n for n in set(only) - {n for n, _ in out} if self.includes(n) and not self.excludes(n)
        )
        for name in missing:
            log.error(f"{self.name}: {name}: not found")
        return out, missing

    def includes(self, table: str) -> bool:
        return not self.include or any(fnmatch.fnmatchcase(table, p) for p in self.include)

    def excludes(self, table: str) -> bool:
        return any(fnmatch.fnmatchcase(table, p) for p in self.exclude)

    def running_backups(self) -> list:
        """Backups still running server-side, e.g. from a killed run"""
        rows = self.ch.rows(
            "SELECT id, name FROM system.backups WHERE status = 'CREATING_BACKUP'"
        )
        return [r for r in rows if self.store.ch_base in r["name"]]

    def wait_for_clickhouse(self) -> None:
        """At boot a missed run starts before ClickHouse accepts queries"""
        t0 = time.monotonic()
        while True:
            try:
                self.ch.query("SELECT 1", timeout=30)
                return
            except (OSError, RuntimeError) as e:
                if time.monotonic() - t0 >= self.clickhouse_wait_s:
                    raise RuntimeError(f"ClickHouse not answering after {self.clickhouse_wait_s:.0f}s: {e}")
                log.info(f"waiting for ClickHouse: {e}")
                time.sleep(10)

    def wait(self, op_id: str, what: str) -> dict:
        t0 = time.monotonic()
        last_log = t0
        failing_since = None
        while True:
            # A backup can run for days: retry a failed poll for a while
            # rather than give up on a BACKUP that is still running
            try:
                rows = self.ch.rows(
                    f"""
                    SELECT status, error, num_files, total_size, uncompressed_size
                    FROM system.backups WHERE id = {sql_str(op_id)}
                    """
                )
                failing_since = None
            except (OSError, RuntimeError) as e:
                failing_since = failing_since or time.monotonic()
                if time.monotonic() - failing_since > 600:
                    raise
                log.warning(f"{what}: polling failed, retrying: {e}")
                time.sleep(self.poll_s)
                continue
            if not rows:
                raise RuntimeError(f"{what}: gone from system.backups (server restart?)")
            st = rows[0]
            if st["status"] == "BACKUP_CREATED":
                return st
            if st["status"] != "CREATING_BACKUP":
                raise RuntimeError(f"{what}: {st['status']}: {st['error']}")
            now = time.monotonic()
            if now - last_log >= 1800:
                log.info(f"{what}: still running after {(now - t0) / 3600:.1f}h")
                last_log = now
            time.sleep(self.poll_s)

    def cleanup_incomplete(self, table: str, chains: dict) -> None:
        tprefix = self.store.table_prefix(self.db, table)
        for chain, entry in chains.items():
            if not any(entry["backups"].values()) and not entry["keep"]:
                n = self.store.delete_prefix(f"{tprefix}{chain}/")
                log.info(f"{table}: removed incomplete chain {chain} ({n} objects)")
                continue
            for backup, ok in entry["backups"].items():
                if not ok:
                    n = self.store.delete_prefix(f"{tprefix}{chain}/{backup}/")
                    log.info(f"{table}: removed incomplete backup {chain}/{backup} ({n} objects)")

    def prune(self, table: str) -> None:
        """Keep the newest keep_chains complete chains plus pinned ones"""
        chains = self.store.chains(self.db, table)
        done = complete_chains(chains)
        tprefix = self.store.table_prefix(self.db, table)
        for chain in done[: -self.keep_chains]:
            if chains[chain]["keep"]:
                continue
            n = self.store.delete_prefix(f"{tprefix}{chain}/")
            log.info(f"{table}: pruned chain {chain} ({n} objects)")

    def backup_table(self, table: str, engine: str, force_full: bool, keep: str) -> bool:
        """Back up one table; True if that was a full backup"""
        chains = self.store.chains(self.db, table)
        self.cleanup_incomplete(table, chains)
        chains = self.store.chains(self.db, table)
        base_chain, base = latest_backup(chains)

        now = utcnow()
        export = engine in EXPORT_ENGINES
        full = (
            force_full
            or base is None
            or export  # tiny tables: a fresh full backup every run
            or parse_ts(base_chain).strftime("%Y%m") != now.strftime("%Y%m")
        )
        chain = ts(now) if full else base_chain
        name = ts(now)
        key = f"{self.store.table_prefix(self.db, table)}{chain}/{name}"
        kind = "full" if full else f"incremental on {base_chain}/{base}"
        what = f"{table}: {chain}/{name} ({kind})"

        if export:
            log.info(f"{table}: exporting {engine} rows")
            self.ch.query(
                f"""
                INSERT INTO FUNCTION s3({self.store.ch_s3(key + "/data.native.zst")}, 'Native')
                SELECT * FROM `{self.db}`.`{table}`
                """,
                timeout=3600,
            )

        sql = f"BACKUP TABLE `{self.db}`.`{table}` TO S3({self.store.ch_s3(key)})"
        if not full:
            base_key = f"{self.store.table_prefix(self.db, table)}{base_chain}/{base}"
            sql += f" SETTINGS base_backup = S3({self.store.ch_s3(base_key)})"
        sql += " ASYNC"

        log.info(f"{what}: starting")
        t0 = time.monotonic()
        out = self.ch.query(sql + "\nFORMAT JSONEachRow", settings=self.settings)
        op_id = json.loads(out.splitlines()[0])["id"]
        st = self.wait(op_id, what)
        secs = time.monotonic() - t0
        log.info(
            f"{what}: done in {secs / 60:.1f} min, {st['num_files']} files, "
            f"{size(int(st['uncompressed_size']))} new data"
        )
        self.metrics.table_result(self.name, table, True, st, secs)

        if keep:
            self.store.put_empty(f"{self.store.table_prefix(self.db, table)}{chain}/KEEP-{keep}")
            log.info(f"{table}: chain {chain} pinned as {keep}")
        self.prune(table)
        return full

    def run(self, only: list, force_full: bool, keep: str) -> int:
        try:
            self.wait_for_clickhouse()
            running = self.running_backups()
            if running:
                for r in running:
                    log.error(f"backup {r['id']} is still running on the server")
                raise RuntimeError("not starting: wait for it to finish, or for the server to drop it")
            tables, failed = self.tables(only)
        except Exception as e:
            log.error(f"{self.name}: could not start: {e}")
            self.metrics.job_failed(self.name)
            return 1

        t0, done, fulls = time.monotonic(), 0, 0
        self.metrics.job_running(self.name, True)
        try:
            for table, engine in tables:
                try:
                    fulls += self.backup_table(table, engine, force_full, keep)
                    done += 1
                except Exception as e:
                    log.error(f"{self.name}: {table}: backup failed: {e}")
                    self.metrics.table_result(self.name, table, False)
                    failed.append(table)
        finally:
            self.metrics.job_running(self.name, False)
        self.metrics.run_result(self.name, time.monotonic() - t0, done, fulls, len(failed))

        if failed:
            log.error(f"{self.name}: failed tables: {', '.join(failed)}")
            return 1
        log.info(f"{self.name}: all tables backed up")
        return 0

    def list(self, only: list) -> int:
        # The listing is the command's output, so it goes to stdout with
        # print(), to be read or piped (e.g. the latest: URL into a RESTORE);
        # log is for what run and release report, to stderr and the journal.
        tables = only or sorted(
            n for n in self.store.subdirs(f"{self.store.prefix}/{self.db}/") if n
        )
        for table in tables:
            chains = self.store.chains(self.db, table)
            for chain in sorted(chains):
                entry = chains[chain]
                keep = f"  KEEP: {', '.join(entry['keep'])}" if entry["keep"] else ""
                print(f"{table}/{chain}{keep}")
                for backup, ok in sorted(entry["backups"].items()):
                    status = "" if ok else "  (incomplete)"
                    print(f"    {backup}{status}")
            chain, backup = latest_backup(chains)
            if backup:
                key = f"{self.store.table_prefix(self.db, table)}{chain}/{backup}"
                print(f"  latest: {self.store.ch_base}/{key}")
        return 0

    def release(self, label: str) -> int:
        n = 0
        for table in self.store.subdirs(f"{self.store.prefix}/{self.db}/"):
            if not table:
                continue
            for chain, entry in self.store.chains(self.db, table).items():
                if label in entry["keep"]:
                    tprefix = self.store.table_prefix(self.db, table)
                    self.store.delete_key(f"{tprefix}{chain}/KEEP-{label}")
                    n += 1
        log.info(f"released {n} chain(s) pinned as {label}; the next run prunes them")
        return 0


def jobs_for_tables(jobs: list, tables: list) -> tuple:
    """(the jobs that back up one of tables, the tables no job backs up)"""
    owns = lambda j, t: j.includes(t) and not j.excludes(t)
    orphans = [t for t in tables if not any(owns(j, t) for j in jobs)]
    return [j for j in jobs if any(owns(j, t) for t in tables)], orphans


def job_confs(conf: dict, names: list) -> list:
    """Each job's config: the top-level keys, overridden by the job's own.

    A config without "jobs" is one job named "default". A job's
    exclude_tables add to the top-level ones."""
    common = {k: v for k, v in conf.items() if k != "jobs"}
    out = []
    for job in conf.get("jobs") or [{"name": "default"}]:
        merged = {**common, **job}
        merged["exclude_tables"] = common.get("exclude_tables", []) + job.get("exclude_tables", [])
        if not names or merged["name"] in names:
            out.append(merged)
    unknown = set(names) - {j["name"] for j in out}
    if unknown:
        raise SystemExit(f"unknown job(s): {', '.join(sorted(unknown))}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("run", help="back up every table")
    p.add_argument("--full", action="store_true", help="start new chains")
    p.add_argument("--table", action="append", default=[], help="only this table (repeatable)")
    p.add_argument("--keep", help="pin the chains used by this run under LABEL")
    p = sub.add_parser("list", help="show backups in the bucket")
    p.add_argument("--table", action="append", default=[])
    p = sub.add_parser("release", help="unpin chains pinned under LABEL")
    p.add_argument("label")
    for p in sub.choices.values():
        p.add_argument("--job", action="append", default=[], help="only this job (repeatable)")
    args = ap.parse_args()

    logging.basicConfig(
        stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    log.setLevel(logging.INFO)

    for label in [getattr(args, "keep", None), getattr(args, "label", None)]:
        if label and not SAFE_NAME.match(label.replace(".", "_").replace("-", "_")):
            ap.error(f"invalid label: {label}")

    with open(args.config) as f:
        conf = json.load(f)
    metrics = Metrics(conf.get("metrics_file", ""), conf.get("state_file", ""))
    jobs = [BackupJob(j, metrics) for j in job_confs(conf, args.job)]

    if args.command == "list":
        for job in jobs:
            job.list(args.table)
        return 0

    if args.command == "run" and args.table:
        # only these tables' jobs: the others would run with no tables, and report that
        jobs, orphans = jobs_for_tables(jobs, args.table)
        if orphans:
            ap.error(f"no job backs up: {', '.join(orphans)}")

    # Exit cleanly on SIGTERM; a BACKUP already sent keeps running
    # server-side, and the next run waits for it (see running_backups).
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    lock_path = conf.get("lock_file", "/run/lock/ooni-clickhouse-backup.lock")
    with open(lock_path, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log.error(f"another instance holds {lock_path}")
            return 1
        rc = 0
        for job in jobs:
            if args.command == "run":
                # A failed job doesn't stop the next one
                rc |= job.run(args.table, args.full, args.keep)
            else:
                rc |= job.release(args.label)
        return rc


if __name__ == "__main__":
    sys.exit(main())
