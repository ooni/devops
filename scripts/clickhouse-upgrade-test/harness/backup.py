"""
Backup/restore checks: do ClickHouse's native backups, taken at different
points of the rolling upgrade, restore correctly -- and onto which versions?

Production backs up the `ooni` database from data3 with native BACKUP, one
chain per table (ansible role clickhouse_backup in ooni/devops). This module
does the same against the test cluster, backing up from ch3 to an
S3-compatible store (the `minio` service in docker-compose.backup.yml), and
restores onto `chr`, a standalone node with its own Keeper, recreated on
whichever version a check asks for.

The questions it answers, one CI step each (see
.github/workflows/clickhouse_upgrade_test.yml):

  - a full backup taken on 24.8 restores on 26.8 (old backup, new server)
  - an incremental chain whose links were taken on 24.8, 25.3 and 26.8
    restores on 26.8
  - a backup taken on 25.3, right before 25.8 changes the on-disk part
    format, restores on 25.3 -- the rollback path, since a backup taken
    after that change can't be restored on an older server (a 24.8 server
    segfaulted restoring a 26.8 backup when this was tried by hand)

Each backup records a per-table row count + content checksum taken on ch3
at backup time, and each restore check compares the restored tables
against it -- so a check covers every table and every row in the backup,
probe rows and DDL-marker columns included, not just the seed data
validate.TABLES covers.

Like production:
  - BACKUP only stores the CREATE statement of EmbeddedRocksDB (and Join)
    tables, so their rows are exported to <backup>/data.native.zst first
    and loaded back after RESTORE. fingerprints_dns/fingerprints_http get a
    few rows on ch3 before the first backup so this path is exercised.
  - Queries never carry S3 keys: ClickHouse takes them from
    config/backup/s3.xml. An incremental backup stores its base_backup
    argument in plain text in its .backup file, and each backup step checks
    no .backup file contains the secret.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from . import compose, validate
from .ch_http import ChNode, ClickHouseError

PROJECT_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_DIR / "results"
BACKUPS_PATH = RESULTS_DIR / "backups.json"
COMPOSE_FILES = ["docker-compose.yml", "docker-compose.backup.yml"]

# How ClickHouse reaches the bucket; credentials come from config/backup/s3.xml
BUCKET_URL = "http://minio:9000/backups"
MINIO_SECRET = "minioadmin"

BACKUP_NODE = ChNode(name="ch3", http_port=8125)  # production backs up from data3
RESTORE_NODE = ChNode(name="chr", http_port=8126)

EXPORT_ENGINES = {"EmbeddedRocksDB", "Join"}
VIEW_ENGINES = {"MaterializedView", "View"}

FINGERPRINT_ROWS = [
    ("fp_backup_test_1", "nat", "full", "example.org"),
    ("fp_backup_test_2", "isp", "contains", "blocked"),
]


def _load_backups() -> dict:
    if BACKUPS_PATH.exists():
        return json.loads(BACKUPS_PATH.read_text())
    return {}


def _save_backups(backups: dict) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    BACKUPS_PATH.write_text(json.dumps(backups, indent=2))


def _minio(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", "ooni-minio", "sh", "-c",
         f"mc alias set local http://localhost:9000 minioadmin {MINIO_SECRET} >/dev/null && {cmd}"],
        capture_output=True,
        text=True,
    )


def ensure_minio(log=print) -> None:
    compose.up(services=["minio"], files=COMPOSE_FILES)
    proc = None
    for _ in range(60):
        proc = _minio("mc mb --ignore-existing local/backups")
        if proc.returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError(f"minio did not come up: {proc.stderr if proc else ''}")


def _tables(node: ChNode) -> list[dict]:
    """Every table in `ooni`, views last (they need their source tables
    restored first). Materialized views' .inner tables are backed up with
    their view."""
    return node.query_rows(
        "SELECT name, engine FROM system.tables "
        "WHERE database = 'ooni' AND NOT is_temporary AND name NOT LIKE '.inner%' "
        "ORDER BY engine IN ('MaterializedView', 'View'), name"
    )


def _snapshot(node: ChNode, tables: list[str]) -> dict:
    """Row count + content checksum of every column that's stored (only
    ALIAS columns skipped), per table -- same hashing idiom as
    validate.table_snapshot(), see the comment there for why it's
    cityHash64(toString(tuple(...)))."""
    out = {}
    for t in tables:
        cols = [
            r["name"]
            for r in node.query_rows(
                f"SELECT name FROM system.columns WHERE database = 'ooni' AND table = '{t}' "
                f"AND default_kind != 'ALIAS' ORDER BY name"
            )
        ]
        col_list = ", ".join(f"`{c}`" for c in cols)
        row = node.query_rows(
            f"SELECT count() AS cnt, sum(cityHash64(toString(tuple({col_list})))) AS checksum FROM ooni.`{t}`",
            timeout=120,
        )[0]
        out[t] = {"row_count": int(row["cnt"]), "checksum": str(row["checksum"])}
    return out


def _wait(node: ChNode, op_id: str, done: str, timeout: float = 900.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = node.query_rows(f"SELECT status, error FROM system.backups WHERE id = '{op_id}'")
        if not rows:
            raise RuntimeError(f"{op_id} gone from system.backups")
        status, error = rows[0]["status"], rows[0]["error"]
        if status == done:
            return
        if not status.startswith(("CREATING", "RESTORING")):
            raise RuntimeError(f"{status}: {error}")
        time.sleep(1)
    raise RuntimeError(f"{op_id} still running after {timeout}s")


def _run_async(node: ChNode, sql: str, done: str) -> None:
    body = node.query(sql + " ASYNC FORMAT JSONEachRow", timeout=120, fmt=None)
    op_id = json.loads(body.splitlines()[0])["id"]
    _wait(node, op_id, done)


def _seed_fingerprints(node: ChNode, log=print) -> None:
    for table in ("fingerprints_dns", "fingerprints_http"):
        if int(node.query_scalar(f"SELECT count() FROM ooni.{table}")) > 0:
            continue
        values = ", ".join(
            f"('{name}', '{scope}', '', '', '{ptype}', '{pattern}', 0, '', 'backup-test', '', '')"
            for name, scope, ptype, pattern in FINGERPRINT_ROWS
        )
        node.execute(f"INSERT INTO ooni.{table} VALUES {values}")
        log(f"[backup] seeded {len(FINGERPRINT_ROWS)} rows into ooni.{table} on {node.name}")


def backup_step(name: str, base: str | None, label: str, log=print) -> dict:
    """BACKUP every table in `ooni` from ch3 to <bucket>/<name>/<table>,
    incremental on backup `base` where `base` has the table."""
    result = {"label": label, "backup_name": name, "base": base, "ok": False}
    try:
        ensure_minio(log=log)
        node = BACKUP_NODE
        backups = _load_backups()
        if base and base not in backups:
            raise RuntimeError(f"base backup {base!r} wasn't recorded -- did its step fail?")
        base_tables = backups[base]["tables"] if base else {}

        _seed_fingerprints(node, log=log)
        tables = _tables(node)
        record = {
            "version": node.version(),
            "base": base,
            "tables": {},
            "snapshot": _snapshot(node, [t["name"] for t in tables]),
        }
        result["version"] = record["version"]

        incremental = []
        for t in tables:
            table, engine = t["name"], t["engine"]
            url = f"{BUCKET_URL}/{name}/{table}"
            export = engine in EXPORT_ENGINES
            if export:
                node.execute(
                    f"INSERT INTO FUNCTION s3('{url}/data.native.zst', 'Native') SELECT * FROM ooni.`{table}`",
                    timeout=300,
                )
            sql = f"BACKUP TABLE ooni.`{table}` TO S3('{url}')"
            if table in base_tables and not export:
                sql += f" SETTINGS base_backup = S3('{base_tables[table]['url']}')"
                incremental.append(table)
            _run_async(node, sql, "BACKUP_CREATED")
            record["tables"][table] = {"engine": engine, "url": url, "export": export}
            log(f"[backup] {name}: {table} ({'incremental on ' + base if table in incremental else 'full'})")

        leaked = []
        for table in record["tables"]:
            proc = _minio(f"mc cat local/backups/{name}/{table}/.backup")
            if proc.returncode != 0:
                raise RuntimeError(f"can't read {name}/{table}/.backup: {proc.stderr}")
            if MINIO_SECRET in proc.stdout:
                leaked.append(table)

        backups[name] = record
        _save_backups(backups)
        result.update(
            ok=not leaked,
            tables=len(record["tables"]),
            incremental_tables=incremental,
            credentials_in_backup=leaked,
        )
        if leaked:
            result["error"] = f".backup files contain the bucket secret: {leaked}"
    except Exception as e:
        result["error"] = str(e)
    log(f"[backup] {label}: {'OK' if result['ok'] else 'FAILED: ' + str(result.get('error'))}")
    return result


def restore_check_step(name: str, version: str, label: str, log=print) -> dict:
    """Restore backup `name` onto a fresh chr running `version`, and compare
    every table against the snapshot taken when the backup was made."""
    result = {"label": label, "restore_of": name, "restore_version": version, "ok": False, "errors": {}, "mismatches": {}}
    try:
        backups = _load_backups()
        if name not in backups:
            raise RuntimeError(f"backup {name!r} wasn't recorded -- did its step fail?")
        record = backups[name]
        result["backup_version"] = record["version"]

        # Fresh node: --renew-anon-volumes drops the previous check's data
        compose._run(
            ["up", "-d", "--force-recreate", "--renew-anon-volumes", "--no-deps", "chr"],
            env={"CHR_IMAGE": version},
            files=COMPOSE_FILES,
        )
        node = RESTORE_NODE
        if not validate.wait_until_up(node, timeout=120):
            raise RuntimeError(f"chr didn't come up on {version}")
        result["actual_version"] = node.version()
        node.execute("CREATE DATABASE IF NOT EXISTS ooni")

        for table, info in record["tables"].items():
            try:
                _run_async(node, f"RESTORE TABLE ooni.`{table}` FROM S3('{info['url']}')", "RESTORED")
                if info["export"]:
                    node.execute(
                        f"INSERT INTO ooni.`{table}` SELECT * FROM s3('{info['url']}/data.native.zst', 'Native')",
                        timeout=300,
                    )
            except (ClickHouseError, RuntimeError) as e:
                if not node.ping():
                    raise RuntimeError(f"chr ({version}) went down restoring {table}: {e}") from None
                result["errors"][table] = str(e)

        restored = [t for t in record["tables"] if t not in result["errors"]]
        current = _snapshot(node, restored)
        for table in restored:
            if current[table] != record["snapshot"][table]:
                result["mismatches"][table] = {"backup": record["snapshot"][table], "restored": current[table]}
        result["tables"] = len(record["tables"])
        result["ok"] = not result["errors"] and not result["mismatches"]
    except Exception as e:
        result["error"] = str(e)
    if not result["ok"]:
        result["chr_log_tail"] = compose.logs("chr", tail=80, files=COMPOSE_FILES)
    log(f"[restore] {label}: {'OK' if result['ok'] else 'FAILED'} {result.get('error', '')}")
    return result
