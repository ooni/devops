#!/usr/bin/env python3
"""
Generate and maintain weekly data dumps served from datadumps.ooni.io.

Ansible-managed in ooni/devops.git (ansible/roles/datadumps).

Meant to run hourly. Each run reconciles the output directory to the
expected state, so missed or failed runs fix themselves on the next one:

- For each query the expected dumps are the last
  `--keep` weeks. A week is identified by the Monday (UTC) it starts on, and
  a dump for it becomes due once the week is over, at the following Monday
  + `--grace-hours`.
  Example: ccs_domains_anomaly_count-2026_10_26.csv.lz4 covers measurements
  in [2026-10-26 00:00, 2026-11-02 00:00) UTC and is generated on
  2026-11-02 at 03:00 UTC (with the default grace).
- A dump is valid if it is non-empty and its .sha256 file matches it.
  Missing or invalid dumps are regenerated.
- Freshly generated dumps are only published (atomic rename) if ClickHouse
  can read them back and they contain at least one row.
- Files matching the dump pattern but outside the expected set (older than
  `--keep` weeks, non-Monday dates) are deleted.
- <name>-latest.csv.lz4(.sha256) symlinks point to the newest dump.

The .sql files must use the {start:String} and {end:String} query
parameters (UTC, 'YYYY-MM-DD HH:MM:SS') for the half-open interval
[start, end), and must not contain FORMAT/INTO OUTFILE clauses.
"""

import argparse
import datetime as dt
import fcntl
import hashlib
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

log = logging.getLogger("datadumps")

DATE_FMT = "%Y_%m_%d"
EXT = ".csv.lz4"
CH_DT_FMT = "%Y-%m-%d %H:%M:%S"


def dump_name(query: str, monday: dt.date) -> str:
    return f"{query}-{monday.strftime(DATE_FMT)}{EXT}"


def dump_re(query: str) -> re.Pattern:
    return re.compile(
        rf"^{re.escape(query)}-(\d{{4}}_\d{{2}}_\d{{2}}){re.escape(EXT)}(\.sha256)?$"
    )


def expected_mondays(now: dt.datetime, keep: int, grace_hours: int) -> list[dt.date]:
    """Start Mondays of the weeks whose dump should exist at `now`, newest first."""
    today = now.date()
    # Monday that ends the most recent complete week
    week_end = today - dt.timedelta(days=today.weekday())
    due = dt.datetime.combine(week_end, dt.time(), tzinfo=dt.timezone.utc)
    if now < due + dt.timedelta(hours=grace_hours):
        week_end -= dt.timedelta(weeks=1)
    week_start = week_end - dt.timedelta(weeks=1)
    return [week_start - dt.timedelta(weeks=i) for i in range(keep)]


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_valid(dump: Path) -> bool:
    sha_file = dump.with_name(dump.name + ".sha256")
    if not dump.is_file() or dump.is_symlink():
        return False
    if dump.stat().st_size == 0:
        log.warning("%s is empty", dump.name)
        return False
    if not sha_file.is_file():
        log.warning("%s has no checksum file", dump.name)
        return False
    try:
        expected = sha_file.read_text().split()[0]
    except (IndexError, OSError):
        log.warning("%s has an unreadable checksum file", dump.name)
        return False
    if sha256_of(dump) != expected:
        log.warning("%s does not match its checksum", dump.name)
        return False
    return True


def unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def generate(args, query: str, sql: str, monday: dt.date) -> None:
    out_dir: Path = args.output_dir
    name = dump_name(query, monday)
    final = out_dir / name
    final_sha = out_dir / (name + ".sha256")
    # Dot-prefixed temp files keep the real extension (so ClickHouse detects
    # lz4) and are hidden by nginx.
    tmp = out_dir / f".tmp-{name}"
    tmp_sha = out_dir / f".tmp-{name}.sha256"
    unlink(tmp)
    unlink(tmp_sha)

    end = monday + dt.timedelta(weeks=1)
    params = {
        "start": dt.datetime.combine(monday, dt.time()).strftime(CH_DT_FMT),
        "end": dt.datetime.combine(end, dt.time()).strftime(CH_DT_FMT),
    }
    log.info("generating %s for [%s, %s) UTC", name, params["start"], params["end"])

    full_sql = (
        f"{sql}\nINTO OUTFILE '{tmp}' COMPRESSION 'lz4' FORMAT CSVWithNames"
    )
    cmd = [args.clickhouse_client, "--host", args.clickhouse_host, "--query", full_sql]
    cmd += [f"--param_{k}={v}" for k, v in params.items()]
    try:
        subprocess.run(cmd, check=True, timeout=args.query_timeout)

        if not tmp.is_file() or tmp.stat().st_size == 0:
            raise RuntimeError(f"{name}: query produced no output")

        # Read the file back: checks lz4 integrity and that it has rows.
        # An empty result fails here too (ClickHouse can't infer a schema).
        res = subprocess.run(
            [
                args.clickhouse_local,
                "--query",
                f"SELECT count() FROM file('{tmp}', 'CSVWithNames')",
            ],
            capture_output=True,
            text=True,
            timeout=args.query_timeout,
        )
        if res.returncode != 0:
            raise RuntimeError(
                f"{name}: unreadable or empty output: {res.stderr.strip()[:500]}"
            )
        rows = int(res.stdout.strip())
        if rows <= 0:
            raise RuntimeError(f"{name}: query returned no rows")

        tmp_sha.write_text(f"{sha256_of(tmp)}  {name}\n")
        for p in (tmp, tmp_sha):
            p.chmod(0o644)
        # Data first, then checksum: a crash in between leaves a dump without
        # checksum, which is_valid() rejects and the next run regenerates.
        os.replace(tmp, final)
        os.replace(tmp_sha, final_sha)
        log.info("published %s (%d rows, %d bytes)", name, rows, final.stat().st_size)
    finally:
        unlink(tmp)
        unlink(tmp_sha)


def symlink_atomic(target: str, link: Path) -> None:
    tmp = link.with_name(f".tmp-{link.name}")
    unlink(tmp)
    tmp.symlink_to(target)
    os.replace(tmp, link)


def update_latest(out_dir: Path, query: str, mondays: list[dt.date]) -> None:
    link = out_dir / f"{query}-latest{EXT}"
    link_sha = out_dir / f"{query}-latest{EXT}.sha256"
    for monday in mondays:  # newest first
        name = dump_name(query, monday)
        if (out_dir / name).is_file() and (out_dir / (name + ".sha256")).is_file():
            # Relative targets so the links survive moving the directory.
            # Note: the checksum file names the dated file, so verify with
            # `sha256sum -c` against the dated download.
            symlink_atomic(name, link)
            symlink_atomic(name + ".sha256", link_sha)
            return
    unlink(link)
    unlink(link_sha)


def prune(out_dir: Path, query: str, mondays: list[dt.date]) -> None:
    keep = {m.strftime(DATE_FMT) for m in mondays}
    pattern = dump_re(query)
    for p in out_dir.iterdir():
        m = pattern.match(p.name)
        if m and m.group(1) not in keep:
            log.info("deleting %s", p.name)
            unlink(p)


def process_query(args, query: str, sql: str, now: dt.datetime) -> bool:
    mondays = expected_mondays(now, args.keep, args.grace_hours)
    ok = True
    for monday in mondays:
        if is_valid(args.output_dir / dump_name(query, monday)):
            continue
        try:
            generate(args, query, sql, monday)
        except (RuntimeError, subprocess.SubprocessError) as e:
            log.error("failed to generate %s: %s", dump_name(query, monday), e)
            ok = False
        except Exception:
            log.exception("failed to generate %s", dump_name(query, monday))
            ok = False
    prune(args.output_dir, query, mondays)
    update_latest(args.output_dir, query, mondays)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--queries-dir", type=Path, required=True)
    ap.add_argument("--keep", type=int, default=4, help="weeks of dumps to keep")
    ap.add_argument(
        "--grace-hours", type=int, default=3,
        help="hours after Monday 00:00 UTC before the week's dump is due",
    )
    ap.add_argument("--clickhouse-client", default="clickhouse-client")
    ap.add_argument("--clickhouse-local", default="clickhouse-local")
    ap.add_argument("--clickhouse-host", default="localhost")
    ap.add_argument("--query-timeout", type=int, default=3600, help="seconds")
    ap.add_argument(
        "--now", type=dt.datetime.fromisoformat,
        help="override current time (testing), ISO format, UTC assumed",
    )
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    now = args.now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)

    out_dir: Path = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    lock = (out_dir / ".lock").open("w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log.info("another run is in progress, exiting")
        return 0

    for stale in out_dir.glob(".tmp-*"):
        unlink(stale)

    queries = sorted(args.queries_dir.glob("*.sql"))
    if not queries:
        log.error("no queries found in %s", args.queries_dir)
        return 1

    ok = True
    for qfile in queries:
        sql = qfile.read_text().strip().rstrip(";")
        ok &= process_query(args, qfile.stem, sql, now)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
