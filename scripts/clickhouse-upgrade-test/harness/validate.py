"""
Cluster health / correctness checks used before, during, and after each
upgrade step.
"""
from __future__ import annotations

import time
import uuid

from .ch_http import ChNode, ClickHouseError

TABLES = ["citizenlab", "fastpath", "analysis_web_measurement", "obs_web"]


def wait_until_up(node: ChNode, timeout: float = 90.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if node.ping():
            return True
        time.sleep(2)
    return False


def wait_all_up(nodes: list[ChNode], timeout: float = 90.0) -> dict[str, bool]:
    return {n.name: wait_until_up(n, timeout=timeout) for n in nodes}


def get_versions(nodes: list[ChNode]) -> dict[str, str | None]:
    out = {}
    for n in nodes:
        try:
            out[n.name] = n.version()
        except Exception:
            out[n.name] = None
    return out


def cluster_replica_count(node: ChNode) -> int:
    """How many replicas does system.clusters see as reachable for oonidata_cluster?"""
    rows = node.query_rows(
        "SELECT count() AS c FROM system.clusters WHERE cluster = 'oonidata_cluster'"
    )
    return int(rows[0]["c"]) if rows else 0


def replicas_readonly_status(node: ChNode) -> list[dict]:
    """Per-table replication state as seen from this node."""
    return node.query_rows(
        "SELECT database, table, is_readonly, is_session_expired, "
        "future_parts, parts_to_check, queue_size, absolute_delay "
        "FROM system.replicas WHERE database = 'ooni'"
    )


def row_counts(node: ChNode) -> dict[str, int | None]:
    out = {}
    for t in TABLES:
        try:
            out[t] = int(node.query_scalar(f"SELECT count() FROM ooni.{t}"))
        except Exception:
            out[t] = None
    return out


def row_counts_all_nodes(nodes: list[ChNode]) -> dict[str, dict[str, int | None]]:
    return {n.name: row_counts(n) for n in nodes}


def counts_converged(counts_by_node: dict[str, dict[str, int | None]]) -> bool:
    """True if every table has the same non-None row count on every node."""
    node_names = list(counts_by_node.keys())
    if not node_names:
        return False
    for t in TABLES:
        values = {counts_by_node[n].get(t) for n in node_names}
        if len(values) != 1 or None in values:
            return False
    return True


def wait_for_convergence(nodes: list[ChNode], timeout: float = 120.0, interval: float = 3.0):
    """Poll row counts on all nodes until they match (replication caught up)."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = row_counts_all_nodes(nodes)
        if counts_converged(last):
            return True, last
        time.sleep(interval)
    return False, last


def probe_write_then_read(write_node: ChNode, read_nodes: list[ChNode], timeout: float = 60.0) -> dict:
    """
    Insert one uniquely identifiable row on `write_node`, then poll every
    node in `read_nodes` until the row shows up (or timeout). This is the
    most direct evidence of whether replication is actually working end to
    end during a mixed-version state, independent of aggregate row counts.
    """
    probe_id = f"probe-{uuid.uuid4().hex[:12]}"
    result = {"probe_id": probe_id, "write_node": write_node.name, "write_ok": False, "read_back": {}}
    try:
        write_node.execute(
            "INSERT INTO ooni.citizenlab (domain, url, cc, category_code) VALUES "
            f"('{probe_id}.example.test', 'https://{probe_id}.example.test/', 'ZZ', 'PROBE')"
        )
        result["write_ok"] = True
    except ClickHouseError as e:
        result["write_error"] = str(e)
        return result

    deadline = time.time() + timeout
    pending = {n.name: n for n in read_nodes}
    while pending and time.time() < deadline:
        for name in list(pending):
            n = pending[name]
            try:
                c = n.query_scalar(
                    f"SELECT count() FROM ooni.citizenlab WHERE domain = '{probe_id}.example.test'"
                )
                if c and int(c) > 0:
                    result["read_back"][name] = True
                    del pending[name]
            except ClickHouseError:
                pass
        if pending:
            time.sleep(2)
    for name in pending:
        result["read_back"][name] = False
    result["fully_replicated"] = len(pending) == 0
    return result


# --- error-code classification -------------------------------------------
#
# Forcibly killing/recreating a peer container -- exactly what
# `docker compose up --no-deps --force-recreate` does to simulate an
# in-place node upgrade -- severs any in-flight connections the other two
# nodes had open to it. ClickHouse reliably logs NETWORK / CANNOT_READ_ALL_
# DATA / REPLICA-session-class errors on the *surviving* nodes when that
# happens, even when the container comes back on the exact same version.
# That's a side effect of the bounce itself, not evidence of a version
# incompatibility -- and it self-heals, which is exactly what the
# write-then-read-back probe and row-count convergence checks (run right
# after) are there to confirm.
#
# Genuine cross-version incompatibility shows up differently: checksum
# mismatches, an unsupported/unknown data-part format version, "too old
# software version" errors, corrupted data. Those only fire for an actual
# data-format/version reason, never from a plain socket bounce, so they're
# treated as hard failures that gate a hop.
TRANSIENT_ERROR_NAME_PATTERNS = [
    "%NETWORK%",
    "%CANNOT_READ_ALL_DATA%",
    "%UNFINISHED%",
    "%REPLICA%",
    "%SOCKET%",
    "%CONNECTION%",
    "%TIMEOUT%",
    "%ALL_CONNECTION_TRIES_FAILED%",
]
HARD_ERROR_NAME_PATTERNS = [
    "%CHECKSUM%",
    "%UNKNOWN_FORMAT%",
    "%TOO_OLD%",
    "%NOT_ENOUGH_SPACE%",
    "%CORRUPTED%",
    "%INCOMPATIBLE%",
]
_ALL_WATCHED_PATTERNS = TRANSIENT_ERROR_NAME_PATTERNS + HARD_ERROR_NAME_PATTERNS


def _classify(name: str) -> str:
    for p in TRANSIENT_ERROR_NAME_PATTERNS:
        if p.strip("%") in name:
            return "transient"
    return "hard"


def error_snapshot(node: ChNode) -> dict[str, dict]:
    """
    Current cumulative system.errors rows for the watched error codes, keyed
    by name. `value` is a monotonic counter since server start -- meaningless
    read in isolation, but diffing two snapshots taken before/after a step
    (see new_errors_since()) tells you exactly how many *new* occurrences
    happened during that specific step. A `last_error_time > now() -
    INTERVAL n MINUTE` window can't do that reliably across a multi-step CI
    job: an error logged during hop 1 is still "recent" by the time hop 4
    runs, so it keeps getting re-reported as if it just happened.
    """
    like_clauses = " OR ".join(f"name LIKE '{p}'" for p in _ALL_WATCHED_PATTERNS)
    try:
        rows = node.query_rows(
            f"SELECT name, value, last_error_message, last_error_time "
            f"FROM system.errors WHERE {like_clauses}"
        )
    except ClickHouseError:
        return {}
    return {r["name"]: r for r in rows}


def new_errors_since(node: ChNode, baseline: dict[str, dict]) -> list[dict]:
    """
    Diff a fresh error snapshot against `baseline` (captured before the step
    started). Returns only error codes whose counter increased during this
    step, each tagged 'transient' or 'hard' per the pattern lists above --
    it's this classification, not raw presence of an error, that
    scenarios._hop_ok() gates a hop's pass/fail on.
    """
    current = error_snapshot(node)
    out = []
    for name, row in current.items():
        before_value = int(baseline.get(name, {}).get("value", 0) or 0)
        after_value = int(row.get("value", 0) or 0)
        if after_value > before_value:
            out.append({
                "name": name,
                "value": after_value,
                "new_since_step_start": after_value - before_value,
                "last_error_message": row.get("last_error_message", ""),
                "last_error_time": row.get("last_error_time"),
                "kind": _classify(name),
            })
    return out


def recent_replication_errors(node: ChNode, since_minutes: int = 30) -> list[dict]:
    """
    Standalone (non-diffed) view for ad-hoc health snapshots -- e.g.
    full_health_snapshot() below -- where there's no "before" baseline to
    diff against. NOT used to decide hop pass/fail; see new_errors_since().
    """
    try:
        return node.query_rows(
            f"""
            SELECT name, value, last_error_message, last_error_time
            FROM system.errors
            WHERE last_error_time > now() - INTERVAL {since_minutes} MINUTE
              AND ({" OR ".join(f"name LIKE '{p}'" for p in _ALL_WATCHED_PATTERNS)})
            ORDER BY last_error_time DESC
            """
        )
    except ClickHouseError:
        return []


def replication_queue_problems(node: ChNode) -> list[dict]:
    try:
        return node.query_rows(
            "SELECT database, table, node_name, type, num_tries, last_exception "
            "FROM system.replication_queue WHERE num_tries > 2"
        )
    except ClickHouseError:
        return []


def full_health_snapshot(nodes: list[ChNode]) -> dict:
    return {
        "versions": get_versions(nodes),
        "up": {n.name: n.ping() for n in nodes},
        "row_counts": row_counts_all_nodes(nodes),
        "replicas": {n.name: replicas_readonly_status(n) for n in nodes},
        "errors": {n.name: recent_replication_errors(n) for n in nodes},
        "queue_problems": {n.name: replication_queue_problems(n) for n in nodes},
    }
