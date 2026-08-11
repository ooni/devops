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


def recent_replication_errors(node: ChNode, since_minutes: int = 30) -> list[dict]:
    """
    Errors ClickHouse itself has logged for replication-related exception
    codes since the upgrade step started. This is what actually shows up
    when nodes run mismatched, incompatible versions (e.g. checksum
    mismatches, unknown part format, protocol errors).
    """
    try:
        return node.query_rows(
            f"""
            SELECT name, value, last_error_message, last_error_time
            FROM system.errors
            WHERE last_error_time > now() - INTERVAL {since_minutes} MINUTE
              AND (
                name LIKE '%REPLICA%' OR
                name LIKE '%CHECKSUM%' OR
                name LIKE '%UNKNOWN_FORMAT%' OR
                name LIKE '%TOO_OLD%' OR
                name LIKE '%NETWORK%' OR
                name LIKE '%UNFINISHED%' OR
                name LIKE '%NOT_ENOUGH_SPACE%' OR
                name LIKE '%CANNOT_READ_ALL_DATA%'
              )
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
