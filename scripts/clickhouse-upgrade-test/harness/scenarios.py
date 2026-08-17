"""
The two upgrade scenarios.

Both scenarios stand up the same 3-node "oonidata_cluster" clone from
scratch (fresh volumes), load the schema + synthetic seed data, then walk
through a version ladder upgrading exactly one node at a time -- i.e. a real
rolling upgrade, never taking the whole shard down.

* scenario_staged_lts(): walks 24.8.6.70 -> 25.3.14.14 -> 25.8.29.51 ->
  26.3.17.110 -> 26.7.3.19, one LTS hop at a time. Each hop stays within
  ClickHouse's documented ~1 year mixed-version compatibility window.

* scenario_direct_jump(): goes straight from 24.8.6.70 to 26.7.3.19,
  node-by-node. This intentionally puts the cluster in a state ClickHouse's
  own docs say not to run (>1 year version skew between replicas of the same
  shard) so we can observe -- rather than assume -- what actually breaks.
"""
from __future__ import annotations

import time
from pathlib import Path

from . import compose, validate
from .ch_http import ChNode
from .seed_data import build_all_seed_statements
from .versions import BASE_VERSION, DIRECT_JUMP, LATEST_VERSION, LTS_HOPS

SQL_DIR = Path(__file__).resolve().parent.parent / "sql"
NODE_ORDER = ["ch1", "ch2", "ch3"]


def make_nodes() -> list[ChNode]:
    return [
        ChNode("ch1", http_port=8123),
        ChNode("ch2", http_port=8124),
        ChNode("ch3", http_port=8125),
    ]


def fresh_cluster(base_version: str, log=print) -> dict:
    """Tear down any previous state and bring up all 3 nodes pinned to base_version."""
    log(f"[setup] tearing down any previous cluster state...")
    compose.down(volumes=True)
    env = {"CH1_IMAGE": base_version, "CH2_IMAGE": base_version, "CH3_IMAGE": base_version}
    log(f"[setup] starting fresh 3-node cluster at {base_version}...")
    compose.up(env=env, force_recreate=True)
    nodes = make_nodes()
    up = validate.wait_all_up(nodes, timeout=180)
    if not all(up.values()):
        raise RuntimeError(f"cluster did not come up cleanly: {up}\nlogs:\n" + "\n".join(compose.logs(n) for n in NODE_ORDER))
    return env


def _strip_sql_comments(sql: str) -> str:
    """
    Drop full-line `--` comments before splitting on `;`. Doing this on the
    raw text (rather than just filtering post-split fragments) matters
    because a comment block containing punctuation-semicolons (e.g. prose
    like "note: X; also Y") would otherwise fool a naive `text.split(";")`
    into treating the tail of the comment as its own statement.
    """
    kept_lines = [line for line in sql.splitlines() if not line.strip().startswith("--")]
    return "\n".join(kept_lines)


def load_schema_and_seed(log=print) -> None:
    nodes = make_nodes()
    entry = nodes[0]  # ch1 -- schema/seed load happens through one node, ON CLUSTER fans it out
    log("[setup] applying schema (ON CLUSTER oonidata_cluster)...")
    schema_sql = _strip_sql_comments((SQL_DIR / "001_schema.sql").read_text())
    for stmt in [s.strip() for s in schema_sql.split(";") if s.strip()]:
        entry.execute(stmt)

    log("[setup] generating + loading synthetic seed data (see harness/seed_data.py for why it's synthetic)...")
    seed = build_all_seed_statements()
    for table, stmts in seed.items():
        log(f"[setup]   loading {len(stmts)} batch(es) into ooni.{table}...")
        for stmt in stmts:
            entry.execute(stmt, timeout=120)

    log("[setup] waiting for initial replication to converge across all 3 nodes...")
    ok, counts = validate.wait_for_convergence(nodes, timeout=180)
    if not ok:
        raise RuntimeError(f"seed data did not converge across replicas: {counts}")
    log(f"[setup] converged. row counts: {counts}")


def _run_upgrade_step(env: dict, node_name: str, new_version: str, log=print) -> dict:
    nodes = make_nodes()
    other_nodes = [n for n in nodes if n.name != node_name]

    log(f"[upgrade] recreating {node_name} on image {new_version} (others stay up)...")
    env = compose.upgrade_node(node_name, new_version, env)

    node_up = validate.wait_until_up(next(n for n in nodes if n.name == node_name), timeout=180)

    # Feed a write while the cluster is in this (possibly mixed-version) state and
    # confirm it replicates to every other node -- the sharpest signal of whether
    # replication is actually functioning right now.
    write_from = other_nodes[0] if other_nodes else nodes[0]
    probe = validate.probe_write_then_read(write_from, nodes, timeout=90)

    converged, counts = validate.wait_for_convergence(nodes, timeout=90)
    versions = validate.get_versions(nodes)
    errors = {n.name: validate.recent_replication_errors(n) for n in nodes}
    queue_problems = {n.name: validate.replication_queue_problems(n) for n in nodes}

    step = {
        "label": f"upgrade {node_name} -> {new_version}",
        "node": node_name,
        "new_version": new_version,
        "node_came_back_up": node_up,
        "versions": versions,
        "all_up_throughout": all(validate.wait_all_up(nodes, timeout=5).values()),
        "converged": converged,
        "row_counts": counts,
        "probe": probe,
        "errors_found": errors,
        "queue_problems": queue_problems,
    }
    return step, env


def _hop_ok(step: dict) -> bool:
    return bool(
        step.get("node_came_back_up")
        and step.get("converged")
        and step.get("probe", {}).get("fully_replicated")
        and not any(v for v in step.get("errors_found", {}).values())
    )


# ---------------------------------------------------------------------------
# Granular, individually invokable steps.
#
# Each of these is a self-contained unit of work: bring up a fresh cluster,
# upgrade exactly one node, or verify ON CLUSTER DDL still propagates. They
# don't depend on being called from within the same Python process as a
# previous step -- state is recovered from the running containers via
# compose.current_env(), not threaded through function arguments. That's
# what lets ci_step.py invoke each one as its own separate CLI call, so a
# CI workflow can turn each one into its own GitHub Actions step with its
# own pass/fail checkmark, timing, and log -- rather than one opaque job
# that only reports pass/fail for the whole upgrade path at once.
#
# scenario_staged_lts() and scenario_direct_jump() below are the
# single-process equivalent for local/`make test` use, built out of these
# same functions so the two entry points can never silently diverge.
# ---------------------------------------------------------------------------


def setup_step(base_version: str, label: str = "setup", log=print) -> dict:
    try:
        fresh_cluster(base_version, log=log)
        load_schema_and_seed(log=log)
        return {"label": label, "base_version": base_version, "ok": True}
    except Exception as e:
        return {"label": label, "base_version": base_version, "ok": False, "error": str(e)}


def upgrade_node_step(node_name: str, new_version: str, label: str | None = None, log=print) -> dict:
    env = compose.current_env()
    step, _env = _run_upgrade_step(env, node_name, new_version, log=log)
    if label:
        step["label"] = label
    return step


def verify_ddl_step(version: str, label: str | None = None, log=print) -> dict:
    """Once every replica is on `version`, confirm ON CLUSTER DDL still works
    cluster-wide (a real thing OONI does during normal operation, not just
    something that matters mid-upgrade)."""
    nodes = make_nodes()
    marker = f"test_marker_{version.replace('.', '_')}"
    try:
        nodes[0].execute(
            f"ALTER TABLE ooni.citizenlab ON CLUSTER oonidata_cluster "
            f"ADD COLUMN IF NOT EXISTS {marker} String DEFAULT ''"
        )
        ok, error = True, None
    except Exception as e:
        ok, error = False, str(e)
        log(f"[verify-ddl] ON CLUSTER ALTER failed at {version}: {error}")
    return {
        "label": label or f"verify-ddl-{version}",
        "version": version,
        "on_cluster_alter_ok": ok,
        "error": error,
    }


def step_ok(step: dict) -> bool:
    """Pass/fail check that works across all three step shapes above
    (setup / upgrade-node / verify-ddl) -- used by ci_step.py to set its
    process exit code, and by report.py to compute an overall verdict."""
    if "on_cluster_alter_ok" in step:
        return bool(step["on_cluster_alter_ok"])
    if "base_version" in step and "node" not in step:
        return bool(step.get("ok"))
    return _hop_ok(step)


def scenario_staged_lts(log=print) -> dict:
    scenario = {
        "name": "Staged rolling upgrade via LTS hops",
        "description": (
            f"Rolling (one node at a time) upgrade from {BASE_VERSION} to {LATEST_VERSION}, "
            "stepping through each intermediate LTS release so no two replicas are ever "
            "more than ~1 year of ClickHouse releases apart (per ClickHouse's documented "
            "mixed-version compatibility window)."
        ),
        "steps": [],
    }
    setup = setup_step(BASE_VERSION, label="setup", log=log)
    if not setup.get("ok"):
        scenario["verdict"] = f"ERROR during setup: {setup.get('error')}"
        return scenario

    hop_versions = [v for v, _months in LTS_HOPS[1:]]  # skip the starting version
    all_ok = True
    for hop_version in hop_versions:
        for node_name in NODE_ORDER:
            step = upgrade_node_step(node_name, hop_version, log=log)
            scenario["steps"].append(step)
            ok = step_ok(step)
            all_ok = all_ok and ok
            log(f"[staged] {step['label']}: {'OK' if ok else 'PROBLEM DETECTED'}")

        ddl_result = verify_ddl_step(hop_version, log=log)
        scenario.setdefault("ddl_checks", []).append(ddl_result)
        all_ok = all_ok and step_ok(ddl_result)

    scenario["verdict"] = "PASS -- rolling, node-by-node upgrade completed with no data loss, no replication errors, zero full-shard downtime" if all_ok else "FAIL -- see steps above for where it broke"
    return scenario


def scenario_direct_jump(log=print) -> dict:
    scenario = {
        "name": "Direct one-hop rolling upgrade (skips all intermediate LTS releases)",
        "description": (
            f"Rolling (one node at a time) upgrade straight from {BASE_VERSION} to "
            f"{LATEST_VERSION}, the same way you'd do it if you just bumped the version "
            "in Ansible and rolled it out host-by-host without stopping to think about "
            "version skew. This intentionally spends time with replicas ~23 months apart "
            "in version, well past ClickHouse's ~1 year documented compatibility window, "
            "to observe what actually happens rather than assume."
        ),
        "steps": [],
    }
    setup = setup_step(BASE_VERSION, label="setup", log=log)
    if not setup.get("ok"):
        scenario["verdict"] = f"ERROR during setup: {setup.get('error')}"
        return scenario

    all_ok = True
    for node_name in NODE_ORDER:
        step = upgrade_node_step(node_name, LATEST_VERSION, log=log)
        scenario["steps"].append(step)
        ok = step_ok(step)
        all_ok = all_ok and ok
        log(f"[direct] {step['label']}: {'OK' if ok else 'PROBLEM DETECTED'}")

    scenario["verdict"] = (
        "PASS -- surprisingly, no issues observed (re-verify; ClickHouse still advises against this)"
        if all_ok
        else "FAIL -- confirms ClickHouse's guidance: do not skip >1 year of releases in a mixed-version cluster"
    )
    return scenario
