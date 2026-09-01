"""
Real-data end-to-end scenario: does the actual OONI data pipeline (not this
harness's synthetic seed data) still work at each hop of the production
upgrade path?

This is a *separate, additional* scenario from scenario_staged_lts() /
scenario_direct_jump() in harness/scenarios.py -- it does not replace the
synthetic-data harness, which stays as the fast, self-contained check that
runs on every relevant PR. This one is slower and has a real external
dependency (ooni/data#160, still an open PR as of this writing) and real
network access (downloading actual OONI measurements), so it's wired up as
its own CI job -- see the `real-data-upgrade` job in
.github/workflows/clickhouse_upgrade_test.yml.

Design, per the explicit instructions this was built to:
  - Download and ingest the real dataset exactly ONCE per run, at
    BASE_VERSION, rather than at every hop -- re-downloading/re-ingesting
    at each of PRODUCTION_HOPS's 4 checkpoints would multiply this job's
    already-substantial runtime for no real gain, since the interesting
    question is "does upgrading corrupt what's already there and keep
    queries working", not "can fresh data still be ingested at every
    intermediate version" (the latter is a real question too, but a
    different one -- see the module-level TODO below).
  - PRODUCTION_HOPS (4 hops: 24.8.6.70 -> 25.3.14.14 -> 25.8.29.51 ->
    26.3.17.110 -> 26.7.3.19), not the 8-hop LTS_HOPS bisection ladder --
    this job verifies the actual recommended upgrade path, not every
    diagnostic waypoint used to find where the mark-file incompatibility
    lived.
  - After each hop: (a) re-run the exact row-count + content-checksum
    snapshot taken right after the initial load and diff it against that
    golden baseline -- any difference at all is a hard failure, since
    nothing should be writing new data during an upgrade rehearsal; and
    (b) re-run ooni/data#160's own pytest suite against the (now upgraded)
    cluster through the real api-oonimeasurements service, to confirm the
    genuine query/API paths still work, not just that ClickHouse's own
    replication mechanics survived (already covered by the synthetic
    scenario's write-then-read-back probe).

TODO / explicitly out of scope for this version: re-ingesting *fresh* real
data at each hop as well, to test the write/ingestion path (not just reads)
at every individual ClickHouse version. That's a real, different question
from "did upgrading corrupt what's there" -- worth its own follow-up if the
per-hop runtime budget allows for it.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import compose, validate
from .ch_http import ChNode
from .scenarios import apply_schema, fresh_cluster, make_nodes, step_ok

PROJECT_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_DIR / "results"
SNAPSHOT_PATH = RESULTS_DIR / "real_data_golden_snapshot.json"

COMPOSE_FILES = ["docker-compose.yml", "docker-compose.real-data.yml"]

# Only the tables this specific pipeline invocation actually writes --
# `oonidata sync` + `oonipipeline run --workflow-name observations`
# populates obs_web/obs_web_ctrl/obs_http_middlebox, and fastpath's own
# ingestion populates ooni.fastpath. `citizenlab`, `fingerprints_dns/http`,
# and `obs_openvpn` all need a *different* updater/workflow invocation this
# job doesn't run, so they're expected to stay empty here -- not a bug,
# just not exercised by this specific real-data path. If a later change
# adds those invocations too, add the relevant table(s) here.
REAL_DATA_TABLES = ["fastpath", "obs_web", "obs_web_ctrl", "obs_http_middlebox"]

# downloader does `oonidata sync` (real network + S3, can be slow) then
# `oonipipeline run` (processes 3 days x 2 countries of real measurements);
# fastpath separately re-ingests the same window. Generous but bounded --
# a hang here should fail the job, not exhaust the whole workflow timeout.
LOAD_TIMEOUT_SECONDS = 30 * 60


def snapshot_tables(node: ChNode, tables: list[str] = REAL_DATA_TABLES) -> dict[str, dict]:
    """Row count + an order-independent content checksum per table.
    `sum(cityHash64(*))` is ClickHouse's own idiom for "checksum a table
    without listing its columns by hand" -- cityHash64 is variadic and `*`
    expands to every column, and summing (rather than, say, concatenating)
    means row order -- which MergeTree never guarantees is stable across
    replicas or across a re-merge triggered by an upgrade -- can't cause a
    false mismatch."""
    out = {}
    for t in tables:
        try:
            row = node.query_rows(
                f"SELECT count() AS cnt, sum(cityHash64(*)) AS checksum FROM ooni.{t}"
            )[0]
            out[t] = {"row_count": int(row["cnt"]), "checksum": str(row["checksum"])}
        except Exception as e:
            out[t] = {"row_count": None, "checksum": None, "error": str(e)}
    return out


def snapshot_all_nodes(nodes: list[ChNode], tables: list[str] = REAL_DATA_TABLES) -> dict[str, dict]:
    return {n.name: snapshot_tables(n, tables) for n in nodes}


def _snapshots_agree(snap_by_node: dict[str, dict]) -> tuple[bool, list[str]]:
    """True if every node's snapshot has identical (row_count, checksum)
    for every table. Returns (agree, [mismatching table names])."""
    node_names = list(snap_by_node.keys())
    if not node_names:
        return False, []
    mismatches = []
    for t in REAL_DATA_TABLES:
        values = {(snap_by_node[n][t].get("row_count"), snap_by_node[n][t].get("checksum")) for n in node_names}
        if len(values) != 1:
            mismatches.append(t)
    return (len(mismatches) == 0), mismatches


def setup_real_data_step(base_version: str, label: str = "setup-real-data", log=print) -> dict:
    """Same as scenarios.setup_step(), except schema only -- no synthetic
    seed data. The real-data scenario populates its tables via the actual
    pipeline (load_real_data_step below), not harness/seed_data.py."""
    try:
        fresh_cluster(base_version, log=log)
        apply_schema(log=log)
        # schema_only distinguishes this from scenarios.setup_step()'s
        # otherwise-identical-shaped dict, so report.py can render an
        # accurate message (no synthetic seed data here -- see module
        # docstring) instead of claiming seed data was loaded.
        return {"label": label, "base_version": base_version, "schema_only": True, "ok": True}
    except Exception as e:
        return {"label": label, "base_version": base_version, "schema_only": True, "ok": False, "error": str(e)}


def load_real_data_step(label: str = "load-real-data", log=print) -> dict:
    """Bring up postgres/valkey/api/downloader/fastpath (NOT verify -- that
    runs separately, on demand, once per checkpoint) and wait for the two
    one-shot containers (downloader, fastpath) to exit 0. Meant to run
    exactly once per CI run, immediately after setup_real_data_step()."""
    try:
        log("[real-data] bringing up postgres/valkey/api/downloader/fastpath...")
        compose.up(
            services=["postgres", "valkey", "api", "downloader", "fastpath"],
            files=COMPOSE_FILES,
        )

        results = {}
        for container in ["ooni-e2e-downloader", "ooni-e2e-fastpath"]:
            log(f"[real-data] waiting for {container} to finish...")
            code = _wait_for_exit(container, timeout=LOAD_TIMEOUT_SECONDS)
            results[container] = code
            if code != 0:
                log(f"[real-data] {container} exited {code} -- last 200 log lines:")
                log(compose.logs(container.replace("ooni-e2e-", ""), tail=200, files=COMPOSE_FILES))

        api_up = _wait_for_healthy("ooni-e2e-api", timeout=180)

        ok = all(c == 0 for c in results.values()) and api_up
        return {
            "label": label,
            "downloader_exit_code": results.get("ooni-e2e-downloader"),
            "fastpath_exit_code": results.get("ooni-e2e-fastpath"),
            "api_healthy": api_up,
            "ok": ok,
        }
    except Exception as e:
        log(f"[real-data] load_real_data_step raised: {e}")
        return {"label": label, "ok": False, "error": str(e)}


def take_golden_snapshot_step(label: str = "golden-snapshot", log=print) -> dict:
    """Snapshot every REAL_DATA_TABLES table on all 3 nodes, require they
    already agree with each other (replication should have long since
    converged by this point -- load_real_data_step already waited on the
    pipeline containers to exit), and persist the result as the baseline
    every later hop's integrity check diffs against."""
    nodes = make_nodes()
    snap = snapshot_all_nodes(nodes)
    agree, mismatches = _snapshots_agree(snap)
    if agree:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        SNAPSHOT_PATH.write_text(json.dumps(snap["ch1"], indent=2))
        log(f"[real-data] golden snapshot taken: {snap['ch1']}")
    else:
        log(f"[real-data] nodes disagree before any upgrade even started -- tables: {mismatches}")
    return {
        "label": label,
        "ok": agree,
        "snapshot_by_node": snap,
        "mismatched_tables": mismatches,
    }


def check_integrity_step(label: str, log=print) -> dict:
    """Re-snapshot all 3 nodes and diff against the golden baseline taken
    right after the initial real-data load. Any difference -- on any node,
    in either row_count or checksum -- is a hard failure: nothing in this
    scenario should ever write new data after take_golden_snapshot_step(),
    so any change can only mean the upgrade altered or lost something."""
    if not SNAPSHOT_PATH.exists():
        return {"label": label, "ok": False, "error": f"no golden snapshot found at {SNAPSHOT_PATH}"}
    golden = json.loads(SNAPSHOT_PATH.read_text())
    nodes = make_nodes()
    current = snapshot_all_nodes(nodes)

    diffs = {}
    for node_name, node_snap in current.items():
        for t in REAL_DATA_TABLES:
            if node_snap[t] != golden[t]:
                diffs.setdefault(node_name, {})[t] = {"golden": golden[t], "current": node_snap[t]}

    ok = len(diffs) == 0
    if not ok:
        log(f"[real-data] integrity check FAILED at {label}: {diffs}")
    else:
        log(f"[real-data] integrity check OK at {label}: every table matches the golden snapshot on all 3 nodes")
    return {
        "label": label,
        "ok": ok,
        "golden_snapshot": golden,
        "current_snapshot_by_node": current,
        "diffs": diffs,
    }


def run_e2e_verify_step(label: str, log=print) -> dict:
    """`docker compose run --rm verify` -- ooni/data#160's own pytest suite
    against the api-oonimeasurements service, which itself reads from
    whatever ClickHouse version ch1/ch2/ch3 currently are. A fresh
    container and a fresh pass/fail every call; see docker-compose.real-data.yml's
    `verify` service for why `run`, not `up`."""
    proc = compose.run_oneoff("verify", files=COMPOSE_FILES)
    ok = proc.returncode == 0
    output = (proc.stdout or "") + (proc.stderr or "")
    log(f"[real-data] {label}: pytest {'PASSED' if ok else 'FAILED'} (exit {proc.returncode})")
    if not ok:
        log(output[-4000:])  # tail -- the failure summary is what matters, not the full run
    return {
        "label": label,
        "ok": ok,
        "exit_code": proc.returncode,
        "pytest_output": output,
    }


def real_data_hop_step(hop_version: str, hop_label: str, log=print) -> dict:
    """Upgrade all 3 nodes to hop_version (reusing the exact same
    upgrade_node_step() mechanics the synthetic scenario uses -- these are
    already version/schema-agnostic), then run the integrity check and the
    real pytest suite. Returns one combined dict so ci_step.py can persist
    it as a single results/steps/<label>.json, the same shape convention
    every other step in this project uses."""
    from .scenarios import NODE_ORDER, upgrade_node_step  # local import: avoids a cycle at module load time

    node_steps = []
    for node_name in NODE_ORDER:
        step = upgrade_node_step(node_name, hop_version, label=f"{hop_label}-{node_name}", log=log)
        node_steps.append(step)

    integrity = check_integrity_step(f"{hop_label}-integrity", log=log)
    verify = run_e2e_verify_step(f"{hop_label}-verify", log=log)

    all_node_upgrades_ok = all(step_ok(s) for s in node_steps)
    ok = all_node_upgrades_ok and integrity["ok"] and verify["ok"]

    return {
        "label": hop_label,
        "hop_version": hop_version,
        "node_steps": node_steps,
        "integrity": integrity,
        "verify": verify,
        "ok": ok,
    }


def _wait_for_exit(container_name: str, timeout: int) -> int | None:
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        code = compose.inspect_exit_code(container_name)
        if code is not None:
            return code
        time.sleep(5)
    return None


def _wait_for_healthy(container_name: str, timeout: int) -> bool:
    import subprocess
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        proc = subprocess.run(
            ["docker", "inspect", container_name, "--format", "{{.State.Health.Status}}"],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0 and proc.stdout.strip() == "healthy":
            return True
        time.sleep(5)
    return False
