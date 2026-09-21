"""
Zero-downtime proof: does the cluster keep accepting reads and writes,
without ever fully blocking and without losing or corrupting a single
acknowledged write, for the ENTIRE duration of a rolling upgrade -- not
just at the point-in-time checkpoints the other scenarios take between
node bounces?

This is a different question from what harness/real_data.py's per-hop
integrity check answers. That check proves data already sitting in the
cluster survives an upgrade untouched (a quiescent before/after diff). It
says nothing about whether a client trying to read or write *during* a
node's bounce experiences any interruption -- and "no downtime, no
blocked writes" is a claim about exactly that window, not about data at
rest.

How this proves it: a background canary thread continuously reads and
writes against the cluster for the WHOLE rollout (all 4 PRODUCTION_HOPS
hops, all 12 node upgrades), started before the first node bounce and
stopped only after the last one settles. Every attempt round-robins
across ch1/ch2/ch3 with immediate failover to the next node on failure --
this is what "no blocked writes" actually means for a 3-replica cluster:
not that every individual node stays reachable every second (one node
WILL be briefly unreachable during its own bounce -- that's the entire
point of a rolling upgrade), but that a reasonably-written client (or the
load balancer/proxy production already runs in front of the cluster --
see ansible/roles/clickhouse_proxy) always has a path to an available
replica. A write or read that fails on every one of the 3 nodes in the
same attempt is what we count as a genuine block.

At the end: every write the canary believes succeeded is checked against
the cluster's actual final state, one probe_id at a time. A write that
ClickHouse acknowledged but that isn't actually present afterwards is
silent data loss/corruption -- a stricter and more direct test than
comparing row counts, and one that would have caught it if any of the
self-healing incompatibilities documented in harness/versions.py had
actually dropped data instead of just delaying its replication.
"""
from __future__ import annotations

import threading
import time
import uuid

from . import real_data
from .ch_http import ChNode
from .scenarios import NODE_ORDER, make_nodes, step_ok, upgrade_node_step

PROBE_TABLE = "availability_probe"

# Not part of sql/001_schema.sql on purpose: this table is pure test
# instrumentation, not a stand-in for any real production table, so it
# doesn't belong in the file that otherwise mirrors real prod DDL.
PROBE_TABLE_DDL = f"""
CREATE TABLE IF NOT EXISTS ooni.{PROBE_TABLE} ON CLUSTER oonidata_cluster
(
    `probe_id` String,
    `written_via` LowCardinality(String),
    `written_at` DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/{{cluster}}/tables/ooni/{PROBE_TABLE}/{{shard}}',
    '{{replica}}'
)
ORDER BY probe_id
"""

# ~2 attempts/sec each for reads and writes -- dense enough to have several
# attempts land inside even a short (~10-20s, per real CI timings) node
# bounce window, without meaningfully loading a CI runner.
CANARY_INTERVAL_SECONDS = 0.5
# Short enough that a write against a currently-down node fails fast and
# gets failed over to a peer well within the same tick, not stuck retrying
# against a dead port until a long default timeout expires.
PER_ATTEMPT_TIMEOUT_SECONDS = 4.0
# How long to keep the canary running after the very last node comes back
# up, before reconciling -- long enough to catch any post-upgrade
# straggler effects, short enough not to waste CI time.
GRACE_PERIOD_SECONDS = 10


class CanaryWriter:
    """Background thread issuing continuous reads and writes against the
    cluster, round-robining across all nodes with automatic failover.
    Thread-safe: results are appended under a lock so the main thread can
    read `.stats()` at any time, including right after `.stop()`."""

    def __init__(self, nodes: list[ChNode]):
        self.nodes = nodes
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._rotate_at = 0
        self.write_results: list[dict] = []
        self.read_results: list[dict] = []
        self.successful_write_ids: set[str] = set()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=30)

    def _order(self) -> list[ChNode]:
        n = len(self.nodes)
        start = self._rotate_at
        self._rotate_at = (self._rotate_at + 1) % n
        return [self.nodes[(start + i) % n] for i in range(n)]

    def _attempt_write(self) -> dict:
        probe_id = str(uuid.uuid4())
        attempts = []
        for node in self._order():
            t0 = time.monotonic()
            try:
                node.execute(
                    f"INSERT INTO ooni.{PROBE_TABLE} (probe_id, written_via) VALUES "
                    f"('{probe_id}', '{node.name}')",
                    timeout=PER_ATTEMPT_TIMEOUT_SECONDS,
                )
                attempts.append({"node": node.name, "ok": True, "latency": time.monotonic() - t0})
                return {"kind": "write", "probe_id": probe_id, "ok": True, "via": node.name, "attempts": attempts}
            except Exception as e:
                attempts.append({"node": node.name, "ok": False, "latency": time.monotonic() - t0, "error": str(e)[:200]})
        return {"kind": "write", "probe_id": probe_id, "ok": False, "via": None, "attempts": attempts}

    def _attempt_read(self) -> dict:
        attempts = []
        for node in self._order():
            t0 = time.monotonic()
            try:
                node.query_scalar(f"SELECT count() FROM ooni.{PROBE_TABLE}", timeout=PER_ATTEMPT_TIMEOUT_SECONDS)
                attempts.append({"node": node.name, "ok": True, "latency": time.monotonic() - t0})
                return {"kind": "read", "ok": True, "via": node.name, "attempts": attempts}
            except Exception as e:
                attempts.append({"node": node.name, "ok": False, "latency": time.monotonic() - t0, "error": str(e)[:200]})
        return {"kind": "read", "ok": False, "via": None, "attempts": attempts}

    def _run(self) -> None:
        while not self._stop.is_set():
            read_result = self._attempt_read()
            write_result = self._attempt_write()
            with self._lock:
                self.read_results.append(read_result)
                self.write_results.append(write_result)
                if write_result["ok"]:
                    self.successful_write_ids.add(write_result["probe_id"])
            self._stop.wait(CANARY_INTERVAL_SECONDS)

    def stats(self) -> dict:
        with self._lock:
            writes = list(self.write_results)
            reads = list(self.read_results)
            ids = set(self.successful_write_ids)

        write_failures = [w for w in writes if not w["ok"]]
        read_failures = [r for r in reads if not r["ok"]]

        per_node_write: dict[str, dict] = {}
        per_node_read: dict[str, dict] = {}
        for bucket, results in ((per_node_write, writes), (per_node_read, reads)):
            for r in results:
                for a in r["attempts"]:
                    d = bucket.setdefault(a["node"], {"attempts": 0, "successes": 0})
                    d["attempts"] += 1
                    if a["ok"]:
                        d["successes"] += 1

        write_latencies = [a["latency"] for w in writes for a in w["attempts"] if a["ok"]]
        read_latencies = [a["latency"] for r in reads for a in r["attempts"] if a["ok"]]

        return {
            "total_write_attempts": len(writes),
            "write_hard_failures": len(write_failures),
            "total_read_attempts": len(reads),
            "read_hard_failures": len(read_failures),
            "per_node_write_stats": per_node_write,
            "per_node_read_stats": per_node_read,
            "max_write_latency_seconds": max(write_latencies) if write_latencies else None,
            "max_read_latency_seconds": max(read_latencies) if read_latencies else None,
            "successful_write_ids": ids,
            # Capped so a bad run doesn't blow up the results JSON with
            # hundreds of near-identical failure dicts.
            "write_hard_failure_samples": write_failures[:5],
            "read_hard_failure_samples": read_failures[:5],
        }


def ensure_probe_table(entry: ChNode, log=print) -> None:
    log(f"[availability] ensuring ooni.{PROBE_TABLE} exists (ON CLUSTER oonidata_cluster)...")
    entry.execute(PROBE_TABLE_DDL)


def _probe_table_agreement(nodes: list[ChNode]) -> tuple[bool, dict]:
    """Same idiom as real_data._snapshots_agree(): row count + an
    order-independent content checksum, required to match across all 3
    nodes. If the canary's own table doesn't converge cleanly, that's as
    much a "the rollout broke replication" signal as anything else here."""
    snaps = {}
    for n in nodes:
        row = n.query_rows(f"SELECT count() AS cnt, sum(cityHash64(probe_id)) AS checksum FROM ooni.{PROBE_TABLE}")[0]
        snaps[n.name] = {"row_count": int(row["cnt"]), "checksum": str(row["checksum"])}
    agree = len({(v["row_count"], v["checksum"]) for v in snaps.values()}) == 1
    return agree, snaps


def run_zero_downtime_upgrade(
    hops: list[tuple[str, int | None]],
    label: str = "zero-downtime-upgrade",
    log=print,
) -> dict:
    """
    Run every hop in `hops` (each upgrading all 3 nodes, one at a time, via
    the exact same upgrade_node_step() mechanics every other scenario
    uses) with the CanaryWriter running continuously in the background for
    the whole thing -- not restarted between hops, so a problem landing
    exactly on a hop boundary can't hide in an artificial gap.

    After each hop, also re-runs real_data.check_integrity_step() (did the
    PRE-EXISTING real data loaded before this test survive untouched) and
    real_data.run_e2e_verify_step() (does the real query/API path still
    work) -- this replaces the discrete per-hop CI steps
    real_data.real_data_hop_step() used to be invoked from, folding them
    into one continuous run so the canary never has to stop and restart.

    Pass condition (`ok`): every node upgrade succeeded, every per-hop
    integrity/verify check passed, zero write attempts were blocked on
    every node, zero read attempts were blocked on every node, zero
    acknowledged writes are missing from the final cluster state, and all
    3 nodes agree on the canary table's final contents.
    """
    nodes = make_nodes()
    entry = nodes[0]

    try:
        ensure_probe_table(entry, log=log)
    except Exception as e:
        # Mirrors scenarios.upgrade_node_step()'s own reasoning: a cluster
        # that's unreachable before the canary even starts should land as a
        # clean, diagnosable failed step (results/steps/<label>.json still
        # gets written, ci_step.py still exits non-zero) -- not an
        # uncaught traceback that kills the whole CI job with nothing
        # recorded at all.
        log(f"[availability] {label} FAILED before the canary could start: {e}")
        return {
            "label": label,
            "ok": False,
            "error": str(e),
            "hops": [],
            "write_stats": {},
            "missing_writes": [],
            "cross_node_agreement": False,
            "probe_table_snapshot_by_node": {},
        }

    writer = CanaryWriter(nodes)
    log(
        "[availability] starting continuous read/write canary (round-robin "
        f"+ failover across {', '.join(n.name for n in nodes)}, "
        f"~{1 / CANARY_INTERVAL_SECONDS:.0f}/sec each for reads and writes)..."
    )
    writer.start()

    hop_results = []
    try:
        for hop_version, _months in hops:
            hop_label = f"hop-{hop_version}"
            log(f"[availability] === {hop_label}: upgrading all 3 nodes; canary keeps running underneath ===")
            node_steps = []
            for node_name in NODE_ORDER:
                step = upgrade_node_step(node_name, hop_version, label=f"{hop_label}-{node_name}", log=log)
                node_steps.append(step)

            integrity = real_data.check_integrity_step(f"{hop_label}-integrity", log=log)
            verify = real_data.run_e2e_verify_step(f"{hop_label}-verify", log=log)
            hop_ok = all(step_ok(s) for s in node_steps) and integrity["ok"] and verify["ok"]
            hop_results.append({
                "label": hop_label,
                "hop_version": hop_version,
                "node_steps": node_steps,
                "integrity": integrity,
                "verify": verify,
                "ok": hop_ok,
            })
    finally:
        # Always stop the canary even if a hop raised -- otherwise the
        # background thread outlives this function and keeps hammering a
        # cluster nothing is monitoring anymore.
        log(f"[availability] rollout finished; settling {GRACE_PERIOD_SECONDS}s before stopping the canary...")
        time.sleep(GRACE_PERIOD_SECONDS)
        writer.stop()

    stats = writer.stats()

    # The reconciliation queries below are themselves just more requests
    # against a cluster that has spent the last several minutes bouncing
    # nodes -- they can fail too. If they do, we genuinely don't know
    # whether every acknowledged write survived, so this must count as a
    # failure (missing=[] would otherwise silently read as "confirmed zero
    # data loss," which is not what an inconclusive check means) rather
    # than crash ci_step.py with no results/steps/<label>.json written.
    reconciliation_error = None
    missing: list[str] = []
    cross_node_agreement = False
    probe_snapshot: dict = {}
    try:
        log("[availability] reconciling every acknowledged write against the final cluster state...")
        actual_ids = {r["probe_id"] for r in entry.query_rows(f"SELECT probe_id FROM ooni.{PROBE_TABLE}")}
        missing = sorted(stats["successful_write_ids"] - actual_ids)
        cross_node_agreement, probe_snapshot = _probe_table_agreement(nodes)
    except Exception as e:
        reconciliation_error = str(e)
        log(
            f"[availability] reconciliation itself failed ({reconciliation_error}) -- "
            "can't confirm zero data loss, treating this as a failure"
        )

    ok = (
        reconciliation_error is None
        and all(h["ok"] for h in hop_results)
        and stats["write_hard_failures"] == 0
        and stats["read_hard_failures"] == 0
        and not missing
        and cross_node_agreement
    )

    if missing:
        log(f"[availability] DATA LOSS: {len(missing)} acknowledged write(s) are missing from the final cluster state")
    if stats["write_hard_failures"] or stats["read_hard_failures"]:
        log(
            f"[availability] BLOCKED OPERATIONS: {stats['write_hard_failures']} write attempt(s) and "
            f"{stats['read_hard_failures']} read attempt(s) failed on every node in the same tick"
        )
    if not cross_node_agreement and reconciliation_error is None:
        log(f"[availability] canary table disagreement across nodes: {probe_snapshot}")
    if ok:
        log(
            f"[availability] PASS -- {stats['total_write_attempts']} write(s) and "
            f"{stats['total_read_attempts']} read(s) attempted across the entire rollout, "
            "zero blocked on every node, zero lost, zero cross-node disagreement"
        )

    write_stats_for_report = {k: v for k, v in stats.items() if k != "successful_write_ids"}
    write_stats_for_report["successful_write_count"] = len(stats["successful_write_ids"])

    return {
        "label": label,
        "ok": ok,
        "hops": hop_results,
        "write_stats": write_stats_for_report,
        "missing_writes": missing,
        "cross_node_agreement": cross_node_agreement,
        "probe_table_snapshot_by_node": probe_snapshot,
        "reconciliation_error": reconciliation_error,
    }
