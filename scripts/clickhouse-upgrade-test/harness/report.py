"""Turns the structured results dict produced by scenarios.py into a
human-readable Markdown report."""
from __future__ import annotations

import json
from pathlib import Path


def _fmt_bool(b) -> str:
    return "PASS" if b else "FAIL"


def render_step(step: dict) -> str:
    lines = []
    lines.append(f"### Step: {step['label']}")
    lines.append("")
    lines.append(f"- Node upgraded: `{step.get('node', '-')}`")
    lines.append(f"- New version: `{step.get('new_version', '-')}`")
    lines.append(f"- Versions across cluster after this step: `{step.get('versions')}`")
    lines.append(f"- Rolling (never all-3-down): **{_fmt_bool(step.get('all_up_throughout'))}**")
    lines.append(f"- Row counts converged across nodes: **{_fmt_bool(step.get('converged'))}**")
    probe = step.get("probe", {})
    lines.append(
        f"- Write-then-read-back probe fully replicated: **{_fmt_bool(probe.get('fully_replicated'))}** "
        f"(probe id `{probe.get('probe_id')}`)"
    )
    errs = step.get("errors_found", {})
    hard = step.get("hard_errors_found", {})
    any_hard = any(v for v in hard.values())
    any_transient = any(
        e.get("kind") == "transient" for errlist in errs.values() for e in errlist
    )
    lines.append(
        f"- Version-incompatibility errors logged by ClickHouse: "
        f"**{'YES -- FAILS THIS STEP' if any_hard else 'none'}**"
    )
    if any_hard:
        for node, errlist in hard.items():
            if errlist:
                lines.append(f"  - `{node}`:")
                for e in errlist[:5]:
                    lines.append(
                        f"    - `{e.get('name')}` (+{e.get('new_since_step_start')} since step start): "
                        f"{e.get('last_error_message', '')[:200]}"
                    )
    if any_transient:
        lines.append(
            "- Transient connection errors during the container bounce "
            "(expected side effect of force-recreating a peer; non-gating -- see harness/validate.py):"
        )
        for node, errlist in errs.items():
            transient = [e for e in errlist if e.get("kind") == "transient"]
            if transient:
                names = ", ".join(f"`{e['name']}` (+{e['new_since_step_start']})" for e in transient)
                lines.append(f"  - `{node}`: {names}")
    qprob = step.get("queue_problems", {})
    any_q = any(v for v in qprob.values())
    if any_q:
        lines.append("- Replication queue entries stuck retrying:")
        for node, items in qprob.items():
            if items:
                lines.append(f"  - `{node}`: {len(items)} stuck task(s)")
    lines.append("")
    return "\n".join(lines)


def render_scenario(scenario: dict) -> str:
    lines = []
    lines.append(f"## Scenario: {scenario['name']}")
    lines.append("")
    lines.append(scenario.get("description", ""))
    lines.append("")
    lines.append(f"**Overall result: {scenario.get('verdict', 'UNKNOWN')}**")
    lines.append("")
    for step in scenario.get("steps", []):
        lines.append(render_step(step))
    return "\n".join(lines)


def render_full_report(results: dict) -> str:
    lines = ["# ClickHouse Upgrade Test Report", ""]
    lines.append(f"Base (production) version: `{results.get('base_version')}`")
    lines.append(f"Target (latest stable) version: `{results.get('latest_version')}`")
    lines.append("")
    for scenario in results.get("scenarios", []):
        lines.append(render_scenario(scenario))
        lines.append("")
    lines.append("## Raw results (JSON)")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(results, indent=2, default=str))
    lines.append("```")
    return "\n".join(lines)


def write_report(results: dict, path: Path) -> None:
    path.write_text(render_full_report(results))


def render_ci_step(step: dict) -> str:
    """Render one step from ci_step.py's results/steps/*.json. Dispatches on
    which keys are present the same way scenarios.step_ok() does -- covers
    both the original three shapes (setup / upgrade-node / verify-ddl) and
    the real-data scenario's shapes from harness/real_data.py
    (setup-real-data / load-real-data / golden-snapshot / verify-e2e /
    real-data-hop)."""
    label = step.get("label", "?")

    if "on_cluster_alter_ok" in step:
        ok = step["on_cluster_alter_ok"]
        lines = [f"### `{label}` -- {_fmt_bool(ok)}", ""]
        lines.append(f"`ALTER TABLE ... ON CLUSTER` at version `{step.get('version')}`: " + ("succeeded" if ok else f"FAILED: {step.get('error')}"))
        lines.append("")
        return "\n".join(lines)

    if "write_stats" in step:
        # harness/availability.py's run_zero_downtime_upgrade() -- one step
        # spanning the ENTIRE rollout (every hop in PRODUCTION_HOPS[1:]),
        # with a continuous read/write canary (harness.availability.CanaryWriter)
        # running in the background throughout, never paused between hops.
        # This is what actually proves "no downtime, no blocked writes, no
        # corruption" rather than just "data at rest matches between
        # checkpoints" (that's what the per-hop integrity/verify checks
        # nested below still check, same as real_data_hop_step()).
        ok = step.get("ok")
        ws = step.get("write_stats", {})
        missing = step.get("missing_writes") or []
        lines = [f"### `{label}` -- {_fmt_bool(ok)}", ""]
        if step.get("error"):
            lines.append(f"FAILED before the canary could even start: {step['error']}")
            lines.append("")
            return "\n".join(lines)
        if step.get("reconciliation_error"):
            lines.append(
                f"Rollout ran, but the final reconciliation query itself failed "
                f"({step['reconciliation_error']}) -- data-loss/agreement can't be "
                "confirmed, so this is treated as a failure rather than a pass."
            )
            lines.append("")
        lines.append(
            "Continuous read/write canary (round-robin across all 3 nodes, "
            "immediate failover on a failed attempt) ran for the entire "
            "rollout below without ever pausing between hops."
        )
        lines.append("")
        lines.append(
            f"- Write attempts: `{ws.get('total_write_attempts')}`, "
            f"blocked on every node in the same tick: **{ws.get('write_hard_failures')}**"
        )
        lines.append(
            f"- Read attempts: `{ws.get('total_read_attempts')}`, "
            f"blocked on every node in the same tick: **{ws.get('read_hard_failures')}**"
        )
        lines.append(
            f"- Every acknowledged write survived to the final cluster state: "
            f"**{_fmt_bool(not missing)}**"
            + (f" -- {len(missing)} MISSING (data loss)" if missing else "")
        )
        lines.append(f"- Cross-node agreement on the canary table's final contents: **{_fmt_bool(step.get('cross_node_agreement'))}**")
        if ws.get("max_write_latency_seconds") is not None:
            lines.append(
                f"- Max latency on a successful attempt: write `{ws['max_write_latency_seconds']:.2f}s`, "
                f"read `{ws.get('max_read_latency_seconds') or 0:.2f}s`"
            )
        if ws.get("write_hard_failure_samples"):
            lines.append(f"- Sample blocked-write failures: `{ws['write_hard_failure_samples']}`")
        if ws.get("read_hard_failure_samples"):
            lines.append(f"- Sample blocked-read failures: `{ws['read_hard_failure_samples']}`")
        lines.append("")
        lines.append(
            "Per-hop detail (each hop upgrades all 3 nodes, then re-checks "
            "integrity against the golden snapshot and re-runs ooni/data's "
            "pytest suite -- same as real_data_hop_step(), but here the "
            "canary above never stops running underneath it):"
        )
        lines.append("")
        for hop in step.get("hops", []):
            lines.append(render_ci_step(hop))
        lines.append("")
        return "\n".join(lines)

    if "node_steps" in step:
        # real_data.real_data_hop_step()'s combined shape: 3 node upgrades +
        # an integrity re-check + a real pytest run, folded into one step.
        ok = step.get("ok")
        lines = [f"### `{label}` -- {_fmt_bool(ok)}", ""]
        lines.append(f"Real-data hop to `{step.get('hop_version')}`: all 3 nodes upgraded, then re-checked against the golden snapshot and ooni/data's real pytest suite re-run.")
        lines.append("")
        for node_step in step.get("node_steps", []):
            lines.append(render_ci_step(node_step))
        integrity = step.get("integrity", {})
        lines.append(f"- Integrity vs. golden snapshot: **{_fmt_bool(integrity.get('ok'))}**")
        if not integrity.get("ok"):
            lines.append(f"  - Diffs: `{integrity.get('diffs') or integrity.get('error')}`")
        verify = step.get("verify", {})
        lines.append(f"- ooni/data#160 pytest suite: **{_fmt_bool(verify.get('ok'))}** (exit code `{verify.get('exit_code')}`)")
        lines.append("")
        return "\n".join(lines)

    if "downloader_exit_code" in step or "fastpath_exit_code" in step:
        # real_data.load_real_data_step()
        ok = step.get("ok")
        lines = [f"### `{label}` -- {_fmt_bool(ok)}", ""]
        lines.append(f"- `downloader` (oonidata sync + oonipipeline observations) exit code: `{step.get('downloader_exit_code')}`")
        lines.append(f"- `fastpath` exit code: `{step.get('fastpath_exit_code')}`")
        lines.append(f"- `api-oonimeasurements` became healthy: **{_fmt_bool(step.get('api_healthy'))}**")
        if not ok and step.get("error"):
            lines.append(f"- error: {step.get('error')}")
        lines.append("")
        return "\n".join(lines)

    if "mismatched_tables" in step:
        # real_data.take_golden_snapshot_step()
        ok = step.get("ok")
        lines = [f"### `{label}` -- {_fmt_bool(ok)}", ""]
        if ok:
            tables = sorted(next(iter(step.get("snapshot_by_node", {}).values()), {}).keys())
            lines.append(f"Golden snapshot recorded (all 3 nodes agreed) for tables: `{tables}`.")
        else:
            lines.append(f"Nodes disagreed before any upgrade started -- mismatched tables: `{step.get('mismatched_tables')}`")
        lines.append("")
        return "\n".join(lines)

    if "pytest_output" in step:
        # real_data.run_e2e_verify_step(), run standalone (not nested inside
        # a real-data-hop step) -- e.g. the base-version sanity check.
        ok = step.get("ok")
        lines = [f"### `{label}` -- {_fmt_bool(ok)}", ""]
        lines.append(f"ooni/data#160 pytest suite: {'PASSED' if ok else 'FAILED'} (exit code `{step.get('exit_code')}`)")
        if not ok:
            lines.append("")
            lines.append("```")
            lines.append((step.get("pytest_output") or "")[-2000:])
            lines.append("```")
        lines.append("")
        return "\n".join(lines)

    if "base_version" in step and "node" not in step:
        ok = step.get("ok")
        lines = [f"### `{label}` -- {_fmt_bool(ok)}", ""]
        if ok:
            if step.get("schema_only"):
                lines.append(f"Fresh 3-node cluster brought up at `{step.get('base_version')}`, schema applied -- no synthetic seed data (real-data scenario; see harness/real_data.py).")
            else:
                lines.append(f"Fresh 3-node cluster brought up at `{step.get('base_version')}`, schema + seed data loaded and converged.")
        else:
            lines.append(f"FAILED: {step.get('error')}")
        lines.append("")
        return "\n".join(lines)

    # upgrade-node shaped
    return f"### `{label}`\n\n" + render_step(step)


def render_ci_steps_report(steps: list[dict]) -> str:
    """Assemble the report ci_step.py's `report` subcommand writes, from
    whatever results/steps/*.json files exist on disk -- possibly a subset,
    if an earlier CI step failed and later ones were skipped."""
    from .scenarios import step_ok  # local import: avoids a report<->scenarios import cycle at module load time

    lines = ["# ClickHouse Upgrade Test -- CI Step Report", ""]
    if not steps:
        lines.append("_No step results found -- did every step run before this one?_")
        return "\n".join(lines)

    any_fail = any(not step_ok(s) for s in steps)
    lines.append(f"**Overall: {'ALL STEPS PASSED' if not any_fail else 'AT LEAST ONE STEP FAILED -- see below'}**")
    lines.append("")
    lines.append(f"{len(steps)} step(s) recorded:")
    lines.append("")
    for step in steps:
        ok = step_ok(step)
        lines.append(f"- `{step.get('label')}`: {'PASS' if ok else 'FAIL'}")
    lines.append("")
    for step in steps:
        lines.append(render_ci_step(step))
    return "\n".join(lines)
