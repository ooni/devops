"""Turns the structured results dict produced by scenarios.py into a
human-readable Markdown report."""
from __future__ import annotations

import json
import re
from pathlib import Path

# Groups a hop's node-upgrade steps together with the verify-ddl step that
# checkpoints the end of that hop, purely by label convention: `<hop>-ch1`
# / `<hop>-ch2` / `<hop>-ch3` alongside `<hop>-verify-ddl` -- see
# .github/workflows/clickhouse_upgrade_test.yml's step labels (hop1-ch1,
# hop1-verify-ddl, direct-ch1, direct-verify-ddl, skip-hop1-ch1, ...).
# Steps outside this convention (setup, content-integrity, and the
# real-data/availability shapes, which use a different labeling scheme and
# already have their own, stronger per-hop integrity checks) simply don't
# match and fall back to their own literal step_ok() everywhere below.
_HOP_NODE_RE = re.compile(r"^(?P<hop>.+)-ch[123]$")
_HOP_DDL_RE = re.compile(r"^(?P<hop>.+)-verify-ddl$")


def _fmt_bool(b) -> str:
    return "PASS" if b else "FAIL"


def _hop_groups(steps: list[dict]) -> dict[str, dict]:
    groups: dict[str, dict] = {}
    for step in steps:
        label = step.get("label", "")
        m = _HOP_NODE_RE.match(label)
        if m and "node" in step:
            groups.setdefault(m.group("hop"), {}).setdefault("node_steps", []).append(step)
            continue
        m = _HOP_DDL_RE.match(label)
        if m and "on_cluster_alter_ok" in step:
            groups.setdefault(m.group("hop"), {})["ddl_step"] = step
    return groups


def self_healed(step: dict, all_steps: list[dict]) -> bool:
    """True if `step` failed step_ok() but the hop it belongs to (per
    _hop_groups(), keyed off its label) had settled into a fully converged,
    healthy state -- row counts matching across all 3 nodes, nothing still
    stuck retrying in system.replication_queue -- by the time that hop's
    verify-ddl checkpoint ran (see scenarios._hop_settled() /
    verify_ddl_step()). This is the expected, self-healing mixed-version
    incompatibility documented at length in harness/versions.py clearing
    before the hop ended, as distinct from a hop that never recovered."""
    from .scenarios import step_ok  # local import: avoids a report<->scenarios import cycle

    if step_ok(step):
        return False
    m = _HOP_NODE_RE.match(step.get("label", ""))
    if not m:
        return False
    group = _hop_groups(all_steps).get(m.group("hop"), {})
    ddl_step = group.get("ddl_step")
    return bool(ddl_step and step_ok(ddl_step) and ddl_step.get("settled"))


def effective_ok(step: dict, all_steps: list[dict]) -> bool:
    """step_ok(), except a hard-error node-upgrade step that self-healed
    (see self_healed()) counts as passing for gating purposes. It still
    renders as its literal FAIL in the per-step list below (annotated
    "SELF-HEALED", not hidden) -- only the overall pass/fail is affected.
    Every other step shape (verify-ddl itself, setup, content-integrity,
    and anything outside the hop-node/verify-ddl label convention) is
    ungated by self-healing and must literally pass."""
    from .scenarios import step_ok

    return step_ok(step) or self_healed(step, all_steps)


def overall_ok(steps: list[dict]) -> bool:
    """The end-to-end pass/fail this project actually wants: no data loss
    or corruption by the time the rollout finished, even if some
    mid-rollout steps logged a hard-looking error that cleared before its
    own hop ended. Used by both ci_step.py's `report` exit code and this
    module's rendered "Overall" line, so the two can't drift apart."""
    return all(effective_ok(s, steps) for s in steps)


def render_step(step: dict, all_steps: list[dict] | None = None) -> str:
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
    # "self_healed" is set directly on the step dict by the local,
    # single-process scenario_staged_lts()/scenario_direct_jump() (they
    # already know their own hop grouping); for the CI-step-model report
    # (render_ci_step() below) it's derived from label conventions instead
    # via self_healed(), passed in through all_steps.
    healed = bool(step.get("self_healed")) or (all_steps is not None and self_healed(step, all_steps))
    if any_hard:
        status = "YES -- SELF-HEALED (cluster fully converged by end of hop, see verify-ddl below)" if healed else "YES -- FAILS THIS STEP"
    else:
        status = "none"
    lines.append(f"- Version-incompatibility errors logged by ClickHouse: **{status}**")
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


def render_content_integrity(step: dict) -> str:
    """scenarios.content_integrity_step()'s shape -- "does the pre-existing
    seed data still survive untouched, right now" -- keyed on its
    always-present "diffs" field (see that function's docstring). Called
    once per hop (not just once at the end of the rollout -- see
    scenario_staged_lts()), so the wording below deliberately says "as of
    this check" rather than "by the end of the rollout": whichever call
    happens to be the last one IS the end-of-rollout answer, but every
    earlier one is just as real a pass/fail for the hop it followed."""
    label = step.get("label", "content-integrity")
    ok = step.get("ok")
    lines = [f"### `{label}` -- {_fmt_bool(ok)}", ""]
    if step.get("error") and not step.get("golden_snapshot"):
        lines.append(f"Could not run: {step['error']}")
    elif ok:
        lines.append(
            "Every pre-existing seed row (probe-tagged rows from mid-rollout "
            "writes excluded) still checksum-matches the golden snapshot "
            "taken right after setup, on all 3 nodes, as of this check -- "
            "**no data loss or corruption in the pre-existing data so far.**"
        )
    else:
        lines.append("Pre-existing seed data changed by this point in the rollout -- genuine data loss/corruption, not self-healing:")
        lines.append("")
        lines.append("```")
        lines.append(json.dumps(step.get("diffs"), indent=2, default=str)[:3000])
        lines.append("```")
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
    all_steps = scenario.get("steps", [])
    for step in all_steps:
        lines.append(render_step(step, all_steps=all_steps))
    for ddl in scenario.get("ddl_checks", []):
        lines.append(
            f"### Step: {ddl.get('label')}\n\n"
            f"- `ALTER TABLE ... ON CLUSTER` at `{ddl.get('version')}`: **{_fmt_bool(ddl.get('on_cluster_alter_ok'))}**\n"
            f"- Cluster settled (converged, no stuck replication-queue entries) by end of this hop: **{_fmt_bool(ddl.get('settled'))}**\n"
        )
    # "content_integrity_checks" (plural, one per hop) is the current shape
    # -- see scenario_staged_lts()/scenario_direct_jump() in scenarios.py.
    # Falls back to the older singular "content_integrity" key so any
    # results.json produced before this change still renders.
    content_checks = scenario.get("content_integrity_checks")
    if content_checks is None and "content_integrity" in scenario:
        content_checks = [scenario["content_integrity"]]
    for check in content_checks or []:
        lines.append(render_content_integrity(check))
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


def render_ci_step(step: dict, all_steps: list[dict] | None = None) -> str:
    """Render one step from ci_step.py's results/steps/*.json. Dispatches on
    which keys are present the same way scenarios.step_ok() does -- covers
    both the original three shapes (setup / upgrade-node / verify-ddl), the
    content-integrity shape (now recorded once per hop, not just once at
    the end of the rollout -- see content_integrity_step()'s docstring;
    dispatch here doesn't care which hop it came from, only its shape), and
    the real-data scenario's shapes from harness/real_data.py
    (setup-real-data / load-real-data / golden-snapshot / verify-e2e /
    real-data-hop). `all_steps` (the full flat list this step came from) is
    threaded through so upgrade-node
    steps can report self_healed() status -- see render_step()."""
    label = step.get("label", "?")

    if "on_cluster_alter_ok" in step:
        ok = step["on_cluster_alter_ok"]
        lines = [f"### `{label}` -- {_fmt_bool(ok)}", ""]
        lines.append(f"`ALTER TABLE ... ON CLUSTER` at version `{step.get('version')}`: " + ("succeeded" if ok else f"FAILED: {step.get('error')}"))
        if "settled" in step:
            lines.append(
                f"- Cluster settled (row counts converged, no stuck replication-queue entries) "
                f"by end of this hop: **{_fmt_bool(step.get('settled'))}**"
            )
        lines.append("")
        return "\n".join(lines)

    if "diffs" in step and "on_cluster_alter_ok" not in step:
        # scenarios.content_integrity_step() -- see render_content_integrity().
        return render_content_integrity(step)

    if "write_stats" in step:
        # harness/availability.py's run_zero_downtime_upgrade() -- one step
        # spanning the ENTIRE rollout (every hop in RECOMMENDED_LTS_HOPS[1:]),
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
            lines.append(render_ci_step(hop, all_steps=all_steps))
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
            lines.append(render_ci_step(node_step, all_steps=all_steps))
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
    return f"### `{label}`\n\n" + render_step(step, all_steps=all_steps)


def render_ci_steps_report(steps: list[dict]) -> str:
    """Assemble the report ci_step.py's `report` subcommand writes, from
    whatever results/steps/*.json files exist on disk -- possibly a subset,
    if an earlier CI step failed and later ones were skipped.

    Overall pass/fail (overall_ok(), also what ci_step.py's `report` exits
    non-zero on) reflects whether the rollout ended with no data loss or
    corruption -- a mid-rollout step that logged a hard-looking error but
    self-healed by the end of its own hop (see self_healed()) does NOT fail
    the job on its own, though it's still shown as its literal FAIL below,
    annotated, so nothing is hidden."""
    from .scenarios import step_ok  # local import: avoids a report<->scenarios import cycle at module load time

    lines = ["# ClickHouse Upgrade Test -- CI Step Report", ""]
    if not steps:
        lines.append("_No step results found -- did every step run before this one?_")
        return "\n".join(lines)

    any_fail = not overall_ok(steps)
    lines.append(
        f"**Overall: {'ALL STEPS PASSED (or self-healed -- no data loss or corruption by end of rollout)' if not any_fail else 'AT LEAST ONE STEP FAILED -- see below'}**"
    )
    lines.append("")
    lines.append(f"{len(steps)} step(s) recorded:")
    lines.append("")
    for step in steps:
        ok = step_ok(step)
        if ok:
            status = "PASS"
        elif self_healed(step, steps):
            status = "FAIL, but SELF-HEALED by end of hop (does not fail the job)"
        else:
            status = "FAIL"
        lines.append(f"- `{step.get('label')}`: {status}")
    lines.append("")
    for step in steps:
        lines.append(render_ci_step(step, all_steps=steps))
    return "\n".join(lines)
