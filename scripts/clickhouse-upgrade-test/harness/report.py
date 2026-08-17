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
    any_errs = any(v for v in errs.values())
    lines.append(f"- Replication-related errors logged by ClickHouse: **{'YES' if any_errs else 'none'}**")
    if any_errs:
        for node, errlist in errs.items():
            if errlist:
                lines.append(f"  - `{node}`:")
                for e in errlist[:5]:
                    lines.append(f"    - `{e.get('name')}`: {e.get('last_error_message', '')[:200]}")
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
    """Render one step from ci_step.py's results/steps/*.json -- these use
    one of three shapes (setup / upgrade-node / verify-ddl); dispatch on
    which keys are present the same way scenarios.step_ok() does."""
    label = step.get("label", "?")

    if "on_cluster_alter_ok" in step:
        ok = step["on_cluster_alter_ok"]
        lines = [f"### `{label}` -- {_fmt_bool(ok)}", ""]
        lines.append(f"`ALTER TABLE ... ON CLUSTER` at version `{step.get('version')}`: " + ("succeeded" if ok else f"FAILED: {step.get('error')}"))
        lines.append("")
        return "\n".join(lines)

    if "base_version" in step and "node" not in step:
        ok = step.get("ok")
        lines = [f"### `{label}` -- {_fmt_bool(ok)}", ""]
        if ok:
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
