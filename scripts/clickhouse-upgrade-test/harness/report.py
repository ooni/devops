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
