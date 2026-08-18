#!/usr/bin/env python3
"""
Per-step CLI for running the upgrade test as discrete, individually
pass/fail-able steps -- built for .github/workflows/clickhouse_upgrade_test.yml,
where each hop / node-upgrade gets its own GitHub Actions step (own
checkmark, own timing, own expandable log), rather than one opaque job that
only reports pass/fail for the entire upgrade path at once.

Each invocation is a fresh process. State that would normally be threaded
through function arguments (which image tag each node is currently running)
is instead recovered by inspecting the already-running containers via
`docker inspect` (see harness/compose.py:current_env()) -- so steps are
just plain sequential shell commands in a workflow, no shared state file to
keep in sync, other than the results/steps/*.json this script writes after
every step (used by the final `report` step to assemble a combined summary
from whichever steps actually ran).

For local one-shot runs (not CI), use run_test.py / `make test` instead --
this script is intentionally low-level.

Usage:
    python3 ci_step.py setup --base-version 24.8.6.70 --label setup
    python3 ci_step.py upgrade-node --node ch1 --version 25.3.14.14 --label hop-25.3-ch1
    python3 ci_step.py verify-ddl --version 25.3.14.14 --label hop-25.3-verify-ddl
    python3 ci_step.py report
    python3 ci_step.py teardown

Real-data scenario (harness/real_data.py) -- separate CLI verbs, since it's
a different flow (load real data once, then hop):
    python3 ci_step.py setup-real-data --base-version 24.8.6.70 --label setup-real-data
    python3 ci_step.py load-real-data --label load-real-data
    python3 ci_step.py golden-snapshot --label golden-snapshot
    python3 ci_step.py verify-e2e --label base-verify-e2e
    python3 ci_step.py real-data-hop --version 25.3.14.14 --label rd-hop1
    python3 ci_step.py report
    python3 ci_step.py teardown-real-data

See .github/workflows/clickhouse_upgrade_test.yml for the full sequence.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import compose, real_data, report
from harness.scenarios import setup_step, step_ok, upgrade_node_step, verify_ddl_step

PROJECT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = PROJECT_DIR / "results"
STEPS_DIR = RESULTS_DIR / "steps"


def _save_step(label: str, result: dict) -> None:
    STEPS_DIR.mkdir(parents=True, exist_ok=True)
    safe = label.replace("/", "_")
    (STEPS_DIR / f"{safe}.json").write_text(json.dumps(result, indent=2, default=str))


def cmd_setup(args) -> int:
    result = setup_step(args.base_version, label=args.label)
    _save_step(args.label, result)
    ok = step_ok(result)
    print(f"[{args.label}] {'OK' if ok else 'FAILED: ' + str(result.get('error'))}")
    return 0 if ok else 1


def cmd_upgrade_node(args) -> int:
    step = upgrade_node_step(args.node, args.version, label=args.label)
    _save_step(args.label, step)
    ok = step_ok(step)
    print(f"[{args.label}] {'OK' if ok else 'PROBLEM DETECTED'}")
    print(json.dumps(step, indent=2, default=str))
    return 0 if ok else 1


def cmd_verify_ddl(args) -> int:
    result = verify_ddl_step(args.version, label=args.label)
    _save_step(result["label"], result)
    ok = step_ok(result)
    print(f"[{result['label']}] {'OK' if ok else 'FAILED: ' + str(result.get('error'))}")
    return 0 if ok else 1


def cmd_report(args) -> int:
    RESULTS_DIR.mkdir(exist_ok=True)
    steps = []
    if STEPS_DIR.exists():
        # Chronological order (steps run strictly sequentially within a CI
        # job), not alphabetical -- so mtime, not filename, decides order.
        for f in sorted(STEPS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime):
            steps.append(json.loads(f.read_text()))

    md = report.render_ci_steps_report(steps)
    (RESULTS_DIR / "report.md").write_text(md)
    (RESULTS_DIR / "report.json").write_text(json.dumps(steps, indent=2, default=str))
    print(md)

    gh_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_summary:
        with open(gh_summary, "a") as f:
            f.write(md)
            f.write("\n")

    # Individual upgrade-node/verify-ddl steps now run with
    # `continue-on-error: true` (see .github/workflows/clickhouse_upgrade_test.yml)
    # so that a failure partway through a hop doesn't abort the job before
    # the remaining nodes in that hop get a chance to upgrade too -- e.g. so
    # we can observe whether a lagging node's stuck replication queue clears
    # once it also reaches the new version. That means this step -- which
    # has no continue-on-error and runs with `if: always()` -- is now the
    # thing that actually has to fail the job when something stayed broken.
    any_fail = any(not step_ok(s) for s in steps)
    return 1 if any_fail else 0


def cmd_teardown(args) -> int:
    try:
        compose.down(volumes=True)
    except Exception as e:
        print(f"teardown warning (non-fatal): {e}")
    return 0


# ---------------------------------------------------------------------------
# Real-data scenario (harness/real_data.py) -- see the `real-data-upgrade`
# job in .github/workflows/clickhouse_upgrade_test.yml for the full step
# sequence these are wired into, and README.md for the design writeup.
# ---------------------------------------------------------------------------


def cmd_setup_real_data(args) -> int:
    result = real_data.setup_real_data_step(args.base_version, label=args.label)
    _save_step(args.label, result)
    ok = step_ok(result)
    print(f"[{args.label}] {'OK' if ok else 'FAILED: ' + str(result.get('error'))}")
    return 0 if ok else 1


def cmd_load_real_data(args) -> int:
    result = real_data.load_real_data_step(label=args.label)
    _save_step(args.label, result)
    ok = step_ok(result)
    print(f"[{args.label}] {'OK' if ok else 'FAILED'}")
    print(json.dumps(result, indent=2, default=str))
    return 0 if ok else 1


def cmd_golden_snapshot(args) -> int:
    result = real_data.take_golden_snapshot_step(label=args.label)
    _save_step(args.label, result)
    ok = step_ok(result)
    print(f"[{args.label}] {'OK' if ok else 'FAILED: nodes disagree before any upgrade -- ' + str(result.get('mismatched_tables'))}")
    return 0 if ok else 1


def cmd_verify_e2e(args) -> int:
    result = real_data.run_e2e_verify_step(args.label)
    _save_step(args.label, result)
    ok = step_ok(result)
    print(f"[{args.label}] {'OK' if ok else 'FAILED (exit ' + str(result.get('exit_code')) + ')'}")
    return 0 if ok else 1


def cmd_real_data_hop(args) -> int:
    result = real_data.real_data_hop_step(args.version, args.label)
    _save_step(args.label, result)
    ok = step_ok(result)
    print(f"[{args.label}] {'OK' if ok else 'PROBLEM DETECTED'}")
    print(json.dumps(result, indent=2, default=str))
    return 0 if ok else 1


def cmd_teardown_real_data(args) -> int:
    try:
        compose.down(volumes=True, files=real_data.COMPOSE_FILES)
    except Exception as e:
        print(f"teardown warning (non-fatal): {e}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_setup = sub.add_parser("setup", help="Tear down any previous state, bring up a fresh cluster, load schema + seed data")
    p_setup.add_argument("--base-version", required=True, help="ClickHouse image tag for all 3 nodes at startup")
    p_setup.add_argument("--label", default="setup", help="Step label, used as the results/steps/<label>.json filename")
    p_setup.set_defaults(func=cmd_setup)

    p_upgrade = sub.add_parser("upgrade-node", help="Recreate one node on a new image tag; other nodes keep running")
    p_upgrade.add_argument("--node", required=True, choices=["ch1", "ch2", "ch3"])
    p_upgrade.add_argument("--version", required=True, help="ClickHouse image tag to upgrade this node to")
    p_upgrade.add_argument("--label", required=True, help="Step label, e.g. hop-25.3-ch1")
    p_upgrade.set_defaults(func=cmd_upgrade_node)

    p_ddl = sub.add_parser("verify-ddl", help="Confirm an ON CLUSTER ALTER still propagates at the current version(s)")
    p_ddl.add_argument("--version", required=True, help="Version label for this checkpoint (used in the test column name)")
    p_ddl.add_argument("--label", default=None, help="Step label; defaults to verify-ddl-<version>")
    p_ddl.set_defaults(func=cmd_verify_ddl)

    p_report = sub.add_parser("report", help="Aggregate every results/steps/*.json into results/report.md + report.json")
    p_report.set_defaults(func=cmd_report)

    p_teardown = sub.add_parser("teardown", help="docker compose down -v")
    p_teardown.set_defaults(func=cmd_teardown)

    p_setup_rd = sub.add_parser("setup-real-data", help="Fresh cluster + schema only (no synthetic seed) -- real-data scenario")
    p_setup_rd.add_argument("--base-version", required=True, help="ClickHouse image tag for all 3 nodes at startup")
    p_setup_rd.add_argument("--label", default="setup-real-data")
    p_setup_rd.set_defaults(func=cmd_setup_real_data)

    p_load_rd = sub.add_parser("load-real-data", help="Bring up postgres/valkey/api/downloader/fastpath, wait for the one-shot containers -- run exactly once per CI run")
    p_load_rd.add_argument("--label", default="load-real-data")
    p_load_rd.set_defaults(func=cmd_load_real_data)

    p_golden = sub.add_parser("golden-snapshot", help="Snapshot real-data tables on all 3 nodes; persist as the baseline every later hop is diffed against")
    p_golden.add_argument("--label", default="golden-snapshot")
    p_golden.set_defaults(func=cmd_golden_snapshot)

    p_verify_e2e = sub.add_parser("verify-e2e", help="Run ooni/data#160's real pytest suite against the cluster's current state (no upgrade)")
    p_verify_e2e.add_argument("--label", default="verify-e2e")
    p_verify_e2e.set_defaults(func=cmd_verify_e2e)

    p_rd_hop = sub.add_parser("real-data-hop", help="Upgrade all 3 nodes to --version, then re-check integrity against the golden snapshot and re-run ooni/data's pytest suite")
    p_rd_hop.add_argument("--version", required=True, help="ClickHouse image tag to upgrade all 3 nodes to")
    p_rd_hop.add_argument("--label", required=True, help="Step label, e.g. rd-hop1")
    p_rd_hop.set_defaults(func=cmd_real_data_hop)

    p_teardown_rd = sub.add_parser("teardown-real-data", help="docker compose -f docker-compose.yml -f docker-compose.real-data.yml down -v")
    p_teardown_rd.set_defaults(func=cmd_teardown_real_data)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
