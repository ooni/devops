#!/usr/bin/env python3
"""
Entry point for the ClickHouse upgrade test.

Usage:
    python3 run_test.py --scenario staged     # recommended path: LTS-hop rolling upgrade
    python3 run_test.py --scenario direct     # naive single-hop rolling upgrade
    python3 run_test.py --scenario both       # run both, one after another (default)

Requires: Docker + the Docker Compose plugin, and network access to pull
clickhouse/clickhouse-server images from Docker Hub (the sandbox this
harness was authored in could not reach Docker Hub -- see README.md).

Writes a Markdown + JSON report to results/report.md and results/report.json.
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import compose, report
from harness.scenarios import scenario_direct_jump, scenario_staged_lts
from harness.versions import BASE_VERSION, LATEST_VERSION

RESULTS_DIR = Path(__file__).resolve().parent / "results"


def log(msg: str) -> None:
    ts = datetime.datetime.utcnow().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=["staged", "direct", "both"], default="both")
    parser.add_argument("--keep-up", action="store_true", help="Don't tear down the cluster when done")
    args = parser.parse_args()

    log("Validating docker-compose.yml (no image pull required for this check)...")
    try:
        compose.config_check()
    except Exception as e:
        log(f"docker compose config failed -- fix docker-compose.yml before running: {e}")
        return 2

    results = {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "base_version": BASE_VERSION,
        "latest_version": LATEST_VERSION,
        "scenarios": [],
    }

    scenarios_to_run = []
    if args.scenario in ("staged", "both"):
        scenarios_to_run.append(("staged", scenario_staged_lts))
    if args.scenario in ("direct", "both"):
        scenarios_to_run.append(("direct", scenario_direct_jump))

    exit_code = 0
    for name, fn in scenarios_to_run:
        log(f"=== Running scenario: {name} ===")
        try:
            scenario_result = fn(log=log)
            results["scenarios"].append(scenario_result)
            log(f"=== Scenario {name} verdict: {scenario_result['verdict']} ===")
            if scenario_result["verdict"].startswith("FAIL"):
                exit_code = 1
        except Exception as e:
            log(f"Scenario {name} raised an exception: {e}")
            traceback.print_exc()
            results["scenarios"].append({"name": name, "verdict": f"ERROR: {e}", "steps": []})
            exit_code = 1

    RESULTS_DIR.mkdir(exist_ok=True)
    (RESULTS_DIR / "report.json").write_text(json.dumps(results, indent=2, default=str))
    report.write_report(results, RESULTS_DIR / "report.md")
    log(f"Report written to {RESULTS_DIR / 'report.md'} and {RESULTS_DIR / 'report.json'}")

    if not args.keep_up:
        log("Tearing down cluster (pass --keep-up to leave it running)...")
        compose.down(volumes=True)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
