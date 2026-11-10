#!/bin/bash
# The production upgrade rehearsed on real data (test_live.py): main's ClickHouse, then this
# branch's role, then its clickhouse_version, one host at a time. Needs docker compose (or
# podman with DOCKER_HOST at its socket), ansible-playbook with community.docker, PyYAML, a
# ClickHouse with OONI data to sample (SAMPLE_CLIENT) and access to packages.clickhouse.com.
# KEEP=1 leaves the hosts running; out/report.md has the results.
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE=${COMPOSE:-docker compose}
compose() { $COMPOSE -f compose.yml "$@"; }
trap '[ -n "${KEEP:-}" ] || compose down -v --remove-orphans >/dev/null 2>&1' EXIT
compose down -v --remove-orphans >/dev/null 2>&1  # left from a run with KEEP=1
rm -rf out && mkdir -p out cache
python3 test_live.py
