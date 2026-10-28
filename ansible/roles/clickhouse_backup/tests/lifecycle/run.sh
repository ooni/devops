#!/bin/bash
# The backup's whole lifecycle (test_lifecycle.py): backups of production's schema by production's jobs,
# then restores after a lost replica, a lost data1, a lost cluster, and on a researcher's own server.
# Needs docker compose, python3-boto3 and python3-yaml. With rootless podman, point DOCKER_HOST at its
# socket. KEEP=1 leaves the containers running.
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE=${COMPOSE:-docker compose}
export PYTHONDONTWRITEBYTECODE=1  # no __pycache__ left in the role's files/
compose() { $COMPOSE -f compose.yml "$@"; }
trap 'rc=$?; [ $rc = 0 ] || compose logs --no-color --tail=100 runner data1 data2 data3; [ -n "${KEEP:-}" ] || compose down -v --remove-orphans >/dev/null 2>&1' EXIT
compose down -v --remove-orphans >/dev/null 2>&1  # left from a run with KEEP=1
compose up -d --build --quiet-pull
python3 test_lifecycle.py
