#!/bin/bash
# Adds a replica to the cluster and removes it again through vars and the roles
# (test_replicas.py). Needs docker compose, ansible-playbook and PyYAML. With rootless
# podman, point DOCKER_HOST at its socket. KEEP=1 leaves the containers running.
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE=${COMPOSE:-docker compose}
compose() { $COMPOSE -f compose.yml "$@"; }
trap 'rc=$?; [ $rc = 0 ] || compose logs --no-color --tail=40; [ -n "${KEEP:-}" ] || compose down -v --remove-orphans >/dev/null 2>&1' EXIT
compose down -v --remove-orphans >/dev/null 2>&1  # left from a run with KEEP=1
rm -rf out && mkdir out
python3 test_replicas.py
