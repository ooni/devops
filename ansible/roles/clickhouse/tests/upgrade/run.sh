#!/bin/bash
# Rolls a ClickHouse version bump out with the role, one host at a time (test_upgrade.py):
#   FROM_VERSION=24.8.6.70 TO_VERSION=25.3.14.14 ./run.sh
# Needs docker compose, ansible-playbook and PyYAML, and network access to
# packages.clickhouse.com; the packages are kept in cache/. With rootless podman, point
# DOCKER_HOST at its socket. KEEP=1 leaves the hosts running.
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE=${COMPOSE:-docker compose}
compose() { $COMPOSE -f compose.yml "$@"; }
journals() { for n in data1 data2 data3; do echo "--- $n"; compose exec -T $n journalctl -u clickhouse-server --no-pager -n 30 2>/dev/null; done; }
trap 'rc=$?; [ $rc = 0 ] || journals; [ -n "${KEEP:-}" ] || compose down -v --remove-orphans >/dev/null 2>&1' EXIT
compose down -v --remove-orphans >/dev/null 2>&1  # left from a run with KEEP=1
rm -rf out && mkdir -p out cache
if ! ansible-galaxy collection list community.docker 2>/dev/null | grep -q community.docker; then
  # the version the repo pins
  ansible-galaxy collection install -p cache/collections -r ../../../../requirements/ansible-galaxy.yml >/dev/null
  export ANSIBLE_COLLECTIONS_PATH="$PWD/cache/collections:${ANSIBLE_COLLECTIONS_PATH:-}"
fi
python3 test_upgrade.py
