#!/bin/bash
# Tests the role's SQL-driven users, quotas and grants (test_sql_objects.py) and its apt pin
# (apt_pin.sh). Needs docker compose, ansible-playbook and PyYAML. With rootless podman,
# point DOCKER_HOST at its socket. KEEP=1 leaves the containers running.
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE=${COMPOSE:-docker compose}
compose() { $COMPOSE -f compose.yml "$@"; }
trap 'rc=$?; [ $rc = 0 ] || compose logs --no-color --tail=50; [ -n "${KEEP:-}" ] || compose down -v --remove-orphans >/dev/null 2>&1' EXIT
compose down -v --remove-orphans >/dev/null 2>&1  # left from a run with KEEP=1
rm -rf out && mkdir out
python3 test_sql_objects.py render
ANSIBLE_NOCOLOR=1 ansible-playbook -i localhost, render.yml > out/ansible-render.log || { tail -40 out/ansible-render.log; exit 1; }
compose up -d --quiet-pull
python3 test_sql_objects.py
[ -n "${SKIP_APT_PIN:-}" ] || ./apt_pin.sh
