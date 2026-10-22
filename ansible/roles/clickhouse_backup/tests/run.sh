#!/bin/bash
# Tests the clickhouse_backup role: renders its configs from the role's templates, checks the backup alerts
# (promtool) and their Alertmanager routes (amtool), runs the schedule tests, then test_e2e.py against the
# containers in compose.yml. Needs docker compose, python3 with boto3, and ansible-core. With rootless podman,
# point DOCKER_HOST at its socket. KEEP=1 leaves the containers running.
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE=${COMPOSE:-docker compose}
export PYTHONDONTWRITEBYTECODE=1  # no __pycache__ left in the role's files/
compose() { $COMPOSE -f compose.yml "$@"; }

echo "== rendering the configs"
rm -rf work && mkdir -p work/textfile
# The template looks up openobservatory.org's MX record for the mail server; render.yml sets one instead
sed '/lookup(.dig./d' ../../prometheus_alertmanager/templates/alertmanager.yml > work/alertmanager.yml.j2
ansible-playbook -i localhost, render.yml > work/render.log || { cat work/render.log; exit 1; }

echo "== alert rules and routes"
compose run --rm --no-deps --entrypoint promtool prometheus test rules /etc/prometheus/alert_rules_test.yml
compose run --rm --no-deps --entrypoint amtool alertmanager check-config /etc/alertmanager/alertmanager.yml
route() {  # alert labels, receiver it must reach
  compose run --rm --no-deps --entrypoint amtool alertmanager config routes test \
    --config.file=/etc/alertmanager/alertmanager.yml --verify.receivers="$2" $1
}
route "alertname=ClickHouseBackupCompleted instance=data3 backup=measurements" slack-notice
route "alertname=ClickHouseBackupFailed instance=data3 backup=measurements table=fastpath" team-all

echo "== schedule"
python3 -m unittest test_schedule

echo "== end to end"
[ -n "${KEEP:-}" ] || trap 'compose down -v --remove-orphans >/dev/null 2>&1' EXIT
compose up -d --build --quiet-pull
python3 test_e2e.py
