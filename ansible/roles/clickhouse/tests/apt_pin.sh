#!/bin/bash
# With the role's pin file, apt's candidate for the ClickHouse packages from
# packages.clickhouse.com is the pinned version, not the newest release in the repo. When
# clickhouse_version is the newest, a pin to an older release is checked too, as the pin
# can't show otherwise.
set -euo pipefail
cd "$(dirname "$0")"
vars=../../../group_vars/clickhouse/vars.yml
version=$(sed -n 's/^clickhouse_version: *//p' $vars)
release=$(sed -n 's/^clickhouse_release_type: *//p' $vars); release=${release:-lts}
# the pin file as tasks/install-Debian.yml writes it, for a version given later
pin=$(python3 -c '
import yaml
task = next(t for t in yaml.safe_load(open("../tasks/install-Debian.yml")) if t.get("ansible.builtin.copy", {}).get("dest") == "/etc/apt/preferences.d/clickhouse")
print(task["ansible.builtin.copy"]["content"], end="")
')
docker run --rm -i -v "$PWD/..:/role:ro,z" -e VERSION="$version" -e RELEASE="$release" -e PIN="$pin" docker.io/library/debian:12 bash -s <<'SH'
set -euo pipefail
apt-get update -qq >/dev/null && apt-get install -y -qq ca-certificates >/dev/null
mkdir -p /etc/apt/keyrings && cp /role/files/clickhouse-repo-keyring.asc /etc/apt/keyrings/clickhouse.asc
echo "deb [signed-by=/etc/apt/keyrings/clickhouse.asc] https://packages.clickhouse.com/deb $RELEASE main" > /etc/apt/sources.list.d/clickhouse.list
apt-get update -qq >/dev/null
newest=$(apt-cache policy clickhouse-server | sed -n 's/^  Candidate: //p')
versions=("$VERSION")
if [ "$newest" = "$VERSION" ]; then
  versions+=("$(apt-cache madison clickhouse-server | awk '{print $3}' | sed -n 2p)")
fi
fail=0
for v in "${versions[@]}"; do
  printf "%s" "${PIN//\{\{ clickhouse_version \}\}/$v}" > /etc/apt/preferences.d/clickhouse
  for p in clickhouse-server clickhouse-client clickhouse-common-static; do
    c=$(apt-cache policy $p | sed -n 's/^  Candidate: //p')
    if [ "$c" = "$v" ]; then echo "ok   pinned to $v, $p: candidate $c (newest in the repo: $newest)"; else echo "FAIL pinned to $v, $p: candidate $c"; fail=1; fi
  done
done
exit $fail
SH
