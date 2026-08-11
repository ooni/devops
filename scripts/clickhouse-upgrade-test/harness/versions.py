"""
Version constants for the upgrade test.

Sourced from:
  - ooni/devops ansible/group_vars/clickhouse/vars.yml -> clickhouse_version: 24.8.6.70
    (this is BASE_VERSION -- what's running in production per issue ooni/devops#437)
  - ClickHouse's own release history (https://clickhouse.com/docs/whats-new/changelog,
    https://endoflife.date/clickhouse) as of 2026-08-10:

      24.8.6.70    LTS, released 2024-08  <- current prod version
      25.3.14.14   LTS, released 2025-03-20
      25.8.29.51   LTS, released 2025-08-29
      26.3.17.110  LTS, released 2026-03-26
      26.7.3.19    latest stable, released 2026-07-22  <- upgrade target

ClickHouse documents a ~1 year mixed-version compatibility window for
replicated clusters (https://clickhouse.com/docs/operations/update): nodes
more than a year apart in version should not be run together mid-upgrade.
BASE_VERSION -> LATEST_VERSION spans ~23 months, so a single-hop rolling
upgrade is out of that window; each LTS_HOPS step individually stays inside
it (5-7 months apart).
"""

BASE_VERSION = "24.8.6.70"        # current production version (issue #437)
LATEST_VERSION = "26.7.3.19"      # latest stable as of 2026-08-10

# Each entry: (version, months_since_previous) -- used for the staged-upgrade
# scenario, walking one LTS release at a time up to the latest stable.
LTS_HOPS = [
    ("24.8.6.70", None),     # starting point
    ("25.3.14.14", 7),
    ("25.8.29.51", 5),
    ("26.3.17.110", 7),
    ("26.7.3.19", 4),        # final hop lands on latest stable (not itself LTS)
]

# For the "direct jump" scenario we go straight from BASE to LATEST.
DIRECT_JUMP = [
    ("24.8.6.70", None),
    ("26.7.3.19", 23),       # ~23 months apart -- exceeds the 1-year window
]
