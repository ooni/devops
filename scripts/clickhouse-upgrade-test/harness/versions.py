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

--- 26.3 is treated as a separate, not-yet-recommended phase --------------

Per review on ooni/devops#477 (hellais): 26.3 ships a backward-incompatible
change to how nested data types serialize
(https://clickhouse.com/docs/resources/changelogs/oss/2026#263-backward-incompatible-change,
"Propagate data types serialization versions to nested data types") that the
changelog itself warns can make *downgrading* after upgrading past it lossy.
Since OONI's rollback plan for any bad upgrade is "downgrade the node back",
crossing 26.3 forecloses that option -- so unlike every other hop here, it
should not be treated as routine until it's been soaked for a while.

RECOMMENDED_NOW is the path this project currently suggests actually running
in production: stop at 25.8.29.51, the last LTS strictly before 26.3.
LTS_HOPS (used by the "staged" CI scenario) still walks all the way to
LATEST_VERSION -- the whole point of this harness is to keep building
confidence in the 26.3+ leg via testing *before* it's recommended for prod,
not to stop testing it. Treat a green staged-upgrade run as "the harness
found nothing wrong with going past 26.3", not as "go ahead and do it in
production now".
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

# What we'd actually tell someone to run in production *today* -- stops one
# LTS short of 26.3's downgrade-losing-data serialization change. See the
# module docstring section above. Not consumed by the CI workflow (which
# still exercises the full LTS_HOPS ladder for validation purposes); this
# is the number the README's recommendation and any runbook should quote.
RECOMMENDED_NOW = "25.8.29.51"

# The 26.3+ leg: still tested, not yet recommended for production until it's
# been through more validation (see module docstring). Kept as its own list
# so a future decision to promote it doesn't require re-deriving which hops
# are "new" vs already-recommended.
PENDING_FURTHER_VALIDATION = [
    ("26.3.17.110", 7),
    ("26.7.3.19", 4),
]

# For the "direct jump" scenario we go straight from BASE to LATEST.
DIRECT_JUMP = [
    ("24.8.6.70", None),
    ("26.7.3.19", 23),       # ~23 months apart -- exceeds the 1-year window
]
