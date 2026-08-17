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

--- STATUS: 25.3.14.14 -> 25.8.29.51 is UNDER INVESTIGATION, not recommended
--- yet, per a real (not hypothetical) CI failure ---------------------------

A real run of the staged-upgrade CI job (ooni/devops#477, run 32044578317)
hit a hard failure partway through exactly this hop, well before ever
reaching 26.3: with ch1+ch2 already on 25.8.29.51 and ch3 still on
25.3.14.14, ch3's replication queue got stuck fetching a part from a peer
with `Code: 79. DB::Exception: Unknown mark file extension: '4'.
(INCORRECT_FILE_NAME)` -- i.e. once a merge happens on a 25.8.29.51 node,
it writes a mark-file format that a 25.3.14.14 node's binary cannot parse
at all, not something that clears up with more retries. This makes the old
replica correctly non-gating-transient-immune but genuinely stuck until it,
too, is upgraded -- and we don't yet know from that run alone whether that
stuck state clears the moment ch3 catches up, or whether it's evidence this
specific hop can't be done as a slow rolling upgrade at all.

LTS_HOPS below has been expanded to walk the monthly stable releases
between 25.3.14.14 and 25.8.29.51 (25.4.13.22, 25.5.11.15, 25.6.13.41,
25.7.8.71 -- versions and dates from https://endoflife.date/api/clickhouse.json)
instead of jumping straight from one LTS to the next, specifically to
bisect which single monthly release first introduces the incompatible mark
format. Until that's identified (and ideally the exact changelog entry for
it is found -- attempts to fetch clickhouse.com's changelog for this range
have so far been unsuccessful, see PR discussion), RECOMMENDED_NOW is
pulled back to the one hop that has actually run clean end-to-end in real
CI so far.

RECOMMENDED_NOW is the path this project currently suggests actually running
in production. LTS_HOPS (used by the "staged" CI scenario) still walks all
the way to LATEST_VERSION -- the whole point of this harness is to keep
building confidence in later legs via testing *before* they're recommended
for prod, not to stop testing them. Treat a green staged-upgrade run as "the
harness found nothing wrong going this far", not as "go ahead and do it in
production now".
"""

BASE_VERSION = "24.8.6.70"        # current production version (issue #437)
LATEST_VERSION = "26.7.3.19"      # latest stable as of 2026-08-10

# Each entry: (version, months_since_previous) -- used for the staged-upgrade
# scenario. 25.4.13.22 through 25.7.8.71 are the monthly (non-LTS) stable
# releases inserted between the 25.3 and 25.8 LTS releases specifically to
# bisect the mark-file incompatibility described above -- see that section
# for why. Everything from 26.3.17.110 onward is still the coarser
# one-LTS-at-a-time ladder; if bisection turns up a similar mid-range issue
# there, expand those the same way.
LTS_HOPS = [
    ("24.8.6.70", None),     # starting point
    ("25.3.14.14", 7),
    ("25.4.13.22", 1),       # bisection step -- see module docstring
    ("25.5.11.15", 1),       # bisection step
    ("25.6.13.41", 1),       # bisection step
    ("25.7.8.71", 1),        # bisection step
    ("25.8.29.51", 1),
    ("26.3.17.110", 7),
    ("26.7.3.19", 4),        # final hop lands on latest stable (not itself LTS)
]

# What we'd actually tell someone to run in production *today*. Pulled back
# to 25.3.14.14 -- the last hop that has actually completed clean in a real
# CI run -- until the 25.3->25.8 mark-file incompatibility above is
# understood. See the module docstring section above; do not bump this
# without a green CI run covering the hop(s) being added.
RECOMMENDED_NOW = "25.3.14.14"

# Everything past RECOMMENDED_NOW: still tested by LTS_HOPS, not yet
# recommended for production. Kept as its own list so a future decision to
# promote part of this doesn't require re-deriving which hops are "new" vs
# already-recommended.
PENDING_FURTHER_VALIDATION = [
    ("25.4.13.22", 1),
    ("25.5.11.15", 1),
    ("25.6.13.41", 1),
    ("25.7.8.71", 1),
    ("25.8.29.51", 1),
    ("26.3.17.110", 7),
    ("26.7.3.19", 4),
]

# For the "direct jump" scenario we go straight from BASE to LATEST.
DIRECT_JUMP = [
    ("24.8.6.70", None),
    ("26.7.3.19", 23),       # ~23 months apart -- exceeds the 1-year window
]
