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

--- CONFIRMED: the 25.3.14.14 -> 25.8.29.51 incompatibility is pinned to
--- exactly 25.8.29.51, via bisection in real CI -----------------------------

A real staged-upgrade CI run (ooni/devops#477, run 32044578317) hit a hard
failure partway through this hop, well before ever reaching 26.3: with
ch1+ch2 already on 25.8.29.51 and ch3 still on 25.3.14.14, ch3's
replication queue got stuck fetching a part with `Code: 79.
DB::Exception: Unknown mark file extension: '4'. (INCORRECT_FILE_NAME)`.

To find out whether that was specific to 25.8.29.51 or something that
crept in gradually across the whole 25.3->25.8 span, LTS_HOPS below was
expanded to walk every monthly (non-LTS) stable release in between
(25.4.13.22, 25.5.11.15, 25.6.13.41, 25.7.8.71 -- versions/dates from
https://endoflife.date/api/clickhouse.json) and re-run. Result (run
32047534149): **24.8.6.70 -> 25.3.14.14 -> 25.4.13.22 -> 25.5.11.15 ->
25.6.13.41 -> 25.7.8.71 all upgrade cleanly, node by node, zero hard
errors.** The failure re-appears exactly and only at the
25.7.8.71 -> 25.8.29.51 transition -- same failure family, this time
`Code: 226. NO_FILE_IN_DATA_PART: No columns_substreams.txt in part
all_17_17_1` while fetching a part whose mark file has the new `.cmrk4`
extension. So this is not a gradual drift-of-versions problem; it's a
single version boundary: 25.8.29.51 changes the on-disk compact-part
format (adding a columns_substreams.txt manifest + new mark-file
extension) in a way that no earlier binary in this range can read.

Corroborating (not certain -- this wasn't ourselves confirmed against the
official changelog text, see PR discussion for the repeated failed
attempts to fetch it) evidence: a v25.12 changelog entry found earlier
reads "Enable advanced shared data for JSON by default... after that
change downgrade to versions before 25.8 will be not possible, because
these versions won't be able to read new data parts with JSON column."
That note is scoped to JSON columns and to *downgrading*, but it names
25.8 as the version where this substream-based part-serialization
infrastructure was introduced. Our `citizenlab` table has no JSON column
at all, so what this bisection run hit is most likely that same
infrastructure applying to plain MergeTree parts generally, not something
JSON-specific -- consistent with, though not proof of, the same root
cause.

RECOMMENDED_NOW is the path this project currently suggests actually
running in production long-term. It's deliberately still 25.3.14.14 (an
LTS release, ~1 year of support) rather than 25.7.8.71, even though
25.4.13.22 through 25.7.8.71 are now confirmed clean: those are all
non-LTS monthly releases with only ~1 month of support each before being
superseded, so "confirmed safe to upgrade through" is not the same claim
as "a sensible place to actually stay". LTS_HOPS (used by the "staged" CI
scenario) still walks all the way to LATEST_VERSION -- the whole point of
this harness is to keep building confidence in later legs via testing
*before* they're recommended for prod, not to stop testing them. Treat a
green staged-upgrade run as "the harness found nothing wrong going this
far", not as "go ahead and do it in production now".
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
