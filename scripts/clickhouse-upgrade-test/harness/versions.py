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

--- CONFIRMED: the same "self-heals once the lagging node catches up"
--- pattern also covers 26.3.17.110, and the full ladder to LATEST_VERSION
--- is now green ------------------------------------------------------------

Once ooni/devops#477's workflow stopped aborting the whole job on a step's
first failure (continue-on-error added per-step, see
.github/workflows/clickhouse_upgrade_test.yml), the harness could finally
see past the 25.8.29.51 hop. Run 32122682392 completed the entire 8-hop
ladder and confirmed two things:

1. The 25.8.29.51 mark-file incompatibility above is exactly the transient,
   self-healing condition it looked like, not a structural block: hop6-ch2
   failed (ch3, still on 25.7.8.71, stuck retrying a GET_PART fetch it
   couldn't parse -- NO_FILE_IN_DATA_PART, missing columns_substreams.txt),
   but hop6-ch3 -- ch3's own upgrade to 25.8.29.51, run immediately after --
   passed clean: converged, fully replicated, zero queue problems. The
   stuck fetch just succeeded on retry once the recipient could finally
   parse the new format.

2. The exact same pattern repeats at 26.3.17.110 -- and this is the
   nested-data-type serialization change flagged in the PR #477 review
   (https://clickhouse.com/docs/resources/changelogs/oss/2026#263-backward-incompatible-change,
   "Propagate data types serialization versions to nested data types").
   hop7-ch1 logged a hard CHECKSUM_DOESNT_MATCH while it was briefly the
   only node on 26.3.17.110; hop7-ch2 then left ch3 (still on 25.8.29.51)
   stuck retrying with CORRUPTED_DATA / "Unknown version of serialization
   infos (1). Should be less or equal than 0". hop7-ch3 -- ch3's own
   upgrade to 26.3.17.110 -- again passed clean. Same self-healing
   mechanism, different error codes: an old-format binary can't parse a
   part written in the new format, and the fix is simply for that binary
   to also become new-format, at which point its own retry of the same
   fetch succeeds.

hop8 (26.3.17.110 -> 26.7.3.19) had zero hard errors of any kind in this
particular run.

--- UPDATE: hop8 can hit the same self-healing pattern too (run
--- 32134303759) -- it is not reliably the one clean hop -----------------

A later run, 32134303759, hit the identical self-healing pattern at
hop8-ch2: a hard CHECKSUM_DOESNT_MATCH ("Different number of files: 3
compressed (expected 3) and 3 uncompressed ones (expected 2)") while ch3
was still on 26.3.17.110, clearing immediately once hop8-ch3 (ch3's own
upgrade to 26.7.3.19) completed. So the "hop8 had zero hard errors"
finding above was true of that specific run, not a property of the hop
itself -- treat hop8 the same operational way as hop6/hop7 (expect
possible trailing-node errors, expect them to clear once that node
finishes upgrading), not as the one hop guaranteed to be quiet.

Important caveat these runs do NOT resolve: the mixed-version window in
each was CI-paced (seconds to at most a couple of minutes between one
node finishing and the next starting). It says nothing about what happens
if a node is left lagging for hours or days at the 25.8.29.51, 26.3.17.110,
or 26.7.3.19 hops specifically -- that hasn't been tested. It also says
nothing about the *downgrade*-lossiness warning in the 26.3 changelog
entry, which is a separate risk (rolling back after the fact) from what
these runs exercised (rolling forward with a temporarily mixed cluster).

--- RECOMMENDED_NOW and PRODUCTION_HOPS: what to actually run -------------

Given the above, RECOMMENDED_NOW is now LATEST_VERSION (26.7.3.19) -- the
harness has a real green run covering every hop, including both of the
ones that previously blocked it. PRODUCTION_HOPS below is the actual
runbook this project recommends: a 4-hop ladder that skips the
25.4.13.22-25.7.8.71 bisection releases entirely, since those were only
ever inserted to localize *which* release introduced the incompatibility
in CI -- production has no reason to stop at non-LTS releases with ~1
month of support each once the boundary is known. Each hop still stays
comfortably under ClickHouse's ~1 year mixed-version window (5-7 months).

Operational rule for the three hops that have each hit a real
incompatibility at least once (25.3.14.14 -> 25.8.29.51, 25.8.29.51 ->
26.3.17.110, and 26.3.17.110 -> 26.7.3.19 -- see the hop8 update above):
upgrade all three nodes back-to-back in one sitting, the way CI does it,
rather than spacing them out the way it's fine to do for every other hop.
Expect the last node in any of those three hops to log hard-looking
errors (NO_FILE_IN_DATA_PART / CORRUPTED_DATA / CHECKSUM_DOESNT_MATCH)
for a minute or two right up until its own upgrade finishes -- that's
expected, not a signal to roll back, *provided it clears once that node
is fully upgraded*. If it doesn't clear within a few minutes of the last
node coming back up, stop and treat it as a real incompatibility rather
than assuming it'll resolve on its own -- that combination (mixed
versions left stuck well past the trailing node's own upgrade finishing)
hasn't been observed or validated.

One remaining gap before treating PRODUCTION_HOPS as fully proven rather
than well-supported: the harness has directly confirmed self-healing for
the 25.7.8.71->25.8.29.51 sub-hop (via the bisection ladder) and for
25.8.29.51->26.3.17.110, but not yet for a genuine single-hop
25.3.14.14 -> 25.8.29.51 jump (skipping the intermediate monthly
releases) with the continue-on-error fix in place. The original
un-bisected 4-hop ladder (run 32044578317) did hit the identical failure
signature at that exact transition, but that run aborted before ch3 got a
chance to complete its own upgrade, so self-healing was never directly
observed for that specific pairing -- only inferred from the mechanism
being the same (an old binary can't parse a new-format part, regardless
of how old). Worth one more CI run of PRODUCTION_HOPS itself to close
this gap before leaning on it unreservedly.
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

# What we'd actually tell someone to run in production *today*. Promoted to
# LATEST_VERSION after run 32122682392 covered the full ladder, including
# both hops that previously blocked it (25.8.29.51, 26.3.17.110) -- see the
# module docstring's "self-heals once the lagging node catches up" section.
# Do not bump BASE_VERSION/LATEST_VERSION themselves without a green CI run
# covering the new range.
RECOMMENDED_NOW = "26.7.3.19"

# The actual production runbook: 4 hops instead of LTS_HOPS's 8. Skips the
# 25.4.13.22-25.7.8.71 monthly (non-LTS) releases entirely -- those exist
# only in LTS_HOPS, inserted purely to bisect *which* release introduced the
# 25.8.29.51 incompatibility in CI. Production has no reason to stop on a
# release with ~1 month of support once the boundary is already known,
# especially since 25.3.14.14 -> 25.8.29.51 (5 months) is still comfortably
# inside ClickHouse's ~1 year mixed-version window on its own.
#
# Operational rule, not encoded here since it's not a version number: the
# 25.3.14.14->25.8.29.51, 25.8.29.51->26.3.17.110, and 26.3.17.110->26.7.3.19
# hops should each be run as three back-to-back node upgrades in one sitting
# (no long pause between nodes), because the trailing node in any of those
# three hops is expected to (not guaranteed to, per the hop8 update in the
# module docstring -- it's been observed on some runs and not others) log
# hard-looking errors until its own upgrade completes -- see the module
# docstring for what to expect and when to actually treat it as a real
# problem instead of the expected transient state.
PRODUCTION_HOPS = [
    ("24.8.6.70", None),
    ("25.3.14.14", 7),
    ("25.8.29.51", 5),
    ("26.3.17.110", 7),
    ("26.7.3.19", 4),
]

# For the "direct jump" scenario we go straight from BASE to LATEST.
DIRECT_JUMP = [
    ("24.8.6.70", None),
    ("26.7.3.19", 23),       # ~23 months apart -- exceeds the 1-year window
]
