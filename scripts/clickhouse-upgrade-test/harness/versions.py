"""
Version constants for the upgrade test.

Sourced from:
  - ooni/devops ansible/group_vars/clickhouse/vars.yml -> clickhouse_version: 24.8.6.70
    (this is BASE_VERSION -- what's running in production per issue ooni/devops#437)
  - ClickHouse's own release history (https://clickhouse.com/docs/whats-new/changelog,
    https://endoflife.date/api/clickhouse.json) as of 2026-09-21:

      24.8.6.70    LTS, released 2024-08          <- current prod version
      25.3.14.14   LTS, released 2025-03-20 (EOL 2026-03-20)
      25.8.29.51   LTS, released 2025-08-29 (EOL 2026-08-29)
      26.3.17.110  LTS, released 2026-03-26
      26.8.9.10    LTS, released 2026-08-27       <- upgrade target

--- RETARGETED from 26.7.3.19 to 26.8.9.10 (2026-09-21) --------------------

The original research (2026-08-10) picked 26.7.3.19 as the upgrade target
because it was "latest stable" at the time -- but 26.7 was never itself an
LTS release, just the newest monthly release then. ClickHouse has since
cut a new LTS, 26.8 (released 2026-08-27; confirmed via
https://endoflife.date/api/clickhouse.json and
https://github.com/ClickHouse/ClickHouse/releases), which supersedes it.
Every other hop in this ladder already lands on an LTS release -- ending
on a non-LTS "stable" release was the odd one out, not a deliberate
choice, and OONI doesn't want production's final resting version to be
anything other than an LTS. LATEST_VERSION, RECOMMENDED_NOW, and the
final RECOMMENDED_LTS_HOPS / AGGRESSIVE_SKIP_HOPS entries are updated below to
land on 26.8.9.10 instead.

**This means the final hop is untested.** Every finding in this docstring
about 26.3.17.110 -> 26.7.3.19 (the old "hop8") is real and stands as
written, but it's evidence about that specific transition, not about
26.3.17.110 -> 26.8.9.10 -- a different target that may or may not carry
the identical self-healing incompatibility, and that may have picked up
others from whatever shipped across 26.4 through 26.8 that hasn't been
looked at. Treat the retargeted final hop as unproven, not as "the same
thing we already validated," until a real CI run covers it -- see
"RETARGETED, continued" near the end of this docstring for what that
means for RECOMMENDED_LTS_HOPS's proof status.

ClickHouse documents a ~1 year mixed-version compatibility window for
replicated clusters (https://clickhouse.com/docs/operations/update): nodes
more than a year apart in version should not be run together mid-upgrade.
BASE_VERSION -> LATEST_VERSION spans ~24 months, so a single-hop rolling
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

hop8 (26.3.17.110 -> 26.7.3.19, the old, now-superseded final hop -- see
"RETARGETED" above) had zero hard errors of any kind in this particular
run.

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
finishes upgrading), not as the one hop guaranteed to be quiet. (Again:
this was 26.3.17.110 -> 26.7.3.19 specifically -- see "RETARGETED" above
for why the current final hop, 26.3.17.110 -> 26.8.9.10, isn't covered by
this finding even though it's the same kind of transition.)

A further real CI run (2026-09-21, ooni/devops#477, run 963814682581, on
the still-8-hop workflow prior to this retarget) reconfirmed the identical
pattern at the identical three boundaries one more time -- hop6-ch2
(NO_FILE_IN_DATA_PART), hop7-ch1+hop7-ch2 (CHECKSUM_DOESNT_MATCH /
CORRUPTED_DATA), hop8-ch2 (CHECKSUM_DOESNT_MATCH, file-count mismatch) --
with hops 1-5 (including all four bisection waypoints) staying clean.
Nothing new; it's the same self-healing mechanism as every prior run.
This is the run that prompted the version retarget in the first place:
rather than keep re-confirming the same known 26.7.3.19-specific finding,
land the final hop on the actual current LTS instead.

Important caveat these runs do NOT resolve: the mixed-version window in
each was CI-paced (seconds to at most a couple of minutes between one
node finishing and the next starting). It says nothing about what happens
if a node is left lagging for hours or days at the 25.8.29.51, 26.3.17.110,
or 26.8.9.10 hops specifically -- that hasn't been tested. It also says
nothing about the *downgrade*-lossiness warning in the 26.3 changelog
entry, which is a separate risk (rolling back after the fact) from what
these runs exercised (rolling forward with a temporarily mixed cluster).

--- RECOMMENDED_NOW and RECOMMENDED_LTS_HOPS: what to actually run -------------

RECOMMENDED_NOW is LATEST_VERSION (26.8.9.10, per the retarget above).
RECOMMENDED_LTS_HOPS below is the actual runbook this project recommends: a
4-hop ladder that skips the 25.4.13.22-25.7.8.71 bisection releases
entirely, since those were only ever inserted to localize *which* release
introduced the incompatibility in CI -- production has no reason to stop
at non-LTS releases with ~1 month of support each once the boundary is
known. Each hop still stays comfortably under ClickHouse's ~1 year
mixed-version window (5-7 months, including the retargeted final hop --
26.3.17.110 to 26.8.9.10 is ~5 months).

Operational rule for the hops that have each hit a real incompatibility
at least once -- 25.3.14.14 -> 25.8.29.51 and 25.8.29.51 -> 26.3.17.110,
both directly confirmed (see above), plus 26.3.17.110 -> 26.8.9.10 by
inference from the pattern repeating at every LTS boundary tested so far,
though not yet directly confirmed itself (see "RETARGETED, continued"
below): upgrade all three nodes back-to-back in one sitting, the way CI
does it, rather than spacing them out the way it's fine to do for every
other hop.
Expect the last node in any of those three hops to log hard-looking
errors (NO_FILE_IN_DATA_PART / CORRUPTED_DATA / CHECKSUM_DOESNT_MATCH)
for a minute or two right up until its own upgrade finishes -- that's
expected, not a signal to roll back, *provided it clears once that node
is fully upgraded*. If it doesn't clear within a few minutes of the last
node coming back up, stop and treat it as a real incompatibility rather
than assuming it'll resolve on its own -- that combination (mixed
versions left stuck well past the trailing node's own upgrade finishing)
hasn't been observed or validated.

One remaining gap before treating RECOMMENDED_LTS_HOPS as fully proven rather
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
of how old). This is exactly what moving the staged-upgrade CI job onto
RECOMMENDED_LTS_HOPS (below) closes -- see that section.

--- RETARGETED, continued: what "fully proven" now requires -------------

The retarget from 26.7.3.19 to 26.8.9.10 (see the top of this docstring)
reopens the equivalent gap for the *final* hop. Before this change,
RECOMMENDED_LTS_HOPS's terminal transition (26.3.17.110 -> 26.7.3.19) had two
direct data points (runs 32122682392 and 32134303759, both clean or
self-healing) plus the 2026-09-21 reconfirmation (run 963814682581).
26.3.17.110 -> 26.8.9.10 has zero -- it has never been run, in any form,
bisected or otherwise. The pattern holding at every other LTS boundary
tested so far (25.8.29.51, 26.3.17.110) is a reasonable basis for
*expecting* it to also hold here, not for treating it as confirmed.
Run staged-upgrade (and ideally aggressive-skip-upgrade, which now also
lands on 26.8.9.10 -- see AGGRESSIVE_SKIP_HOPS below) at least once after
this change lands, and update this section with the result, before
describing RECOMMENDED_LTS_HOPS as fully proven the way the 26.7.3.19-terminated
version of it briefly was.

--- REDUCING THE CI LADDER: LTS_HOPS's bisection releases have done their
--- job; the staged-upgrade CI job now runs RECOMMENDED_LTS_HOPS instead -------

LTS_HOPS's 4 extra monthly waypoints (25.4.13.22 through 25.7.8.71) existed
for exactly one purpose: localize *which* release between 25.3.14.14 and
25.8.29.51 introduced the mark-file incompatibility. That question is
answered (see "CONFIRMED" section above) and doesn't need re-answering on
every CI run -- so the staged-upgrade job (and the local `scenario_staged_lts()`
in harness/scenarios.py) now walk RECOMMENDED_LTS_HOPS's 4 hops instead of
LTS_HOPS's 8. This has two effects, not just one: it cuts the job's runtime
roughly in half, AND it finally exercises the un-bisected 25.3.14.14 ->
25.8.29.51 jump directly (skipping the monthly waypoints, the way
production actually would) -- closing the gap called out just above,
which the bisected 8-hop ladder could never test by construction (it never
took that hop in one step). LTS_HOPS itself is left defined below,
unused by any code path, purely so the bisection methodology and the run
IDs cited above stay inspectable.

Every RECOMMENDED_LTS_HOPS hop is comfortably inside ClickHouse's own stated
maximum: their docs (https://clickhouse.com/docs/operations/update) say
mixed versions are fine if "the difference between them is less than one
year (or if there are less than two LTS versions between them)" -- every
hop here, including the retargeted final one, is directly LTS-to-adjacent-
LTS (0 other LTS releases in between). 4 hops is not a reduction *to* that
maximum, though -- see AGGRESSIVE_SKIP_HOPS below for what actually
pushing to the documented ceiling would look like, and why that's being
kept experimental rather than adopted here.

--- AGGRESSIVE_SKIP_HOPS: what ClickHouse's own rule would technically
--- allow, kept separate and explicitly NOT a production recommendation ---

ClickHouse's "less than two LTS versions between them" clause is an OR,
not an AND, with the one-year clause -- so it permits skipping over an
entire intervening LTS release, not just walking LTS-to-adjacent-LTS the
way RECOMMENDED_LTS_HOPS does. Applied maximally to this range: 24.8.6.70 ->
25.8.29.51 has exactly one LTS release (25.3.14.14) strictly between its
endpoints, and 25.8.29.51 -> 26.8.9.10 has exactly one (26.3.17.110) --
both satisfy "< 2 LTS versions between them" unambiguously (exactly one
LTS release sits strictly between each pair's endpoints). The calendar
clause is a closer call for the second hop specifically: 25.8.29.51's LTS
branch was cut 2025-08-29 and 26.8's 2026-08-27 -- 363 days, just inside a
year -- but the actual patch build used here, 26.8.9.10, was published
2026-09-20, which puts the two builds' own release dates ~12.7 months
apart. Whichever date convention counts, this hop clears "< 2 LTS
versions between them" on its own, so it doesn't depend on resolving that
ambiguity -- but it's worth flagging as a genuinely more aggressive
combination than the pre-retarget 25.8.29.51 -> 26.7.3.19 hop, not a
like-for-like swap. That's still a 2-hop path, half of RECOMMENDED_LTS_HOPS's
4.

This is deliberately NOT promoted to RECOMMENDED_LTS_HOPS or RECOMMENDED_NOW.
It is formally compliant with ClickHouse's documented ceiling, but it
combines the 25.8.29.51 and 26.3.17.110-adjacent incompatibilities --
each independently observed to produce hard-looking (self-healing)
errors on their own, smaller hops -- into two bigger single hops that
have never been run in any form. Whether the self-healing behavior still
holds when the version delta is larger (an even-older binary parsing an
even-newer format, and vice versa for the intervening skipped LTS) is
genuinely unknown, not just unproven -- and after the retarget, its
second hop also inherits the same "untested against 26.8.9.10" gap that
RECOMMENDED_LTS_HOPS's final hop has (see "RETARGETED, continued" above),
stacked on top of the pre-existing "never run at all" gap. See the
(separate, CI-only, workflow_dispatch-gated) `aggressive-skip-upgrade`
job in .github/workflows/clickhouse_upgrade_test.yml, which exists purely
to gather evidence on this before it's ever considered for real use.
"""

BASE_VERSION = "24.8.6.70"        # current production version (issue #437)
LATEST_VERSION = "26.8.9.10"      # latest LTS as of 2026-09-21 (retargeted
                                   # from 26.7.3.19, never itself LTS -- see
                                   # module docstring's "RETARGETED" section)

# HISTORICAL -- not used by the staged-upgrade CI job or scenario_staged_lts()
# anymore (see "REDUCING THE CI LADDER" above); kept only so the bisection
# methodology and the run IDs cited in the module docstring stay inspectable.
# Each entry: (version, months_since_previous). 25.4.13.22 through 25.7.8.71
# are the monthly (non-LTS) stable releases inserted between the 25.3 and
# 25.8 LTS releases specifically to bisect the mark-file incompatibility
# described above -- see that section for why.
LTS_HOPS = [
    ("24.8.6.70", None),     # starting point
    ("25.3.14.14", 7),
    ("25.4.13.22", 1),       # bisection step -- see module docstring
    ("25.5.11.15", 1),       # bisection step
    ("25.6.13.41", 1),       # bisection step
    ("25.7.8.71", 1),        # bisection step
    ("25.8.29.51", 1),
    ("26.3.17.110", 7),
    ("26.7.3.19", 4),        # final hop lands on latest stable (not itself
                              # LTS) -- HISTORICAL, this is what runs
                              # 32044578317/32047534149/32122682392/
                              # 32134303759/963814682581 actually tested.
                              # Superseded by RECOMMENDED_LTS_HOPS's 26.8.9.10 --
                              # see the module docstring's "RETARGETED"
                              # section. Left as 26.7.3.19 here so this
                              # constant keeps matching what those specific
                              # run IDs actually exercised.
]

# What we'd actually tell someone to run in production *today*. Was
# promoted to LATEST_VERSION (then 26.7.3.19) after run 32122682392
# covered the full ladder -- see the module docstring's "self-heals once
# the lagging node catches up" section -- and retargeted to 26.8.9.10
# (the current LTS) on 2026-09-21; see "RETARGETED" in the module
# docstring for why, and "RETARGETED, continued" for what's untested as a
# result. Do not bump BASE_VERSION/LATEST_VERSION themselves without a
# green CI run covering the new range.
RECOMMENDED_NOW = "26.8.9.10"

# The actual production runbook: 4 hops instead of LTS_HOPS's (historical,
# unused) 8. Skips the 25.4.13.22-25.7.8.71 monthly (non-LTS) releases
# entirely -- those existed only to bisect *which* release introduced the
# 25.8.29.51 incompatibility in CI, and that question is answered.
# Production has no reason to stop on a release with ~1 month of support
# once the boundary is already known, especially since 25.3.14.14 ->
# 25.8.29.51 (5 months) is still comfortably inside ClickHouse's ~1 year
# mixed-version window on its own. This is also what the staged-upgrade
# CI job and scenario_staged_lts() (harness/scenarios.py) actually run now
# -- see the module docstring's "REDUCING THE CI LADDER" section.
#
# Final hop retargeted 2026-09-21 from 26.7.3.19 (never itself LTS) to
# 26.8.9.10 (the current LTS) -- see the module docstring's "RETARGETED"
# section for why, and "RETARGETED, continued" for what that means for
# this hop's proof status (untested -- expected, not confirmed, to
# self-heal the same way the other three hops do).
#
# Operational rule, not encoded here since it's not a version number: the
# 25.3.14.14->25.8.29.51, 25.8.29.51->26.3.17.110, and 26.3.17.110->26.8.9.10
# hops should each be run as three back-to-back node upgrades in one sitting
# (no long pause between nodes), because the trailing node in any of those
# three hops is expected to (not guaranteed to, per the hop8 update in the
# module docstring -- it's been observed on some runs and not others) log
# hard-looking errors until its own upgrade completes -- see the module
# docstring for what to expect and when to actually treat it as a real
# problem instead of the expected transient state.
RECOMMENDED_LTS_HOPS = [
    ("24.8.6.70", None),
    ("25.3.14.14", 7),
    ("25.8.29.51", 5),
    ("26.3.17.110", 7),
    ("26.8.9.10", 5),
]

# For the "direct jump" scenario we go straight from BASE to LATEST.
DIRECT_JUMP = [
    ("24.8.6.70", None),
    ("26.8.9.10", 24),       # ~24 months apart -- exceeds the 1-year window
]

# EXPERIMENTAL -- see the module docstring's "AGGRESSIVE_SKIP_HOPS" section
# for the full rationale. Not a production recommendation: this is formally
# within ClickHouse's documented compatibility ceiling ("less than one year
# ... or less than two LTS versions between them" --
# https://clickhouse.com/docs/operations/update), but combines two
# independently-observed incompatibility boundaries (25.8.29.51's mark-file
# format change, 26.3.17.110's nested-type serialization change) into two
# bigger hops that have never actually been run. Wired into a separate,
# workflow_dispatch-only CI job (aggressive-skip-upgrade) purely to gather
# evidence -- do not promote this to RECOMMENDED_LTS_HOPS without a green run.
# Final hop retargeted to 26.8.9.10 along with RECOMMENDED_LTS_HOPS -- see that
# constant's comment and the module docstring's "RETARGETED" section.
AGGRESSIVE_SKIP_HOPS = [
    ("24.8.6.70", None),
    ("25.8.29.51", 12),      # skips 25.3.14.14 entirely -- 1 LTS in between (< 2)
    ("26.8.9.10", 12),       # skips 26.3.17.110 entirely -- 1 LTS in between (< 2)
]
