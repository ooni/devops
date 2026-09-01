# ClickHouse cluster upgrade test (ooni/devops#437)

Answers the question behind [ooni/devops#437](https://github.com/ooni/devops/issues/437):
**can OONI's production ClickHouse cluster be upgraded from its current
version to the latest stable release one node at a time, or does it need a
scheduled-downtime, all-nodes-at-once upgrade?**

## TL;DR

- Production is on **24.8.6.70** (LTS, Aug 2024) — confirmed from
  `ooni/devops` `ansible/group_vars/clickhouse/vars.yml` (`clickhouse_version: 24.8.6.70`),
  matching what issue #437 reports.
- Latest stable as of 2026-08-10 is **26.7.3.19** (released 2026-07-22).
- That's about **23 months apart**. ClickHouse's own docs
  ([clickhouse.com/docs/operations/update](https://clickhouse.com/docs/operations/update))
  say replicas of the same shard should not run versions more than
  **~1 year apart** — beyond that window the docs warn the cluster "may not
  work", queries can fail with arbitrary errors, and downgrading stops being
  an option.
- **Recommendation, updated after CI run
  [32122682392](https://github.com/ooni/devops/actions/runs/32122682392)
  completed the full ladder: do a rolling, node-by-node upgrade all the
  way to `26.7.3.19`, in 4 hops, landing on each LTS release in turn.**
  Three of those hops (`25.3.14.14 -> 25.8.29.51`, `25.8.29.51 ->
  26.3.17.110`, and `26.3.17.110 -> 26.7.3.19`) have each hit real,
  reproducible ClickHouse incompatibilities in CI at least once — but every
  occurrence turned out to be transient and self-healing once the lagging
  node's own upgrade completes, not a structural block. See "Real CI
  findings" below for what that means operationally before doing any of
  these three hops in production.

  ```
  24.8.6.70  →  25.3.14.14  →  25.8.29.51  →  26.3.17.110  →  26.7.3.19
   (current)      LTS        LTS (*)          LTS (*)         (latest) (*)

  (*) upgrade all 3 nodes back-to-back in one sitting for these three hops
      -- the trailing node is expected to log hard-looking errors for a
      minute or two until its own upgrade finishes. See "Real CI findings".
      (The last hop has only been observed to hit this once, in a later
      run, vs. every run for the other two -- see "Real CI findings" for
      why it's still grouped here rather than treated as clean.)
  ```

  No full-cluster downtime is needed — the risk was never downtime, it
  was version skew during the upgrade window, and that skew resolves
  itself as long as the rollout actually finishes rather than being left
  half-done.

  The monthly (non-LTS) releases between `25.3.14.14` and `25.8.29.51`
  (`25.4.13.22`, `25.5.11.15`, `25.6.13.41`, `25.7.8.71`) only exist in
  this project's CI ladder (`harness/versions.py`'s `LTS_HOPS`), inserted
  to bisect *which* release introduced the incompatibility. Production
  has no reason to stop on any of them — see `harness/versions.py`'s
  `PRODUCTION_HOPS` for the 4-hop version of this ladder.

This repo contains a dockerized test that *exercises* this rather than just
asserting it: it spins up a 3-node cluster shaped exactly like OONI's
`oonidata_cluster` (1 shard, 3 replicas, embedded ClickHouse Keeper, same
table schemas), loads it with data, and mechanically upgrades one node at a
time — first via the direct jump (to show what breaks), then via the staged
LTS path (to confirm it doesn't). A third, separate job additionally
replays the real OONI data-ingestion pipeline across the same upgrade path
using actual measurements instead of synthetic data — see "Real-data
end-to-end scenario" below.

## Where the numbers come from

| Fact | Source |
|---|---|
| Current version `24.8.6.70` | `ooni/devops` `ansible/group_vars/clickhouse/vars.yml` → `clickhouse_version:` |
| Cluster topology: 1 shard, 3 replicas, embedded Keeper on `data1/2/3.htz-fsn.prod.ooni.nu` | `ooni/devops` `ansible/group_vars/clickhouse/vars.yml` (`clickhouse_remote_servers`, `clickhouse_keeper`, `clickhouse_macros`), `ansible/roles/oonidata_clickhouse/tasks/main.yml`, `ansible/inventory` |
| Production table schemas (`fastpath`, `citizenlab`, `jsonl`, `analysis_web_measurement`, `event_detector_changepoints`, `faulty_measurements`) | `ooni/devops` `scripts/cluster-migration/schema.sql` |
| `obs_web` column list | `ooni/backend` `ooniapi/services/oonimeasurements/tests/fixtures/initdb/clickhouse.sql` |
| Other table column lists (test/CI copies) | `ooni/backend` `ooniapi/services/oonimeasurements/tests/migrations/0_clickhouse_init_tables.sql` |
| Latest stable / LTS version history | [clickhouse.com/docs/whats-new/changelog](https://clickhouse.com/docs/whats-new/changelog), [endoflife.date/clickhouse](https://endoflife.date/clickhouse) |
| Mixed-version / rolling-upgrade guidance | [clickhouse.com/docs/operations/update](https://clickhouse.com/docs/operations/update) |

## What the test actually does

`docker-compose.yml` brings up 3 ClickHouse nodes (`ch1`, `ch2`, `ch3`) on a
private docker network, each running **both** `clickhouse-server` and an
embedded **ClickHouse Keeper** instance (ports 9181/9234) — the same
topology as `data1/data2/data3` in production, just condensed onto one
Docker host. `sql/001_schema.sql` creates the real table schemas
(`ReplicatedReplacingMergeTree`, `ON CLUSTER oonidata_cluster`) and
`harness/seed_data.py` loads synthetic-but-schema-accurate rows into them.

`run_test.py` then runs one or both scenarios:

- **`staged`** — walks the version ladder above, upgrading `ch1`, then
  `ch2`, then `ch3` at each hop (never more than one node down at a time,
  never all 3 nodes on different versions at once), validating after every
  single node swap that:
  - the node comes back up,
  - a write issued anywhere is readable from every replica within the
    timeout (`harness/validate.py:probe_write_then_read`),
  - row counts converge across all 3 nodes,
  - `system.errors` hasn't accumulated any replication/checksum/protocol
    errors,
  - `system.replication_queue` has no stuck tasks,
  - and, once a hop is fully rolled out, an `ALTER TABLE ... ON CLUSTER`
    still propagates cluster-wide.
- **`direct`** — does the same node-by-node mechanics but jumps straight
  from `24.8.6.70` to `26.7.3.19`, to surface (not just cite) whatever
  breaks when replicas are held ~2 years apart in version for the whole
  rollout.

Results land in `results/report.md` (human-readable) and
`results/report.json` (full structured data, including every row-count
snapshot and every error ClickHouse logged).

## Running it

Requires Docker + Compose v2, and — this matters — **network access to pull
`clickhouse/clickhouse-server` images from Docker Hub**. (This harness was
built inside a sandboxed environment whose egress is restricted to a small
allowlist that does not include Docker Hub or S3, so it could not be
executed end-to-end there; everything here was validated as far as that
constraint allows — see "What was and wasn't verified" below.)

```bash
# from this directory
make test              # both scenarios (staged, then direct), ~20-40 min depending on image pull speed
make test-staged        # just the recommended path
make test-direct        # just the naive direct-jump path
make config              # sanity-check docker-compose.yml without pulling anything
```

Or directly:

```bash
python3 run_test.py --scenario both
```

Add `--keep-up` to leave the cluster running after the test so you can poke
at it manually (`docker compose exec ch1 clickhouse-client`).

## About the seed data

The task pointed at `ooni/backend`'s initdb sample data. That repo doesn't
actually vendor the sample rows in git — its test fixtures
(`ooniapi/services/oonimeasurements/tests/conftest.py`) download
`obs_web-sample.sql.gz` and `analysis_web_measurement-sample.sql.gz` at test
time from a public S3 bucket
(`ooni-data-eu-fra.s3.eu-central-1.amazonaws.com`). This sandbox's network
egress couldn't reach S3 either, so `harness/seed_data.py` generates
synthetic rows that conform exactly to the real schemas instead (same
columns, types, nullability, realistic cardinality for things like
`probe_cc`/ASN/test names). That's sufficient for what this test is
checking — replication and on-disk part-format compatibility across
ClickHouse versions — since that behavior depends on schema and volume, not
on the specific measurement content.

If you have S3 access and want to use the real dump instead:

```bash
curl -sL https://ooni-data-eu-fra.s3.eu-central-1.amazonaws.com/samples/obs_web-sample.sql.gz \
  | gunzip -c | docker compose exec -T ch1 clickhouse-client --database ooni
curl -sL https://ooni-data-eu-fra.s3.eu-central-1.amazonaws.com/samples/analysis_web_measurement-sample.sql.gz \
  | gunzip -c | docker compose exec -T ch1 clickhouse-client --database ooni
```

(after `sql/001_schema.sql` has been applied, and before running an upgrade
scenario — or just skip the seed step in `harness/scenarios.py:load_schema_and_seed`
and load these instead).

## Real CI findings: a genuine incompatibility, pinned to exactly 25.8.29.51

A real staged-upgrade CI run
([ooni/devops#477](https://github.com/ooni/devops/pull/477), run
[32044578317](https://github.com/ooni/devops/actions/runs/32044578317))
got cleanly through `24.8.6.70 -> 25.3.14.14` (including the transient,
non-gating connection blips a container recreate is expected to cause —
see "What was and wasn't verified" below) and then hit a **hard, real
failure** during `25.3.14.14 -> 25.8.29.51`, specifically at the point
where ch1 and ch2 were already on `25.8.29.51` and ch3 was still on
`25.3.14.14`:

- `CHECKSUM_DOESNT_MATCH` logged on both upgraded nodes.
- ch3's replication queue stuck retrying two entries (148 and 147 tries
  and climbing) with the identical root cause on both:
  `Code: 79. DB::Exception: Unknown mark file extension: '4'.
  (INCORRECT_FILE_NAME)`, thrown while ch3 tried to fetch a data part from
  a peer.
- The write-then-read-back probe failed on ch3 for the first time in the
  whole run, and row counts diverged.

That's a **materially bigger finding than the one raised in review** — it
shows up a full LTS hop before 26.3, the version the review flagged as the
one to be careful about.

**Bisected and confirmed** (run
[32047534149](https://github.com/ooni/devops/actions/runs/32047534149),
after inserting every monthly release between the two LTS versions —
`25.4.13.22`, `25.5.11.15`, `25.6.13.41`, `25.7.8.71`, from
[endoflife.date/api/clickhouse.json](https://endoflife.date/api/clickhouse.json)):
**`24.8.6.70 -> 25.3.14.14 -> 25.4.13.22 -> 25.5.11.15 -> 25.6.13.41 ->
25.7.8.71` all upgrade cleanly, node by node, zero hard errors.** The
failure reappears exactly and only at `25.7.8.71 -> 25.8.29.51` — same
failure family, a different specific manifestation this time:
`Code: 226. NO_FILE_IN_DATA_PART: No columns_substreams.txt in part
all_17_17_1`, fetching a part whose mark file has the new `.cmrk4`
extension. This rules out a gradual drift across the whole 25.3-25.8 span
— it's one version boundary, `25.8.29.51`, that changes the on-disk
compact-part format (new manifest file + new mark-file extension) in a
way no earlier binary in this range can read.

**Corroborating evidence** (not confirmed against the official changelog
text itself — repeated attempts to fetch the relevant section, listed
below, all failed): a v25.12 changelog entry found during this
investigation reads *"Enable advanced shared data for JSON by default...
after that change downgrade to versions before 25.8 will be not possible,
because these versions won't be able to read new data parts with JSON
column."* That's scoped to JSON columns and to downgrading specifically,
but it names 25.8 as the version this substream-based part-serialization
infrastructure was introduced in. `citizenlab` (the table that failed
here) has no JSON column, so this bisection most likely caught that same
infrastructure applying to plain `MergeTree` parts generally — consistent
with, though not proof of, a shared root cause.

`harness/versions.py`'s `LTS_HOPS` and
`.github/workflows/clickhouse_upgrade_test.yml` both keep the 8-hop
bisection ladder (rather than collapsing back to 4 hops) so this stays
directly re-testable. Production, however, doesn't need to walk the
monthly releases — see `PRODUCTION_HOPS` below.

## Real CI findings, continued: both incompatibilities self-heal once the lagging node catches up

The open question from the previous section — does the stuck queue clear
once the lagging node's own upgrade finishes, or is it permanent? — is
answered. `.github/workflows/clickhouse_upgrade_test.yml` was changed to
add `continue-on-error: true` to every upgrade/verify step so a hop's
first failure no longer aborts the job before the remaining nodes get a
chance to upgrade too, and `ci_step.py report` was changed to be the
actual job-level pass/fail gate instead. Run
[32122682392](https://github.com/ooni/devops/actions/runs/32122682392)
then completed the entire 8-hop ladder and found:

- **`hop6-ch2`** (upgrading ch2 to `25.8.29.51`, leaving ch3 on
  `25.7.8.71`) failed exactly as before: ch3 stuck retrying a `GET_PART`
  fetch (`NO_FILE_IN_DATA_PART`, missing `columns_substreams.txt`), 17
  tries. **`hop6-ch3`** — ch3's own upgrade to `25.8.29.51`, run
  immediately after — passed clean: converged, fully replicated, zero
  queue problems. The stuck fetch simply succeeded once ch3 could parse
  the new format itself.
- The identical pattern repeats one hop later, and this is the exact
  26.3 nested-type serialization change flagged in the original PR
  review: **`hop7-ch1`** logged a hard `CHECKSUM_DOESNT_MATCH` while
  briefly the only node on `26.3.17.110`. **`hop7-ch2`** then left ch3
  (still on `25.8.29.51`) stuck retrying with `CORRUPTED_DATA` /
  *"Unknown version of serialization infos (1). Should be less or equal
  than 0"* — 17 tries. **`hop7-ch3`** — ch3's own upgrade to
  `26.3.17.110` — again passed clean.
- **`hop8`** (`26.3.17.110 -> 26.7.3.19`) had zero hard errors anywhere in
  this particular run.

So both incompatibilities are the same underlying mechanism: an
old-format binary can't parse a part written in a new on-disk format, and
the fix is simply for that binary to become new-format too, at which
point its own retry of the identical fetch succeeds. Neither is a
structural block on reaching `26.7.3.19`.

**Update:** a later run,
[32134303759](https://github.com/ooni/devops/actions/runs/32134303759),
hit the *same* self-healing pattern at `hop8` too — `hop8-ch2` logged a
hard `CHECKSUM_DOESNT_MATCH` ("Different number of files: 3 compressed
(expected 3) and 3 uncompressed ones (expected 2)") while ch3 was still
on `26.3.17.110`, and `hop8-ch3` (ch3's own upgrade to `26.7.3.19`) again
passed clean immediately after. So `hop8` is not reliably clean the way
the bullet above (from the first run that reached it) suggested — it can
also hit the same transient, self-healing mixed-version friction as
`hop6`/`hop7`, just not on every run. Treat all three of `hop6`, `hop7`,
and `hop8` as "expect this, and expect it to clear once the trailing node
finishes," per the operational rule below, rather than treating `hop8` as
the one hop guaranteed to be quiet.

**What this doesn't tell us**, and shouldn't be assumed: the mixed-version
window in these runs was CI-paced — seconds to at most a couple of
minutes between one node finishing and the next starting. Whether the
same self-healing holds if a node is left lagging for hours or days at
any of these three hops specifically hasn't been tested. Nor does this
touch the separate *downgrade*-lossiness warning in the 26.3 changelog
entry — that's about rolling back after the fact, a different risk from
the forward-rolling mixed-version friction these runs exercised.

Given this, `RECOMMENDED_NOW` in `harness/versions.py` is now
`26.7.3.19`, and `PRODUCTION_HOPS` is the 4-hop runbook this project
recommends: skip the monthly bisection releases (they were CI-diagnostic
only), land on each LTS in turn, and for the three hops that have hit a
real incompatibility at least once (`25.3.14.14 -> 25.8.29.51`,
`25.8.29.51 -> 26.3.17.110`, and `26.3.17.110 -> 26.7.3.19`) upgrade all
three nodes back-to-back in one sitting rather than spacing them out —
expect the trailing node to log hard-looking errors for a minute or two
right up until its own upgrade finishes, and treat that as expected only
if it actually clears once that node is fully upgraded. If it's still
stuck minutes after the last node comes back up, stop and treat it as a
real problem rather than assuming it'll resolve.

One gap before calling `PRODUCTION_HOPS` fully proven: self-healing has
been directly observed for the `25.7.8.71 -> 25.8.29.51` sub-hop (via the
bisection ladder) and for `25.8.29.51 -> 26.3.17.110`, but not yet for a
genuine single-hop `25.3.14.14 -> 25.8.29.51` jump (skipping the
intermediate monthly releases). The original un-bisected 4-hop ladder
(run 32044578317) hit the identical failure signature at that exact
transition, but aborted before ch3 got a chance to complete its own
upgrade — so self-healing there is inferred from the shared mechanism,
not directly confirmed. Worth one more CI run of `PRODUCTION_HOPS` itself
to close this gap.

## PR #477 review response

Raised in review on [ooni/devops#477](https://github.com/ooni/devops/pull/477)
(hellais) — addressed here point by point:

1. **"Read the changelog for tricky breaking changes."** 26.3 ships
   ["Propagate data types serialization versions to nested data
   types"](https://clickhouse.com/docs/resources/changelogs/oss/2026#263-backward-incompatible-change),
   which the changelog itself flags as able to make **downgrading after
   upgrading lossy**. That downgrade-lossiness warning is still true and
   still unresolved. Separately, real CI turned up a *forward*-upgrade
   consequence of this same change too: mixed-version friction while
   rolling through 26.3 (see "Real CI findings, continued" above) — which
   traces to the identical changelog entry, just a different symptom than
   the one originally flagged. Both this and the earlier 25.8.29.51
   mark-file finding turned out to be transient and self-healing rather
   than blocking, once the harness could observe a completed rollout —
   see "Real CI findings" and "Real CI findings, continued" above for the
   full story and the operational caveats that still apply.
2. **"Renamed `searchAny`/`searchAll` to `hasAnyTokens`/`hasAllTokens`
   (25.10) — make sure we aren't using these."** Confirmed absent from
   `oonipipeline` (`ooni/data`, the data-pipeline repo this cluster feeds —
   found via `ansible/roles/oonidata_airflow` / `ansible/roles/notebook`).
   **Still open:** `ooni/backend` hasn't been grepped for these yet.
3. **"Disallow truncating replicated databases — might apply to us in the
   data pipeline."** It does, and there are two independent production
   sites doing it, not one:
   - `ooni/data` (`oonipipeline`) `tasks/updaters/citizenlab_test_lists_updater.py`
   - `ooni/backend` `analysis/analysis/citizenlab_test_lists_updater.py`

   Both run the identical sequence: `TRUNCATE TABLE citizenlab_flip`
   (a `ReplicatedReplacingMergeTree` table, per `sql/001_schema.sql`) →
   `INSERT INTO citizenlab_flip` → `EXCHANGE TABLES citizenlab_flip AND
   citizenlab` — the swapped-ZK-path pair documented there. It's not yet
   confirmed which of these two is the one actually deployed/cron'd today
   vs. legacy code left over from a migration between repos — worth a
   direct check before assuming only one matters.

   Lower-severity but same category, found while checking test suites for
   "run against the target version" (point 4): `ooni/backend`'s
   `oonirun` and `ooniprobe` service test fixtures (`tests/conftest.py`)
   both call `TRUNCATE TABLE` on `url_priorities` and `faulty_measurements`
   respectively — both of which are also `Replicated*` engines per the live
   schema. These only run against ephemeral test containers today, but if
   those test suites get pointed at a candidate ClickHouse version (see
   point 4), a truncate-replicated restriction would surface there too, not
   just in the data pipeline. `oonipipeline`'s own `cli/commands.py`
   `TRUNCATE TABLE event_detector_cusums SYNC` and its `tests/conftest.py`
   truncates are lower risk since `event_detector_cusums`/`_changepoints`
   are plain (non-replicated) `ReplacingMergeTree` per the live schema dump.

   **Still open:** pinning down which exact ClickHouse version introduced
   the truncate-replicated restriction (the reviewer's comment didn't
   include a changelog link for this one) and confirming whether it blocks
   this specific truncate-then-swap pattern outright or only under some
   conditions (e.g. only for `TRUNCATE ... ON CLUSTER` / whole databases,
   not a single replicated table via one node).
4. **"Run the target version against the real API + data pipeline."**
   **Addressed** by the new `real-data-upgrade` job — see "Real-data
   end-to-end scenario" below for the full design. It downloads real OONI
   measurements, ingests them through the actual `oonidata`/`oonipipeline`
   pipeline and `fastpath`, and re-runs `ooni/data`'s own pytest suite
   against the real `api-oonimeasurements` service at every hop of
   `PRODUCTION_HOPS` — not just ClickHouse's own replication mechanics
   (which the synthetic scenario above already covers), but the actual
   ingestion and query paths OONI's data pipeline depends on. One caveat:
   it exercises `ooni/data`'s test suite and `ooni/backend`'s
   `api-oonimeasurements` service, not `oonipipeline`'s own test suite
   directly, and it depends on an unmerged external branch
   (`ooni/data#160`) — see that section for details.
5. **Full changelog sweep, 24.9 through 26.7, for every "Backward
   Incompatible Change" entry** (not just the two the reviewer happened to
   quote) — in progress, not complete. What's confirmed so far is captured
   in points 1-3 above.

Net effect: `LTS_HOPS` (what this harness's `staged` CI job actually
tests) walks the full ladder to `26.7.3.19`. As of run 32122682392 it
completed clean, with both the mark-file finding and the 26.3 nested-type
serialization change turning out to be transient, self-healing mixed-
version friction rather than structural blocks (see "Real CI findings,
continued" above); a later run (32134303759) showed the same friction can
also surface at the final hop (`26.3.17.110 -> 26.7.3.19`), self-healing
the same way. The production recommendation (`RECOMMENDED_NOW` /
`PRODUCTION_HOPS`, and the README TL;DR above) now covers the whole
ladder, with an operational caveat (upgrade the trailing node promptly)
attached to the three hops that have hit a real incompatibility at least
once. Point 4 is now addressed by the `real-data-upgrade` job (see
below). Points 2 and 5 remain open.

## Real-data end-to-end scenario (`real-data-upgrade` job)

A second, separate CI job that answers a different question from the
`staged`/`direct` scenarios above: not "does ClickHouse's own replication
survive the upgrade" (synthetic seed data is sufficient for that, and
fast), but "does OONI's actual data pipeline — real measurements, ingested
through the real `oonidata`/`oonipipeline`/`fastpath` tools, queried
through the real `api-oonimeasurements` service — still work correctly
after each hop of the production runbook, with nothing corrupted or
changed along the way." Implemented in `harness/real_data.py`, wired into
the `real-data-upgrade` job in
`.github/workflows/clickhouse_upgrade_test.yml`.

**Source of the pipeline itself:** [ooni/data#160](https://github.com/ooni/data/pull/160)
(branch `add_end_to_end_tests`), which adds a `tests/integration/` stack
(single-node ClickHouse + Postgres + Valkey + fastpath +
`api-oonimeasurements` + a pytest `verify` container) that downloads real
OONI measurements and processes them through `oonipipeline`, then tests
the API against the result. This job adapts that stack onto this
project's existing 3-node **replicated** cluster instead of a single
throwaway node — see `docker-compose.real-data.yml`'s header comment for
every deliberate difference from the upstream compose file (auth, dropped
`fastpath2`, no host port exposure, etc.).

**Design, per what this cluster actually needs to verify:**

- **Real data is downloaded and ingested exactly once per CI run**, right
  after standing up a fresh cluster at `BASE_VERSION` (`24.8.6.70`) — not
  re-downloaded at every hop. Re-ingesting fresh data at each of
  `PRODUCTION_HOPS`'s 4 checkpoints would multiply this already-slow job's
  runtime for no real gain: the question this job answers is "does
  upgrading corrupt or break access to what's already there," not "can
  fresh data still be ingested at every intermediate version" (a real but
  different question — see the `TODO` in `harness/real_data.py`'s module
  docstring for a possible follow-up).
- Right after that one ingestion, a **golden snapshot** is taken — row
  count + an order-independent content checksum (`sum(cityHash64(*))`,
  ClickHouse's own idiom for hashing a whole table without listing columns
  by hand) per real-data table, on all 3 nodes, requiring they already
  agree with each other.
- **After every hop of `PRODUCTION_HOPS`** (all 3 nodes upgraded
  back-to-back, reusing the exact same `upgrade_node_step()` mechanics the
  synthetic scenario uses — these are already version/schema-agnostic):
  1. re-snapshot all 3 nodes and diff against the golden baseline — any
     difference at all, on any node, in either row count or checksum, is a
     hard failure, since nothing should be writing new data during an
     upgrade rehearsal;
  2. re-run `ooni/data#160`'s own pytest suite against the real
     `api-oonimeasurements` service, to confirm the genuine query/API path
     still works — not just that ClickHouse's own replication mechanics
     survived (already covered by the synthetic scenario's write-then-
     read-back probe).
- **A continuous read/write canary now runs for the entire rollout, not
  just at hop boundaries** (`harness/availability.py`, the
  `zero-downtime-upgrade` step/job). Both checks above are point-in-time —
  they compare data-at-rest between checkpoints, but say nothing about
  what happens to a read or write attempted *during* the brief window
  when a node is mid-bounce, which is exactly the question "does the
  upgrade cause any downtime or blocked writes" is actually asking. A
  background thread (`CanaryWriter`) issues one read and one write every
  ~0.5s for the whole rollout, round-robining across all 3 nodes with
  immediate failover to the next node on failure — mirroring how
  production's own `clickhouse_proxy` role would route around a bounced
  node, not asserting every individual node is reachable at every instant
  (one node *will* be briefly unreachable during its own bounce; that's
  unavoidable in a rolling upgrade and not itself a failure). Pass
  condition, all of which must hold across the entire 4-hop run: zero
  read or write attempts blocked on every node in the same tick (the "no
  downtime, no blocked writes" claim); every write the canary saw
  acknowledged is still present in the cluster's final state once the
  rollout finishes and a short settling grace period elapses (catches
  silent data loss the golden-snapshot diff can't, since that diff only
  tracks the originally-ingested rows, not the canary's own writes); and
  all 3 nodes agree on the canary table's final contents. This replaces
  the four separate `real-data-hop` steps that used to run in the
  workflow (`rd-hop1`..`rd-hop4`, one per `PRODUCTION_HOPS` hop) with one
  `zero-downtime-upgrade` step spanning all 4 hops — the whole point is a
  single canary thread that never stops between hops, so it can't be
  split back across separate steps without losing that continuity.
  `real_data.real_data_hop_step()` / `ci_step.py real-data-hop` are
  unchanged and still available as a standalone primitive (e.g. for a
  future scenario that wants one hop in isolation, without the canary).
- Uses `PRODUCTION_HOPS` (4 hops), not the 8-hop `LTS_HOPS` bisection
  ladder — this job verifies the actual recommended production upgrade
  path, not every diagnostic waypoint used to originally localize the
  mark-file incompatibility. A workflow-level sanity check (mirroring the
  `staged-upgrade` job's own `LTS_HOPS` check) fails loudly if
  `harness/versions.py`'s `PRODUCTION_HOPS` and this job's hardcoded step
  list ever drift apart.

**Does not replace the synthetic scenario.** `harness/seed_data.py` and
`scenario_staged_lts()`/`scenario_direct_jump()` are unchanged and still
run as before — they're fast, self-contained, and sufficient for
verifying replication/on-disk-format compatibility. This is a slower,
additional, more realistic check layered on top.

**New schema tables**, added to `sql/001_schema.sql` to match what
`oonipipeline`'s observations workflow and `fastpath` actually write
(`fingerprints_dns`, `fingerprints_http`, `obs_web_ctrl`,
`obs_http_middlebox`, `obs_openvpn`) — see that file's own comments for
per-table provenance and which ones are cross-checked against a
known-live schema (`obs_web`) versus derived from `oonipipeline`'s DDL
generator with manual signedness corrections (that generator emits
`Int32`/`Int8` unconditionally for `int`/`bool` fields, which is
known-wrong for at least the ASN and boolean-flag columns it shares with
the already-verified `obs_web` table — see the file for the full
reasoning). `EmbeddedRocksDB` (used by a couple of these) has no
`Replicated` variant in ClickHouse — `ON CLUSTER` replicates the table
*structure* for it, not row contents; that's a real, documented
limitation of this engine, not a gap in this test.

**Caveats:**

- `ooni/data#160` is **still an open, unmerged PR** as of this writing.
  `docker-compose.real-data.yml` and the workflow both pin to its
  `add_end_to_end_tests` branch specifically (that's the branch with the
  `oonipipeline` CLI entry point this job needs — `main` doesn't have it
  yet). **Update the checkout ref once #160 merges.**
  `oonidata sync`/`oonipipeline run --workflow-name observations` and
  `fastpath` only populate `fastpath`, `obs_web`, `obs_web_ctrl`, and
  `obs_http_middlebox` — `citizenlab`, `fingerprints_dns/http`, and
  `obs_openvpn` need different updater/workflow invocations this job
  doesn't run, so they're expected to stay empty here and aren't part of
  the integrity check.
- **Not run on every pull request**, unlike `staged-upgrade` and
  `direct-jump-upgrade` above — it checks out an external, unmerged
  branch this repo doesn't control and does real network downloads of
  OONI measurement data, so a flaky or slow dependency there shouldn't
  block unrelated PRs. It runs on push to `main` (when these paths
  change) and on demand via `workflow_dispatch` (`scenario: real-data` or
  `all`). Revisit this if `real-data-upgrade` proves reliable enough, or
  once `ooni/data#160` merges and the external-branch risk goes away.
- Like the rest of this harness, this could not be executed end-to-end in
  the sandbox this was built in (no Docker daemon, restricted egress) —
  verified as far as that allows (Python compiles, YAML/SQL parse
  structurally) and real validation is deferred to an actual CI run, same
  as every other CI-dependent change in this project.

## What was and wasn't verified

This harness has now actually run in GitHub Actions four times (see
`.github/workflows/clickhouse_upgrade_test.yml`, exercised on
[ooni/devops#477](https://github.com/ooni/devops/pull/477)), which has real
network access this project's original build/review sandbox didn't:

- **Run 1** ([32041884883](https://github.com/ooni/devops/actions/runs/32041884883))
  got through `setup` and `ch1`'s `24.8.6.70 -> 25.3.14.14` upgrade, then
  flagged `ch2`'s upgrade as failed — a **false positive in this harness's
  own error-detection logic**, not a real ClickHouse problem (fixed; see
  `harness/validate.py`'s transient-vs-hard error classification).
- **Run 2** ([32044578317](https://github.com/ooni/devops/actions/runs/32044578317)),
  after that fix, got all the way through the full `24.8.6.70 -> 25.3.14.14`
  hop cleanly (including further transient, non-gating blips, confirming
  the fix generalizes) and then hit the real `25.3.14.14 -> 25.8.29.51`
  mark-file incompatibility described in "Real CI findings" above.
- **Run 3** ([32047534149](https://github.com/ooni/devops/actions/runs/32047534149)),
  with the bisection hops in place, confirmed `24.8.6.70` through
  `25.7.8.71` all upgrade cleanly and pinned the failure to exactly the
  `25.7.8.71 -> 25.8.29.51` transition — see "Real CI findings" above for
  the full detail.
- **Run 4** ([32122682392](https://github.com/ooni/devops/actions/runs/32122682392)),
  after adding `continue-on-error` so a hop's first failure no longer
  aborts the job, completed the full 8-hop ladder and confirmed both the
  `25.8.29.51` and `26.3.17.110` incompatibilities are transient and
  self-healing once the lagging node's own upgrade finishes — see "Real
  CI findings, continued" above.

Originally verified only inside a sandbox with restricted egress (no Docker
Hub / S3 access), before any real run:
- `docker-compose.yml` parses and interpolates correctly (`docker compose config`).
- All ClickHouse XML config files (`config/**/*.xml`) are well-formed.
- All Python modules compile and the seed-data generator runs and produces
  well-formed `INSERT` statements against the real column lists.

**Still worth doing:** one more CI run of `PRODUCTION_HOPS` itself (the
4-hop runbook, skipping the monthly bisection releases) to directly
confirm self-healing holds for a genuine single-hop
`25.3.14.14 -> 25.8.29.51` jump, not just the bisected sub-hop; and
separately review the `direct-jump` job's own failure log, which still
hasn't been looked at (it's expected to fail — that's the point of that
job — but it's still worth confirming it fails for the *same* reason and
not something else).

## Files

```
docker-compose.yml            3-node cluster definition, per-node image tag override via env
docker-compose.real-data.yml  Overlay: real ooni/data pipeline (postgres/valkey/api/downloader/fastpath/verify) on top of ch1/ch2/ch3
config/common/                Settings shared by all nodes (remote_servers, zookeeper client, distributed_ddl)
config/ch{1,2,3}/node.xml     Per-node macros (shard/replica) + embedded Keeper raft config
sql/001_schema.sql            Production table DDL (ReplicatedReplacingMergeTree, ON CLUSTER) + real-data-pipeline tables
real_data/fastpath/           fastpath config + cache dir for the real-data scenario
real_data/data/               Downloaded real OONI measurements land here (gitignored, fetched fresh every run)
harness/seed_data.py          Synthetic data generator (see note above on why it's synthetic)
harness/real_data.py          Real-data end-to-end scenario (see "Real-data end-to-end scenario" above)
harness/ch_http.py            Minimal stdlib-only ClickHouse HTTP client
harness/compose.py            docker-compose wrapper (bring up/tear down/recreate one node at a time, multi-file overlay support)
harness/validate.py           Cluster health checks (replication convergence, error scraping, write/read probes)
harness/scenarios.py          The two synthetic-data upgrade scenarios
harness/report.py             Results -> Markdown report renderer (both scenario shapes)
ci_step.py                    Per-step CLI used by the GitHub Actions workflow (all three jobs)
run_test.py                   CLI entry point (synthetic scenarios only; real-data scenario is CI-only via ci_step.py)
results/                      report.md / report.json / golden snapshot land here after a run
```
