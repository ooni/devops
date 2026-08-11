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
- **Recommendation: do a rolling, node-by-node upgrade, but stage it through
  each intermediate LTS release rather than jumping straight to latest.**
  No full-cluster downtime is needed either way — the risk isn't downtime,
  it's version skew during the upgrade window.

  ```
  24.8.6.70  →  25.3.14.14  →  25.8.29.51  →  26.3.17.110  →  26.7.3.19
   (current)      LTS            LTS            LTS          (latest stable)
  ```

  Each hop is 4–7 months of releases apart, comfortably inside the
  compatibility window. Do all 3 replicas one at a time for a given hop
  before starting the next hop (never skip ahead on one node while another
  is still 2+ hops behind).

This repo contains a dockerized test that *exercises* this rather than just
asserting it: it spins up a 3-node cluster shaped exactly like OONI's
`oonidata_cluster` (1 shard, 3 replicas, embedded ClickHouse Keeper, same
table schemas), loads it with data, and mechanically upgrades one node at a
time — first via the direct jump (to show what breaks), then via the staged
LTS path (to confirm it doesn't).

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

## What was and wasn't verified in this sandbox

Verified here:
- `docker-compose.yml` parses and interpolates correctly (`docker compose config`).
- All ClickHouse XML config files (`config/**/*.xml`) are well-formed.
- All Python modules compile and the seed-data generator runs and produces
  well-formed `INSERT` statements against the real column lists.
- The Docker daemon itself works in this sandbox (`docker run` succeeds for
  locally available images).

Not verified here (blocked by sandbox network policy — Docker Hub and S3
are both unreachable; `docker pull` fails with `403 Forbidden` regardless of
image):
- Actually pulling the `clickhouse/clickhouse-server` images.
- Running the containers and confirming the Keeper ensemble forms, the
  replicated tables replicate, and the upgrade steps behave as designed.

**You'll need to run `make test` yourself in an environment with normal
internet access** (a dev laptop, a CI runner, an EC2 box) to get the actual
report. Budget ~10-20 minutes to pull 5 different `clickhouse-server` image
tags the first time; subsequent runs reuse the Docker image cache.

## Files

```
docker-compose.yml          3-node cluster definition, per-node image tag override via env
config/common/              Settings shared by all nodes (remote_servers, zookeeper client, distributed_ddl)
config/ch{1,2,3}/node.xml   Per-node macros (shard/replica) + embedded Keeper raft config
sql/001_schema.sql          Production table DDL (ReplicatedReplacingMergeTree, ON CLUSTER)
harness/seed_data.py        Synthetic data generator (see note above on why it's synthetic)
harness/ch_http.py          Minimal stdlib-only ClickHouse HTTP client
harness/compose.py          docker-compose wrapper (bring up/tear down/recreate one node at a time)
harness/validate.py         Cluster health checks (replication convergence, error scraping, write/read probes)
harness/scenarios.py        The two upgrade scenarios
harness/report.py           Results -> Markdown report renderer
run_test.py                 CLI entry point
results/                    report.md / report.json land here after a run
```
