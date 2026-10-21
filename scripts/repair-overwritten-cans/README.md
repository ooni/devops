# Repairing raw cans the uploader overwrote

Until `fix_uploader_can_overwrite`, `ansible/roles/fastpath/templates/ooni_api_uploader.py` numbered each run's cans
from 0 and PUT them without checking. When measurements reached a fastpath spool after their hour had been
uploaded, the next run wrote the same keys again and replaced the earlier cans. That happened with a fastpath
backlog, and with the reuploader re-sending old measurements. Bucket versioning kept the replaced cans as
noncurrent versions, but the current view lost their measurements, and their `jsonl` rows point at other
measurements' bodies.

A scan of every version under `raw/` in `ooni-data-eu-fra` for 2026-01-01..2026-10-14 found 35,131 measurements
that exist only in replaced versions:

| data day | uploader | measurements |
|---|---|---|
| 2026-02-23 | fastpath2 (n4) | 3,472 |
| 2026-03-11 | fastpath2 (n4) | 16,487 |
| 2026-04-10 | fastpath2 (n4) | 4,123 |
| 2026-04-11 | reuploader (n5) | 680 |
| 2026-04-23 | reuploader (n5) | 281 |
| 2026-04-25 | fastpath2 (n4) | 7,127 |
| 2026-07-14 | fastpath.prod (n1) | 2,961 |

## Tools
- `scan_versions.py FIRST_DAY LAST_DAY`: lists every version under `raw/<day>/` and writes the keys that have more
  than one (`multi_versions.tsv`). Public reads, no credentials.
- `count_lost.py MULTI_VERSIONS_TSV...`: for each affected hour/cc/test group, counts the measurements found only in
  replaced versions and lists their uids (`lost_by_group.tsv`, `lost_uids.tsv`). Public reads.
- `failed_bucket_check.py`: read-only checks of the failed-reports bucket and the reuploader's logs (needs credentials).
- `repair_cans.py`: the repair. Every step is a dry run unless given `--apply`, and its state and logs go to `--state`:
  1. `inventory`: every version of each prefix, and the measurements in each `.tar.gz` version.
  2. `restore`: publishes the measurements found only in noncurrent versions as new cans,
     `<hour>_<cc>_<test>.n9.<k>.tar.gz` / `.jsonl.gz`. No uploader uses collector `n9`. It never overwrites a key,
     and won't run twice on the same inventory.
  3. `fix-jsonl`: deletes the restored measurements' stale `jsonl` rows and inserts rows for the new cans.
  4. `verify`: looks up every measurement in every version (by uid; with `--check-api`, also the way the API does
     for the restored ones) and checks the body served is that measurement's content.
  5. `prune`: deletes noncurrent versions whose every measurement is served from the current view with the same
     content. With `--archive-bucket`, each version is copied there first. It refuses to run unless `verify` passed
     after the last restore.
- `dedupe_postcans.py`: before the reuploader runs again, moves the postcans whose measurement fastpath already has
  out of the failed-reports bucket (see below). Steps `plan`, `apply`, `verify`; dry runs unless given `--apply`.

## Running the repair (production)
Before starting:
- pause the reuploader schedule;
- deploy the uploader fix on all fastpath hosts;
- use credentials that can write to `ooni-data-eu-fra` and to the `jsonl` table.

Then:
```
cut -f2 multi_versions.tsv | sed 's#[^/]*$##' | sort -u > prefixes.txt
A="--db-uri clickhouse://...  --state repair-state --prefixes-from prefixes.txt"
python3 repair_cans.py inventory $A
python3 repair_cans.py restore $A            # read the plan, then:
python3 repair_cans.py restore --apply $A
python3 repair_cans.py fix-jsonl --apply $A
python3 repair_cans.py verify --check-api $A
python3 repair_cans.py prune $A              # read the list, then:
python3 repair_cans.py prune --apply --archive-bucket <archive bucket> $A
```
Afterwards, re-run ooni/data's processing for the affected hours, so obs_web and analysis get the restored
measurements. Also check that the production fastpath table has them; it should, since it scored them live.

## Postcans of the 2026-10-13/14 outage
During the outage (OOPRIV-163) ooniprobe saved submissions to the failed-reports bucket after the load balancer had
already answered 504, so probes submitted again. `submit_measurement` gives each submission a new `report_id` and
`measurement_uid`, so when a retry got through, fastpath has the measurement under other ids and reuploading the
postcan would add it a second time. `dedupe_postcans.py` identifies a measurement by its content without `report_id`,
and sorts the postcans into:

| class | meaning | apply moves it to |
|---|---|---|
| `already_ingested` | fastpath has the postcan's own uid | `dedup/` |
| `retried` | fastpath has it under another uid: same columns, and its `jsonl` row's body has the same content | `dedup/` |
| `repeat_postcan` | another postcan holds the same measurement (the earliest is kept) | `dedup/` |
| `unconfirmed` | fastpath's columns match, but there's no `jsonl` row or body to compare yet | `hold/` |
| `reupload` | none of these | stays, for the reuploader |
| `unreadable` | not a measurement | stays, listed |

`dedup/` and `hold/` are in a separate bucket (`--dedup-bucket`): the reuploader walks the whole failed-reports bucket
(it reads `S3_PREFIX` but never uses it) and deletes whatever fastpath accepts, unreadable bodies included. A move
copies, checks the copy, then deletes the original; nothing is deleted outright.

Order, in production:
1. Keep the reuploader schedule disabled; deploy the uploader fix (devops #515) on all three fastpath hosts.
2. Repair the cans: `scan_versions.py 2026-10-13 <today>`, `count_lost.py`, then the `repair_cans.py` steps above,
   so every `jsonl` row points at its own measurement (`retried` compares against those bodies).
3. Create a private bucket for the dedup copies, then (ClickHouse with `fastpath` and `jsonl`, e.g. data3):
   ```
   D="--db-uri clickhouse://...  --dedup-bucket <dedup bucket> --state dedupe-state"
   python3 dedupe_postcans.py plan $D     # read plan.tsv / plan_by_hour.tsv; then:
   python3 dedupe_postcans.py apply $D    # dry run; then:
   python3 dedupe_postcans.py apply --apply $D
   ```
   `plan` reads every postcan once (`postcans.tsv`), runs two `fastpath` queries per 500 postcans over their
   `measurement_start_time` range, and downloads the raw can of each match to compare bodies.
4. List what's left in the failed-reports bucket (only `reupload` and `unreadable` postcans should be), then enable
   the reuploader.
5. Once the uploader has uploaded the reuploaded hours: `python3 dedupe_postcans.py verify $D`. Each `reupload`
   measurement must be in fastpath once, with one `jsonl` row pointing at its own body, and no measurement of the
   plan may be in fastpath twice. Then re-run the hourly counts (`outage_2026-10-13_fastpath.sql`) and ooni/data's
   processing for the outage hours.
6. The held ones, once their `jsonl` rows exist: `plan` and `apply --apply` with `--prefix hold/postcans/` and a new
   `--state`. The confirmed ones go to `dedup/`, the others back to the failed-reports bucket for the reuploader.

## Test
`test/test_repair.sh` damages a test bucket the way production was: it runs `tests/uploader_e2e` with the uploader as
it was before the fix (`test/ooni_api_uploader_before_fix.py`). Then it runs every repair step and compares
snapshots of the bucket and the `jsonl` table taken before and after (`test/compare.py`). It checks that:
- every deleted version was noncurrent and is in `prune.log`;
- every other object version and every current object is unchanged;
- no existing key got a new version, and the only new objects are restored `n9` cans;
- the `jsonl` rows of measurements the repair didn't restore are unchanged;
- every measurement that reached S3 is served with its own body.

`test/test_dedupe.sh` fills the failed bucket and fastpath with every class above (`test/make_cases.py`), with
control traffic through fastpath. It checks that `plan` gives each postcan its expected class, that a second
`apply` moves nothing, and that after the reuploader and the uploader, `verify` passes and every measurement is
found the way Explorer finds it. Without the dedupe, `verify` finds the `retried`, `repeat_postcan` and held
measurements in fastpath twice (31 in the test). Reuploading an `already_ingested` postcan doesn't duplicate it in
fastpath (same uid, same key), but it does add a second copy to the raw cans.

Requirements are the same as `tests/uploader_e2e`. CI: `.github/workflows/test_repair_overwritten_cans.yml`.
