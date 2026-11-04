"""When ooni_clickhouse_backup.py starts a full backup and what it prunes, over months of daily or weekly runs,
some of them failing. ClickHouse and the bucket are stubbed; test_e2e.py runs the real thing.
    python3 -m unittest test_schedule"""
import importlib.util
import json
import os
import unittest
from datetime import datetime, timedelta, timezone

spec = importlib.util.spec_from_file_location(
    "backup", os.path.join(os.path.dirname(__file__), "..", "files", "ooni_clickhouse_backup.py")
)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)

START = datetime(2026, 10, 23, 2, 30, tzinfo=timezone.utc)  # a Friday


class FakeStore:
    """The bucket. Backups under prod/: c = {chain: {"backups": {backup: complete}, "keep": []}}; under staging/:
    staged = {(chain, backup): complete}, and pins = {chain: [labels]}. Each backup's objects are written at the time
    its name says. With lock_s, prod/ has a lock rule: deleting anything younger is refused, and recorded."""

    def __init__(self, lock_s=0):
        self.c, self.staged_, self.pins, self.lock_s, self.refused = {}, {}, {}, lock_s, []
        self.prefix, self.staging = "prod", "staging"

    def table_prefix(self, db, table, staging=False):
        return f"{'staging' if staging else 'prod'}/{db}/{table}/"

    def ch_s3(self, key):
        return f"'{key}'"

    def chains(self, db, table):
        out = {k: {"backups": dict(e["backups"]), "keep": list(e["keep"])} for k, e in self.c.items()}
        for chain, labels in self.pins.items():
            out.setdefault(chain, {"backups": {}, "keep": []})["keep"] += labels
        return out

    def staged(self, db, table):
        return sorted((c, b, ok) for (c, b), ok in self.staged_.items())

    @staticmethod
    def parse(prefix):
        """(root, chain, backup or None)"""
        parts = prefix.rstrip("/").split("/")
        return (parts[0], parts[3], parts[4]) if len(parts) > 4 else (parts[0], parts[3], None)

    def newest(self, prefix):
        _, chain, b = self.parse(prefix)
        names = [b] if b else list(self.c.get(chain, {"backups": {}})["backups"])
        return max((backup.parse_ts(n) for n in names), default=None)

    def move(self, src, dst):
        _, chain, b = self.parse(src)
        assert self.staged_[(chain, b)], "only complete backups are moved"
        assert dst.startswith("prod/")
        self.c.setdefault(chain, {"backups": {}, "keep": []})["backups"][b] = True
        del self.staged_[(chain, b)]
        return 1

    def delete_prefix(self, prefix):
        root, chain, b = self.parse(prefix)
        if root == "staging":
            self.staged_.pop((chain, b), None)
            return 1
        newest = self.newest(prefix)
        if self.lock_s and newest and newest + backup.timedelta(seconds=self.lock_s) > backup.utcnow():
            self.refused.append(prefix)
            raise RuntimeError(f"objects not deleted under {prefix}: ObjectLockedByBucketPolicy")
        if b:
            self.c[chain]["backups"].pop(b, None)
        else:
            self.c.pop(chain, None)
        return 1

    def exists(self, key):
        _, chain, name = self.parse(key)
        return name.startswith("KEEP-") and name[5:] in self.pins.get(chain, [])

    def put_empty(self, key):
        _, chain, name = self.parse(key)
        assert key.startswith("staging/") and name.startswith("KEEP-"), key
        self.pins.setdefault(chain, []).append(name[5:])


class FakeClickHouse:
    """Takes a backup, or fails one part-way: files uploaded, no .backup. Records each incremental's base."""

    def __init__(self, store):
        self.store, self.fail, self.bases = store, False, []

    def query(self, sql, settings=None, timeout=600):
        key = sql.split("TO S3('")[1].split("'")[0]
        assert key.startswith("staging/"), "ClickHouse writes under staging/ only"
        chain, name = key.split("/")[-2:]
        if "base_backup" in sql:
            self.bases.append(sql.split("base_backup = S3('")[1].split("'")[0])
        self.store.staged_[(chain, name)] = not self.fail
        if self.fail:
            raise RuntimeError("BACKUP_FAILED")
        return json.dumps({"id": "op"})


def new_job(lock_days=0):
    job = backup.BackupJob.__new__(backup.BackupJob)
    job.db, job.name, job.keep_chains, job.settings = "ooni", "t", 2, {}
    job.lock_s = lock_days * 86400
    job.store = FakeStore(job.lock_s)
    job.ch = FakeClickHouse(job.store)
    job.metrics = backup.Metrics()
    job.wait = lambda op, what: {"num_files": 1, "uncompressed_size": 1}
    return job


def runs(every_days, until, failing=(), jitter=True, job=None, start=START):
    """Back up a table at 02:30 UTC daily or on Sundays from start. Yields (day, full, complete chains)."""
    job = job or new_job()
    t, n = start, 0
    while t < until:
        # a table's backup starts a few minutes earlier or later each time
        now = t + timedelta(minutes=9 if n % 2 else -7)
        backup.utcnow = lambda now=now: now
        job.ch.fail = now.date().isoformat() in failing
        try:
            full = job.backup_table("obs_web", "ReplicatedMergeTree", False, "")
        except RuntimeError:
            full = None
        complete = sorted(c for c, e in job.store.c.items() if any(e["backups"].values()))
        yield now.date().isoformat(), full, complete
        n += 1
        if every_days == 7:
            t += timedelta(days=(6 - t.weekday()) % 7 or 7)  # the next Sunday
        else:
            t += timedelta(days=1)


class TestSchedule(unittest.TestCase):
    def fulls(self, every_days):
        return [day for day, full, _ in runs(every_days, datetime(2027, 4, 1, tzinfo=timezone.utc)) if full]

    def test_weekly_fulls_on_the_first_sunday_of_each_month(self):
        self.assertEqual(
            self.fulls(7), ["2026-10-23", "2026-11-01", "2026-12-06", "2027-01-03", "2027-02-07", "2027-03-07"]
        )

    def test_daily_fulls_on_the_first_of_each_month(self):
        self.assertEqual(
            self.fulls(1), ["2026-10-23", "2026-11-01", "2026-12-01", "2027-01-01", "2027-02-01", "2027-03-01"]
        )

    def test_two_complete_chains_kept(self):
        *_, (day, _, complete) = runs(7, datetime(2027, 4, 1, tzinfo=timezone.utc))
        self.assertEqual([c[:8] for c in complete], ["20270207", "20270307"])

    def test_failed_fulls_prune_nothing_and_are_retried(self):
        failing = {"2026-12-06", "2026-12-13", "2027-02-07", "2027-02-14", "2027-02-21", "2027-02-28", "2027-03-07"}
        before = []
        for day, full, complete in runs(7, datetime(2027, 5, 1, tzinfo=timezone.utc), failing):
            month = day[:7].replace("-", "")
            if not any(c.startswith(month) for c in complete):
                # no complete full this month yet: every complete chain from before is still there
                self.assertTrue(set(before) <= set(complete), f"{day}: deleted {set(before) - set(complete)}")
            if day in failing:
                self.assertIsNone(full, day)
            before = complete
        self.assertEqual([c[:8] for c in complete], ["20270314", "20270404"])

    def test_never_fewer_than_two_complete_chains(self):
        # fulls and incrementals failing (cancelled, killed): from the second month's full on, two complete
        # chains at every step
        failing = {"2026-11-08", "2026-11-15", "2026-12-06", "2026-12-13", "2027-01-10", "2027-02-07", "2027-03-21"}
        for day, full, complete in runs(7, datetime(2027, 5, 1, tzinfo=timezone.utc), failing):
            if day >= "2026-11-01":
                self.assertGreaterEqual(len(complete), 2, f"{day}: {complete}")

    def test_a_failed_incremental_is_removed_and_the_next_builds_on_the_last_complete_one(self):
        job = new_job()
        list(runs(7, datetime(2026, 11, 20, tzinfo=timezone.utc), {"2026-11-15"}, job=job))
        nov = job.store.c[max(job.store.c)]["backups"]
        self.assertEqual([b[:8] for b in sorted(nov)], ["20261101", "20261108"])
        (staged,) = job.store.staged("ooni", "obs_web")
        self.assertEqual((staged[1][:8], staged[2]), ("20261115", False), "the failed incremental, in staging: no .backup")
        job.ch.fail = False
        sql = []
        query = job.ch.query
        job.ch.query = lambda q, **kw: sql.append(q) or query(q, **kw)
        backup.utcnow = lambda: datetime(2026, 11, 22, 2, 30, tzinfo=timezone.utc)
        job.backup_table("obs_web", "ReplicatedMergeTree", False, "")
        nov = job.store.c[max(job.store.c)]["backups"]
        self.assertEqual([b[:8] for b in sorted(nov)], ["20261101", "20261108", "20261122"])
        self.assertIn("20261108", sql[0].split("base_backup")[1], "the incremental's base")
        self.assertEqual(job.store.staged("ooni", "obs_web"), [], "the failed one removed from staging")

    def test_a_prune_cut_short_is_finished_by_the_next_run(self):
        # killed while deleting the oldest chain: its full's .backup went first (keys are deleted in order),
        # its incremental's is left, so it still counts as complete, though it can't be restored
        job = new_job()
        job.store.c = {
            "20260906T023000Z": {"backups": {"20260906T023000Z": False, "20260913T023000Z": True}, "keep": []},
            "20261004T023000Z": {"backups": {"20261004T023000Z": True}, "keep": []},
            "20261101T023000Z": {"backups": {"20261101T023000Z": True}, "keep": []},
        }
        backup.utcnow = lambda: datetime(2026, 11, 8, 2, 30, tzinfo=timezone.utc)
        self.assertFalse(job.backup_table("obs_web", "ReplicatedMergeTree", False, ""), "an incremental")
        self.assertEqual(sorted(job.store.c), ["20261004T023000Z", "20261101T023000Z"])
        self.assertEqual(sorted(job.store.c["20261101T023000Z"]["backups"]), ["20261101T023000Z", "20261108T023000Z"])


class TestLockedBucket(unittest.TestCase):
    """prod/ under a 45-day lock rule, as group_vars has it, over 14 months of weekly runs. Fulls fail on the first
    Sunday of December and of May (taken again a week later), incrementals now and then."""

    FAILING = {"2026-12-06", "2027-01-17", "2027-03-14", "2027-05-02", "2027-08-15", "2027-10-10"}

    def setUp(self):
        self.job = new_job(lock_days=45)
        self.steps = list(runs(7, datetime(2028, 1, 1, tzinfo=timezone.utc), self.FAILING, job=self.job))

    def test_no_delete_is_refused(self):
        self.assertEqual(self.job.store.refused, [], "the script never deletes what the lock still holds")

    def test_a_complete_chain_is_always_locked(self):
        # its full can't be deleted with the hosts' key, so it can always be restored
        for day, _, complete in self.steps:
            now = datetime.fromisoformat(day).replace(tzinfo=timezone.utc)
            locked = [c for c in complete if now - backup.parse_ts(c) < timedelta(days=45)]
            self.assertTrue(locked, f"{day}: no complete chain younger than the lock: {complete}")

    def test_the_old_chain_is_pruned_once_the_lock_lets_it(self):
        for day, _, complete in self.steps:
            self.assertLessEqual(len(complete), 3, day)
            if day >= "2027-01-01" and int(day[8:]) >= 22:
                self.assertEqual(len(complete), 2, f"{day}: {complete}")

    def test_incrementals_are_based_on_the_locked_copy(self):
        self.assertTrue(self.job.ch.bases)
        self.assertTrue(all(b.startswith("prod/") for b in self.job.ch.bases), self.job.ch.bases[:3])

    def test_staging_is_left_empty(self):
        self.assertEqual(self.job.store.staged("ooni", "obs_web"), [], "the last run succeeded")

    def test_a_pinned_chain_outlives_the_lock(self):
        job = new_job(lock_days=45)
        list(runs(7, datetime(2026, 11, 2, tzinfo=timezone.utc), job=job))
        first = min(job.store.c)
        job.store.pins[first] = ["release-x"]
        list(runs(7, datetime(2027, 6, 1, tzinfo=timezone.utc), job=job, start=datetime(2026, 11, 8, 2, 30, tzinfo=timezone.utc)))
        self.assertIn(first, job.store.c, "pinned: never pruned")
        self.assertEqual(len([c for c in job.store.c if c != first]), 2)


if __name__ == "__main__":
    unittest.main()
