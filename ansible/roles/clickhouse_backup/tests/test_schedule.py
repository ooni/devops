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
    """The bucket: {chain: {"backups": {backup: complete}, "keep": [labels]}}"""

    def __init__(self):
        self.c = {}

    def table_prefix(self, db, table):
        return f"{db}/{table}/"

    def ch_s3(self, key):
        return f"'{key}'"

    def chains(self, db, table):
        return {k: {"backups": dict(e["backups"]), "keep": list(e["keep"])} for k, e in self.c.items()}

    def delete_prefix(self, prefix):
        parts = prefix.rstrip("/").split("/")
        if parts[-2] in self.c:  # one backup of a chain
            self.c[parts[-2]]["backups"].pop(parts[-1], None)
        else:
            self.c.pop(parts[-1], None)
        return 1

    def put_empty(self, key):
        pass


class FakeClickHouse:
    """Takes a backup, or fails one part-way: files uploaded, no .backup"""

    def __init__(self, store):
        self.store, self.fail = store, False

    def query(self, sql, settings=None, timeout=600):
        chain, name = sql.split("TO S3('")[1].split("'")[0].split("/")[-2:]
        self.store.c.setdefault(chain, {"backups": {}, "keep": []})["backups"][name] = not self.fail
        if self.fail:
            raise RuntimeError("BACKUP_FAILED")
        return json.dumps({"id": "op"})


def new_job():
    job = backup.BackupJob.__new__(backup.BackupJob)
    job.db, job.name, job.keep_chains, job.settings = "ooni", "t", 2, {}
    job.store = FakeStore()
    job.ch = FakeClickHouse(job.store)
    job.metrics = backup.Metrics()
    job.wait = lambda op, what: {"num_files": 1, "uncompressed_size": 1}
    return job


def runs(every_days, until, failing=(), jitter=True, job=None):
    """Back up a table at 02:30 UTC daily or on Sundays from START. Yields (day, full, complete chains)."""
    job = job or new_job()
    t, n = START, 0
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
        self.assertEqual([b[:8] for b in sorted(nov)], ["20261101", "20261108", "20261115"])
        self.assertFalse(nov[max(nov)], "the failed incremental: files but no .backup")
        job.ch.fail = False
        sql = []
        query = job.ch.query
        job.ch.query = lambda q, **kw: sql.append(q) or query(q, **kw)
        backup.utcnow = lambda: datetime(2026, 11, 22, 2, 30, tzinfo=timezone.utc)
        job.backup_table("obs_web", "ReplicatedMergeTree", False, "")
        nov = job.store.c[max(job.store.c)]["backups"]
        self.assertEqual([b[:8] for b in sorted(nov)], ["20261101", "20261108", "20261122"])
        self.assertIn("20261108", sql[0].split("base_backup")[1], "the incremental's base")

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


if __name__ == "__main__":
    unittest.main()
