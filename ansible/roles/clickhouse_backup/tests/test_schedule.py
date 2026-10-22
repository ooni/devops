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


def runs(every_days, until, failing=(), jitter=True):
    """Back up a table at 02:30 UTC daily or on Sundays from START. Yields (day, full, complete chains)."""
    job = backup.BackupJob.__new__(backup.BackupJob)
    job.db, job.name, job.keep_chains, job.settings = "ooni", "t", 2, {}
    job.store = FakeStore()
    job.ch = FakeClickHouse(job.store)
    job.metrics = backup.Metrics()
    job.wait = lambda op, what: {"num_files": 1, "uncompressed_size": 1}
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


if __name__ == "__main__":
    unittest.main()
