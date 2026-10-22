"""How a job runs and what it reports, with ClickHouse stubbed; test_e2e.py runs the real thing.
    python3 -m unittest test_job"""
import importlib.util
import json
import os
import tempfile
import unittest
import urllib.error

spec = importlib.util.spec_from_file_location(
    "backup", os.path.join(os.path.dirname(__file__), "..", "files", "ooni_clickhouse_backup.py")
)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class FlakyClickHouse:
    """Fails the first `failures` calls with a connection error, then answers"""

    def __init__(self, failures=0, status="BACKUP_CREATED"):
        self.failures, self.status, self.calls = failures, status, 0

    def query(self, sql, settings=None, timeout=600):
        self.calls += 1
        if self.calls <= self.failures:
            raise urllib.error.URLError("Connection refused")
        return ""

    def rows(self, sql, **kw):
        self.query(sql)
        if "system.backups WHERE id" in sql:
            return [{"status": self.status, "error": "", "num_files": 1, "total_size": 1, "uncompressed_size": 1}]
        return []


def job(name="measurements", include=(), exclude=(), metrics=None, ch=None):
    j = backup.BackupJob.__new__(backup.BackupJob)
    j.name, j.include, j.exclude = name, list(include), list(exclude)
    j.metrics = metrics or backup.Metrics()
    j.ch = ch or FlakyClickHouse()
    j.poll_s, j.clickhouse_wait_s = 0, 0
    return j


class TestRunningSince(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.metrics = backup.Metrics(os.path.join(d, "out.prom"), os.path.join(d, "state.json"))

    def test_running_since_is_set_while_a_job_runs(self):
        self.metrics.job_running("measurements", True)
        self.assertGreater(self.metrics.state["running_since"]["measurements"], 0)
        with open(self.metrics.metrics_file) as f:
            self.assertIn('ooni_clickhouse_backup_running_since_timestamp_seconds{backup="measurements"}', f.read())
        self.metrics.job_running("measurements", False)
        self.assertEqual(self.metrics.state["running_since"]["measurements"], 0)

    def test_old_state_files_still_load(self):
        with open(self.metrics.state_file, "w") as f:
            json.dump({"tables": {}, "running": {"measurements": 0}}, f)
        m = backup.Metrics(self.metrics.metrics_file, self.metrics.state_file)
        m.job_running("measurements", True)
        self.assertIn("measurements", m.state["running_since"])


class TestRunTable(unittest.TestCase):
    def test_only_the_jobs_that_back_up_the_tables(self):
        jobs = [job("measurements", exclude=["msmt_feedback"]), job("private", include=["msmt_feedback"])]
        selected, orphans = backup.jobs_for_tables(jobs, ["msmt_feedback"])
        self.assertEqual([j.name for j in selected], ["private"])
        self.assertEqual(orphans, [])

    def test_tables_no_job_backs_up(self):
        jobs = [job("private", include=["msmt_feedback"])]
        self.assertEqual(backup.jobs_for_tables(jobs, ["fastpath"]), ([], ["fastpath"]))


if __name__ == "__main__":
    unittest.main()
