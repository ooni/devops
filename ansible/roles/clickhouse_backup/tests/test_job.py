"""How a job runs and what it reports, with ClickHouse stubbed; test_e2e.py runs the real thing.
    python3 -m unittest test_job"""
import importlib.util
import json
import os
import tempfile
import unittest
import urllib.error
from unittest import mock

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
        jobs = [job("measurements", include=["*"], exclude=["msmt_feedback"]), job("private", include=["msmt_feedback"])]
        selected, orphans = backup.jobs_for_tables(jobs, ["msmt_feedback"])
        self.assertEqual([j.name for j in selected], ["private"])
        self.assertEqual(orphans, [])

    def test_tables_no_job_backs_up(self):
        jobs = [job("private", include=["msmt_feedback"])]
        self.assertEqual(backup.jobs_for_tables(jobs, ["fastpath"]), ([], ["fastpath"]))


class TestIncludeTables(unittest.TestCase):
    def test_star_is_every_table(self):
        self.assertTrue(job(include=["*"]).includes("fastpath"))

    def test_an_empty_list_is_no_table(self):
        # once data1's list of its own tables is emptied, data1 mustn't back up everything
        self.assertFalse(job(include=[]).includes("msmt_feedback"))

    def test_a_config_without_jobs_backs_up_every_table(self):
        [conf] = backup.job_confs({"exclude_tables": ["*_tmp"]}, [])
        self.assertEqual(conf["include_tables"], ["*"])


class TestForget(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.metrics = backup.Metrics(os.path.join(d, "out.prom"), os.path.join(d, "state.json"))
        for job_, table in [("data1", "labeling_frames"), ("data1", "changepoint_label"), ("private", "msmt_feedback")]:
            self.metrics.table_result(job_, table, True, {"total_size": 1, "num_files": 1})
        self.metrics.job_running("old_job", False)

    def tables(self):
        return sorted(self.metrics.state["tables"])

    def test_a_table_the_job_no_longer_selects(self):
        # labeling_frames was replicated, and moved from data1's job to data3's
        self.metrics.forget_tables("data1", {"changepoint_label"})
        self.assertEqual(self.tables(), ["data1/changepoint_label", "private/msmt_feedback"])

    def test_a_job_no_longer_configured(self):
        self.metrics.forget_jobs({"data1"})
        self.assertEqual(self.tables(), ["data1/changepoint_label", "data1/labeling_frames"])
        self.assertNotIn("old_job", self.metrics.state["running"])

    def test_a_run_with_table_forgets_nothing(self):
        j = job("data1", include=["*"], metrics=self.metrics)
        j.running_backups = lambda: []
        j.tables = lambda only: ([("changepoint_label", "MergeTree")], [])
        j.backup_table = lambda *a: False
        j.run(["changepoint_label"], False, "")
        self.assertIn("data1/labeling_frames", self.tables())
        j.run([], False, "")
        self.assertNotIn("data1/labeling_frames", self.tables())


class TestClickHouseErrors(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.metrics = backup.Metrics(os.path.join(d, "out.prom"), os.path.join(d, "state.json"))

    def test_waits_for_clickhouse_at_start(self):
        j = job(metrics=self.metrics, ch=FlakyClickHouse(failures=2))
        j.clickhouse_wait_s = 60
        with mock.patch.object(backup.time, "sleep"):
            j.wait_for_clickhouse()
        self.assertEqual(j.ch.calls, 3)

    def test_a_job_that_cant_start_marks_its_tables_failed(self):
        self.metrics.table_result("measurements", "fastpath", True, {"total_size": 1, "num_files": 1})
        self.metrics.table_result("private", "msmt_feedback", True, {"total_size": 1, "num_files": 1})
        j = job(metrics=self.metrics, ch=FlakyClickHouse(failures=1000))
        self.assertEqual(j.run([], False, ""), 1)
        tables = self.metrics.state["tables"]
        self.assertEqual(tables["measurements/fastpath"]["last_failed"], 1)
        self.assertEqual(tables["private/msmt_feedback"]["last_failed"], 0, "another job's table")
        self.assertNotIn("measurements", self.metrics.state["runs"], "no completed run to report")

    def test_a_failed_poll_is_retried(self):
        j = job(ch=FlakyClickHouse(failures=2))
        self.assertEqual(j.wait("op", "obs_web")["status"], "BACKUP_CREATED")
        self.assertEqual(j.ch.calls, 3)


if __name__ == "__main__":
    unittest.main()
