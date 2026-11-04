"""How a job runs and what it reports, with ClickHouse stubbed; test_e2e.py runs the real thing.
    python3 -m unittest test_job"""
import importlib.util
import json
import os
import tempfile
import types
import unittest
import urllib.error
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "backup", os.path.join(os.path.dirname(__file__), "..", "files", "ooni_clickhouse_backup.py")
)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)
backup.log.disabled = True  # the tests check results, not log lines


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


class TestStoreAndState(unittest.TestCase):
    def test_only_this_buckets_running_backups(self):
        j = job()
        j.store = types.SimpleNamespace(ch_base="https://r2.example/ooni-clickhouse-backup", prefix="prod", staging="staging/prod")
        j.ch = types.SimpleNamespace(rows=lambda sql: [
            {"id": "1", "name": "S3('https://r2.example/ooni-clickhouse-backup-private/staging/prod/ooni/msmt_feedback/a/b')"},
            {"id": "2", "name": "S3('https://r2.example/ooni-clickhouse-backup/staging/prod/ooni/fastpath/a/b')"},
            {"id": "3", "name": "S3('https://r2.example/ooni-clickhouse-backup/staging/test/ooni/fastpath/a/b')"},
        ])
        self.assertEqual([r["id"] for r in j.running_backups()], ["2"])

    def test_objects_not_deleted_are_an_error(self):
        store = backup.Store.__new__(backup.Store)
        store.bucket, store.prefix, store.staging = "b", "prod", "staging/prod"
        store.s3 = types.SimpleNamespace(
            get_paginator=lambda name: types.SimpleNamespace(paginate=lambda **kw: [{"Contents": [{"Key": "prod/ooni/t/c/x"}]}]),
            delete_objects=lambda **kw: {"Errors": [{"Key": "prod/ooni/t/c/x", "Code": "AccessDenied", "Message": "no"}]},
        )
        with self.assertRaisesRegex(RuntimeError, "1 objects not deleted"):
            store.delete_prefix("prod/ooni/t/c/")

    def test_an_unreadable_state_file_starts_empty(self):
        d = tempfile.mkdtemp()
        state = os.path.join(d, "state.json")
        with open(state, "w") as f:
            f.write("")  # e.g. truncated by a power loss
        m = backup.Metrics(os.path.join(d, "out.prom"), state)
        m.job_running("measurements", True)
        self.assertEqual(m.state["running"], {"measurements": 1})


class MemoryS3:
    """Enough of boto3's S3 client for Store: objects in a dict, every call logged. Keys under `locked` can't be
    deleted or overwritten, as under a bucket lock."""

    def __init__(self, objects, locked=()):
        self.objects, self.locked, self.calls = dict(objects), tuple(locked), []

    def get_paginator(self, name):
        def paginate(Bucket, Prefix, Delimiter=None):
            return [{"Contents": [{"Key": k, "Size": len(v), "LastModified": 0}
                                  for k, v in sorted(self.objects.items()) if k.startswith(Prefix)]}]
        return types.SimpleNamespace(paginate=paginate)

    def copy(self, src, bucket, key, Config=None):
        if key in self.objects and key.startswith(self.locked):
            raise RuntimeError(f"ObjectLockedByBucketPolicy: {key}")
        self.calls.append(("copy", key))
        self.objects[key] = self.objects[src["Key"]]

    def delete_object(self, Bucket, Key):
        self.calls.append(("delete", Key))
        self.objects.pop(Key, None)

    def delete_objects(self, Bucket, Delete, **kw):
        for o in Delete["Objects"]:
            self.calls.append(("delete", o["Key"]))
            self.objects.pop(o["Key"], None)
        return {}


class TestMove(unittest.TestCase):
    SRC, DST = "staging/prod/ooni/t/c/b/", "prod/ooni/t/c/b/"

    def store(self, objects):
        store = backup.Store.__new__(backup.Store)
        store.bucket, store.prefix, store.staging, store.transfer = "b", "prod", "staging/prod", None
        store.s3 = MemoryS3(objects, locked=["prod/"])
        return store

    def test_a_backup_is_copied_backup_file_last_then_removed_backup_file_first(self):
        store = self.store({self.SRC + ".backup": "m", self.SRC + "data/1": "aa", self.SRC + "data/2": "bbb"})
        self.assertEqual(store.move(self.SRC, self.DST), 3)
        self.assertEqual(set(store.s3.objects), {self.DST + ".backup", self.DST + "data/1", self.DST + "data/2"})
        copies = [k for op, k in store.s3.calls if op == "copy"]
        deletes = [k for op, k in store.s3.calls if op == "delete"]
        self.assertEqual(copies[-1], self.DST + ".backup", "a copy is complete only once its .backup is there")
        self.assertEqual(deletes[0], self.SRC + ".backup", "what a cut short delete leaves is incomplete")

    def test_a_move_cut_short_is_finished_without_overwriting(self):
        # the locked copy has one file already; copying it again would be refused
        store = self.store({self.SRC + ".backup": "m", self.SRC + "data/1": "aa", self.SRC + "data/2": "bbb",
                            self.DST + "data/1": "aa"})
        store.move(self.SRC, self.DST)
        self.assertEqual([k for op, k in store.s3.calls if op == "copy"], [self.DST + "data/2", self.DST + ".backup"])
        self.assertFalse([k for k in store.s3.objects if k.startswith("staging/")])

    def test_an_incomplete_backup_isnt_moved(self):
        store = self.store({self.SRC + "data/1": "aa"})
        with self.assertRaisesRegex(RuntimeError, "isn't a complete backup"):
            store.move(self.SRC, self.DST)
        self.assertEqual(store.s3.calls, [])

    def test_a_copy_that_didnt_arrive_is_an_error_and_nothing_is_removed(self):
        store = self.store({self.SRC + ".backup": "m", self.SRC + "data/1": "aa"})
        copy = store.s3.copy
        store.s3.copy = lambda src, b, key, Config=None: None if key.endswith("data/1") else copy(src, b, key, Config)
        with self.assertRaisesRegex(RuntimeError, "1 objects of .* not copied"):
            store.move(self.SRC, self.DST)
        self.assertIn(self.SRC + "data/1", store.s3.objects)
        self.assertNotIn(self.DST + ".backup", store.s3.objects, "not complete where it's locked")


class TestNotBackedUp(unittest.TestCase):
    def test_tables_no_job_covers(self):
        jobs = [job("measurements", include=["*"], exclude=["msmt_feedback", "labeling_frames", "*_tmp"]),
                job("private", include=["msmt_feedback"])]
        tables = {
            "fastpath": ["data1", "data2", "data3"],         # replicated: measurements
            "msmt_feedback": ["data1", "data2", "data3"],    # private
            "labeling_frames": ["data1", "data2", "data3"],  # data1 backs it up
            "asnmeta_tmp": ["data1"],                         # excluded
            "fingerprints_dns": ["data1", "data2"],           # excluded: rebuilt hourly
            "made_on_data1": ["data1"],                       # nothing: data3 doesn't have it
        }
        missing = backup.not_backed_up(tables, "data3", jobs, ["*_tmp", "fingerprints_*"], ["labeling_frames"])
        self.assertEqual(missing, {"made_on_data1": ["data1"]})

    def test_the_metric_names_the_table_and_its_hosts(self):
        d = tempfile.mkdtemp()
        m = backup.Metrics(os.path.join(d, "out.prom"), os.path.join(d, "state.json"))
        m.not_backed_up({"made_on_data1": ["data2", "data1"]})
        with open(m.metrics_file) as f:
            self.assertIn('ooni_clickhouse_backup_table_not_backed_up{table="made_on_data1",hosts="data1,data2"} 1', f.read())
        m.not_backed_up({})
        with open(m.metrics_file) as f:
            self.assertNotIn("made_on_data1", f.read())


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


class TestInterruptions(unittest.TestCase):
    """ClickHouse restarted mid-backup, or gone for good"""

    def setUp(self):
        d = tempfile.mkdtemp()
        self.metrics = backup.Metrics(os.path.join(d, "out.prom"), os.path.join(d, "state.json"))
        self.calls = []
        self.failing = {}  # table: the exception its next backup raises
        self.j = job(metrics=self.metrics)
        self.j.running_backups = lambda: []
        self.j.wait_for_clickhouse = lambda: None
        self.j.tables = lambda only: ([("fastpath", "MergeTree"), ("obs_web", "MergeTree"), ("test_groups", "EmbeddedRocksDB")], [])
        self.j.backup_table = self.backup_table

    def backup_table(self, table, engine, full, keep):
        self.calls.append((table, full, keep))
        if table in self.failing:
            raise self.failing.pop(table)
        self.metrics.table_result(self.j.name, table, True, {"total_size": 1, "num_files": 1})
        return full

    def tables_called(self):
        return [t for t, _, _ in self.calls]

    def test_a_table_cancelled_by_a_restart_starts_again(self):
        self.failing["obs_web"] = RuntimeError("obs_web: gone from system.backups (server restart?)")
        self.j.restarted_since = lambda t: True
        self.assertEqual(self.j.run([], False, ""), 0)
        self.assertEqual(self.tables_called(), ["fastpath", "obs_web", "obs_web", "test_groups"])

    def test_a_failure_without_a_restart_isnt_retried(self):
        self.failing["obs_web"] = RuntimeError("BACKUP_FAILED")
        self.j.restarted_since = lambda t: False
        waited = []
        self.j.wait_for_running_backups = lambda: waited.append(True)
        self.assertEqual(self.j.run([], False, ""), 1)
        self.assertEqual(self.tables_called(), ["fastpath", "obs_web", "test_groups"])
        self.assertEqual(waited, [True], "the next table waits for the failed one's BACKUP, if still running")
        self.assertEqual(self.metrics.state["tables"]["measurements/obs_web"]["last_failed"], 1)

    def test_clickhouse_gone_stops_the_run(self):
        self.failing["obs_web"] = RuntimeError("Connection refused")

        def down():  # up when the run starts, then gone after obs_web's backup fails
            if self.tables_called():
                raise backup.ClickHouseDown("ClickHouse not answering after 600s")
        self.j.wait_for_clickhouse = down
        self.assertEqual(self.j.run([], False, ""), 1)
        self.assertEqual(self.tables_called(), ["fastpath", "obs_web"], "test_groups isn't tried")

    def test_restarted_since(self):
        self.j.ch = types.SimpleNamespace(query=lambda sql, timeout=600: "100\n")
        self.assertTrue(self.j.restarted_since(backup.time.time() - 200))
        self.assertFalse(self.j.restarted_since(backup.time.time() - 50))


class TestUnsupportedNames(unittest.TestCase):
    def test_a_table_whose_name_cant_be_backed_up_is_reported_failed(self):
        d = tempfile.mkdtemp()
        metrics = backup.Metrics(os.path.join(d, "out.prom"), os.path.join(d, "state.json"))
        j = job(include=["*"], metrics=metrics)
        j.db = "ooni"
        j.ch = types.SimpleNamespace(rows=lambda sql, **kw: [
            {"name": "fastpath", "engine": "MergeTree"}, {"name": "bad-name", "engine": "MergeTree"}])
        j.running_backups = lambda: []
        j.wait_for_clickhouse = lambda: None
        j.backup_table = lambda *a: False
        self.assertEqual(j.run([], False, ""), 1)
        entry = metrics.state["tables"]["measurements/bad-name"]
        self.assertEqual(entry["last_failed"], 1, "kept after the run: forget_tables mustn't drop it")


if __name__ == "__main__":
    unittest.main()
