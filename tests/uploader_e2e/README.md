# Measurement uploader end-to-end test

Runs `ansible/roles/fastpath/templates/ooni_api_uploader.py` against the real pieces it works with and checks
that every measurement can still be found the way Explorer finds it:

- the fastpath image production runs (`fastpath_image` in `ansible/host_vars/fastpath.prod.ooni.io/vars.yml`),
  receiving measurements over HTTP and writing them to its spool (`--write-to-disk`);
- MinIO with versioning on, standing in for `ooni-data-eu-fra` (raw cans) and the failed-reports bucket;
- ClickHouse 24.8.6.70 with the `jsonl` and `fastpath` tables;
- the uploader in its production runtime (Ubuntu 22.04 and its apt packages, `Dockerfile.uploader`);
- the reuploader from ooni/backend, at master and at the version production runs.

`poster.py` submits real measurements (one public can from `ooni-data-eu-fra`, downloaded on first run) the
way the ooniprobe service does: it mints the measurement_uid from the submission time, POSTs to the fastpath,
and writes to the failed-reports bucket when that fails. `check.py` then looks every measurement up with the
same query and fetch as oonimeasurements (`jsonl` row -> `s3path`, `linenum` -> body) and compares the body.

## Scenarios
1. A normal hour.
2. Measurements written to the spool after their hour was uploaded (fastpath workers suspended, then
   resumed), as on 2026-07-14.
3. A full fastpath queue: requests time out, measurements go to the failed-reports bucket.
4. The reuploader re-sending them into hours already uploaded: production's version (never deletes) twice,
   then master's.
5. S3 unreachable during an upload, and two uploader runs at once.

The run fails if any measurement is not found or comes back with another measurement's body, if any S3
object was replaced, or if anything is left in the spool or the failed-reports bucket.

## Running it
```
cd tests/uploader_e2e
docker build -t ooni-uploader-e2e -f Dockerfile.uploader .
pip install boto3 requests clickhouse-driver
REUPLOADER_NEW=../../../backend/reuploader/src/reuploader/main.py ./scenario.sh local
```
About 20 minutes. `DOCKER=podman` works too; `UPLOADER=<file>` tests another version of the uploader
(the version before 2026-10 fails it: replaced cans, measurements found with another's body, measurements
lost when S3 is unreachable). Logs and results are in `work/`. CI: `.github/workflows/test_uploader_e2e.yml`.
