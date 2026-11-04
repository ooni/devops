#!/usr/bin/env python3
"""
Uploads OONI API measurements to S3
Reads /etc/ooni/api.conf
"""

from configparser import ConfigParser
from pathlib import Path
from pathlib import PosixPath as PP
from datetime import datetime, timedelta
from typing import List, Dict
import fcntl
import gzip
import logging
import re
import tarfile
import time
import yaml

import ujson
import boto3
import statsd  # debdeps: python3-statsd

# debdeps: python3-clickhouse-driver
from clickhouse_driver import Client as Clickhouse


metrics = statsd.StatsClient("127.0.0.1", 8125, prefix="ooni_api_uploader")
log = logging.getLogger("ooni_api_uploader")

try:
    from systemd.journal import JournalHandler  # debdeps: python3-systemd

    log.addHandler(JournalHandler(SYSLOG_IDENTIFIER="ooni_api_uploader"))
except ImportError:
    pass

log.setLevel(logging.DEBUG)


def create_s3_client(conf):
    session = boto3.Session(
        aws_access_key_id=conf.get("aws_access_key_id"),
        aws_secret_access_key=conf.get("aws_secret_access_key"),
    )
    return session.resource("s3")


def read_conf():
    cf = "/etc/ooni/api-uploader.conf"
    log.info(f"Starting. Reading {cf}")
    conf = ConfigParser()
    conf.read(cf)
    return conf["DEFAULT"]


def connect_to_db(conf):
    default = "clickhouse://api:api@localhost/default"
    uri = conf.get("db_uri", default)
    log.debug(f"Connecting to database on {uri}")
    conn = Clickhouse.from_url(uri)
    return conn


@metrics.timer("update_db_table")
def update_db_table(conn, lookup_list, jsonl_s3path):
    for d in lookup_list:
        d["s3path"] = jsonl_s3path

    q = "INSERT INTO jsonl (report_id, input, s3path, linenum, measurement_uid) VALUES"
    log.info(f"Writing {len(lookup_list)} rows to DB")
    conn.execute(q, lookup_list)


@metrics.timer("upload_measurement")
def upload_to_s3(s3, bucket_name: str, tarf: PP, s3path: str) -> None:
    obj = s3.Object(bucket_name, s3path)
    log.info(f"Uploading {s3path}")
    obj.put(Body=tarf.read_bytes())


def first_free_can_index(s3, bucket_name: str, s3dir: str, basename: str) -> int:
    """Index of the first can of this run for an hour, cc and test name.

    Measurements for an hour can reach the spool after the hour has been
    uploaded (a fastpath backlog, or the reuploader re-sending old
    measurements, which keep their measurement_uid and so their hour). The
    next run then finds the hour's directory again. Numbering its cans from 0
    would overwrite the cans already on S3 for that hour, and the jsonl rows
    pointing into them, so continue after the highest index already there.

    s3dir is "raw/<YYYYMMDD>/<HH>/<cc>/<testname>/", basename
    "<YYYYMMDDHH>_<cc>_<testname>.<identity>"
    """
    pattern = re.compile(re.escape(basename) + r"\.(\d+)\.(tar|jsonl)\.gz$")
    highest = -1
    paginator = s3.meta.client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name, Prefix=s3dir):
        for obj in page.get("Contents", []):
            m = pattern.match(obj["Key"][len(s3dir) :])
            if m:
                highest = max(highest, int(m.group(1)))
    return highest + 1


def s3_key_exists(s3, bucket_name: str, s3path: str) -> bool:
    try:
        s3.meta.client.head_object(Bucket=bucket_name, Key=s3path)
        return True
    except s3.meta.client.exceptions.ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
            return False
        raise


def remove_hourdir_if_done(
    hourdir: PP, tmp_max_age_s: int = 3600, empty_max_age_s: int = 86400
) -> None:
    """Clean up an hour's spool directory after its upload.

    The fastpath can still write to it: a .post that arrived after the last
    can was filled, or a .post.tmp being written, belongs to the next run.
    Only stale temporary files, left by an interrupted write, are deleted.

    The directory itself is removed only once it has been empty and without
    writes for empty_max_age_s. The fastpath creates it (mkdir exist_ok) and
    then writes into it: removing it right after an upload, when late writes
    for the hour are most likely, could land between the two and make the
    fastpath's write fail.
    """
    now = time.time()
    for f in hourdir.iterdir():
        if f.name.endswith(".tmp") and now - f.stat().st_mtime > tmp_max_age_s:
            log.info(f"Deleting stale {f}")
            f.unlink()
    if any(hourdir.iterdir()):
        log.info(f"Keeping {hourdir}: measurements arrived during the upload")
        metrics.incr("hourdir_kept")
        return
    if now - hourdir.stat().st_mtime < empty_max_age_s:
        return
    try:
        hourdir.rmdir()
    except OSError:
        pass  # written to since the check: the next run handles it


@metrics.timer("fill_postcan")
def fill_postcan(hourdir: PP, postcanf: PP) -> List[PP]:
    msmt_files = sorted(f for f in hourdir.iterdir() if f.suffix == ".post")
    if not msmt_files:
        log.info(f"Nothing to fill {postcanf.name}")
        return []
    log.info(f"Filling {postcanf.name}")
    measurements = []
    postcan_byte_thresh = 20 * 1000 * 1000
    # Open postcan
    with tarfile.open(str(postcanf), "w:gz") as tar:
        for msmt_f in msmt_files:
            # Add a msmt and delete the msmt file
            metrics.incr("msmt_count")
            tar.add(str(msmt_f))
            measurements.append(msmt_f)
            tarsize = postcanf.stat().st_size
            if tarsize > postcan_byte_thresh:
                log.info(f"Reached {tarsize} bytes")
                return measurements

    return measurements


@metrics.timer("fill_jsonl")
def fill_jsonl(measurements: List[PP], jsonlf: PP) -> List[Dict]:
    log.info(f"Filling {jsonlf.name}")
    # report_id, input, 2020092119_IT_tor.n0.0.jsonl.gz
    lookup_list = []
    with gzip.open(jsonlf, "w") as jf:
        for linenum, msmt_f in enumerate(measurements):
            try:
                post = ujson.load(msmt_f.open())
            except Exception:
                log.error("Unable to parse measurement")
                jf.write(b"{}\n")
                continue

            fmt = post.get("format", "").lower()
            msm = None
            if fmt == "json":
                msm = post.get("content", {})
            elif fmt == "yaml":
                try:
                    msm = yaml.load(msm, Loader=yaml.CLoader)
                except Exception:
                    pass

            if msm is None:
                log.error("Unable to parse measurement")
                jf.write(b"{}\n")
                continue

            jf.write(ujson.dumps(msm).encode())
            jf.write(b"\n")

            rid = msm.get("report_id") or ""
            input = msm.get("input") or ""
            msmt_uid = msmt_f.name[:-5]
            d = dict(
                report_id=rid, input=input, measurement_uid=msmt_uid, linenum=linenum
            )
            lookup_list.append(d)

    return lookup_list


def delete_msmt_posts(measurements: List[PP]) -> None:
    log.info(f"Deleting {len(measurements)} measurements")
    for msmt_f in measurements:
        msmt_f.unlink()


@metrics.timer("total_run_time")
def main():
    conf = read_conf()
    bucket_name = conf.get("bucket_name")
    spooldir = Path(conf.get("msmt_spool_dir"))
    format_char = "n"
    collector_id = conf.get("collector_id")
    identity = f"{format_char}{collector_id}"
    log.info(f"Uploader {collector_id} starting")
    assert collector_id, "collector_id is not set"
    log.info(f"Using bucket {bucket_name} and spool {spooldir}")
    # minutes an hour's spool directory must go without writes before upload
    quiet_s = 60 * int(conf.get("quiet_minutes", "5"))

    # A run started by hand while the timer's run is in progress would pick
    # the same can indexes. The timer itself never overlaps (Type=oneshot).
    lockf = open(spooldir / "uploader.lock", "w")
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log.info("Another uploader is running, exiting")
        return

    s3 = create_s3_client(conf)

    db_conn = connect_to_db(conf)

    # Scan spool directories, by age
    idir = spooldir / "incoming"
    threshold = datetime.utcnow() - timedelta(hours=1)
    for hourdir in sorted(idir.iterdir()):
        if not hourdir.is_dir() or hourdir.suffix == ".tmp":
            continue
        try:
            tstamp, cc, testname = hourdir.name.split("_")
        except Exception:
            continue
        if len(tstamp) != 10:
            continue
        hourdir_time = datetime.strptime(tstamp, "%Y%m%d%H")
        if hourdir_time > threshold:
            log.info(f"Stopping before {hourdir_time}")
            break
        # Uploaded hours stay as empty directories for a day (see
        # remove_hourdir_if_done): clean those up without calling S3
        if not any(f.suffix == ".post" for f in hourdir.iterdir()):
            remove_hourdir_if_done(hourdir)
            continue
        # The hour being over does not mean its measurements have all been
        # written: a fastpath backlog writes them later, and the reuploader
        # writes into hours long past. Each write (.tmp, then rename to .post)
        # updates the directory's mtime: wait until it has been quiet.
        since_write = time.time() - hourdir.stat().st_mtime
        if since_write < quiet_s:
            log.info(f"Skipping {hourdir.name}: written {int(since_write)} s ago, waiting for {quiet_s} s without writes")
            metrics.incr("hourdir_busy")
            continue

        log.info(f"Processing {hourdir}")
        s3dir = f"raw/{tstamp[:8]}/{tstamp[8:10]}/{cc}/{testname}/"
        # Split msmts across multiple postcans and jsonl files, numbered after
        # any cans already uploaded for this hour
        can_cnt = first_free_can_index(s3, bucket_name, s3dir, f"{hourdir.name}.{identity}")
        if can_cnt:
            log.warning(f"{hourdir.name} was already uploaded: new cans start at {can_cnt}")
            metrics.incr("late_hour_count")
        while True:
            postcanf = hourdir.with_suffix(f".{identity}.{can_cnt}.tar.gz")
            jsonlf = hourdir.with_suffix(f".{identity}.{can_cnt}.jsonl.gz")
            postcan_s3path = s3dir + postcanf.name
            jsonl_s3path = s3dir + jsonlf.name
            # Never replace an object: a replaced can loses its measurements
            # and leaves their jsonl rows pointing at other measurements
            if s3_key_exists(s3, bucket_name, postcan_s3path) or s3_key_exists(
                s3, bucket_name, jsonl_s3path
            ):
                log.error(f"{postcan_s3path} or its jsonl already exists, skipping index {can_cnt}")
                metrics.incr("can_index_taken")
                can_cnt += 1
                continue
            # Compress raw POSTs into a tar.gz postcan
            msmfiles = fill_postcan(hourdir, postcanf)
            if len(msmfiles) == 0:
                break
            # Also create the jsonl file
            lookup_list = fill_jsonl(msmfiles, jsonlf)

            # Upload the postcan and jsonl to S3 and record where each
            # measurement is. Delete the POSTs only once all of that worked:
            # if it fails they stay in the spool and the next run uploads them
            # under the next free index
            try:
                upload_to_s3(s3, bucket_name, postcanf, postcan_s3path)
                upload_to_s3(s3, bucket_name, jsonlf, jsonl_s3path)
                update_db_table(db_conn, lookup_list, jsonl_s3path)
            finally:
                postcanf.unlink()
                jsonlf.unlink()
            delete_msmt_posts(msmfiles)

            can_cnt += 1
            metrics.incr("postcan_count")

        remove_hourdir_if_done(hourdir)

    log.info("Exiting")


if __name__ == "__main__":
    main()
