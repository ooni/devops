#!/usr/bin/env python3
"""Submits measurements the way the probe does, through the ooniprobe service (open a report,
POST the measurement, close it): ooniprobe forwards each to fastpath, which writes it to
ClickHouse. Checks that each one reaches ClickHouse's fastpath table and comes back out of
oonimeasurements' measurement_meta, and how long that takes:  python3 submit.py [N]

Its rows stay: their report ids have collector id 999 (_n999_). It doesn't delete them, as a
DELETE on fastpath can rewrite a part of tens of GB to remove a few rows. Run it before
recording on the old version and after recording on the new one (README.md), so that its rows
don't show up as a difference.
The measurement is a real one (UID2 in values.env, fetched with raw_measurement) with a new
report and new times."""
import json, os, subprocess, sys, time, urllib.request
from datetime import datetime, timezone

PORTS = dict(p.split("=") for p in os.environ["SERVICE_PORTS"].split(","))
PROBE, MEAS = f"http://127.0.0.1:{PORTS['ooniprobe']}", f"http://127.0.0.1:{PORTS['oonimeasurements']}"
CH = ["podman", "exec", os.environ["CLICKHOUSE_CONTAINER"], "clickhouse-client",
      "-u", os.environ["CLICKHOUSE_USER"], "--password", os.environ["CLICKHOUSE_PASSWORD"]]


def call(url, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 method="POST" if body is not None else "GET",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read() or b"{}")


def ch(q):
    return subprocess.run(CH + ["-q", q], capture_output=True, text=True).stdout.strip()


msm = call(f"{MEAS}/api/v1/raw_measurement?measurement_uid={os.environ['UID2']}")
assert msm.get("test_name"), f"no measurement body for {os.environ['UID2']}: {str(msm)[:200]}"
results = []
for i in range(int(sys.argv[1]) if len(sys.argv) > 1 else 3):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    report = call(f"{PROBE}/report", {"data_format_version": "0.2.0", "format": "json",
                  "probe_asn": msm["probe_asn"], "probe_cc": msm["probe_cc"], "software_name": msm["software_name"],
                  "software_version": msm["software_version"], "test_name": msm["test_name"],
                  "test_start_time": now, "test_version": msm["test_version"]})
    rid = report["report_id"]
    assert "_n999_" in rid, f"set COLLECTOR_ID=999 on ooniprobe, so that these rows can be found: {rid}"
    started = time.time()
    uid = call(f"{PROBE}/report/{rid}", {"format": "json", "content": dict(msm, report_id=rid, test_start_time=now,
                                                                             measurement_start_time=now)}).get("measurement_uid")
    call(f"{PROBE}/report/{rid}/close", {})
    in_ch = in_api = None
    for _ in range(60):
        if uid and in_ch is None and ch(f"SELECT count() FROM ooni.fastpath WHERE measurement_uid = '{uid}'") == "1":
            in_ch = round(time.time() - started, 1)
        if in_ch is not None:
            try:
                if call(f"{MEAS}/api/v1/measurement_meta?measurement_uid={uid}").get("measurement_uid") == uid:
                    in_api = round(time.time() - started, 1)
                    break
            except Exception:
                pass
        time.sleep(1)
    results.append({"measurement_uid": uid, "in_clickhouse_s": in_ch, "in_api_s": in_api})
    print(json.dumps(results[-1]), flush=True)
ok = all(r["in_clickhouse_s"] is not None and r["in_api_s"] is not None for r in results)
print("ok" if ok else "FAIL: a measurement didn't reach ClickHouse or the API")
sys.exit(0 if ok else 1)
