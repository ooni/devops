"""
Synthetic seed data generator.

The task asked for this test to use OONI's initdb sample data from
ooni/backend. That repo's tests don't actually vendor the sample rows in
git -- ooniapi/services/oonimeasurements/tests/conftest.py downloads them at
test time from a public S3 bucket
(https://ooni-data-eu-fra.s3.eu-central-1.amazonaws.com/samples/*.sql.gz).
This sandbox's network egress is restricted to a small allowlist and cannot
reach S3 or Docker Hub, so those exact files couldn't be fetched while
building this harness.

Instead, this module generates synthetic rows that conform *exactly* to the
production table schemas (see sql/001_schema.sql) with realistic-ish random
values and realistic cardinality/skew (a handful of repeated probe_cc/ASN
values, mostly-null optional columns, etc). This is enough to meaningfully
exercise ReplicatedMergeTree merges, replication, and wide-table part
formats across ClickHouse versions -- which is what the upgrade test cares
about, more than the specific content of the rows.

If you're running this somewhere with S3 access, see README.md for how to
swap in the real dump instead (download the .sql.gz files referenced above,
`gunzip -c | docker compose exec -T ch1 clickhouse-client --database ooni`).
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

PROBE_CCS = ["US", "DE", "IR", "CN", "RU", "BR", "IN", "IT", "FR", "GB", "EG", "TR"]
ASNS = [7018, 3320, 12389, 4134, 24560, 1221, 3269, 4837, 8151, 6830]
TEST_NAMES = ["web_connectivity", "http_invalid_request_line", "signal", "telegram", "facebook_messenger"]
DOMAINS = ["example.com", "twitter.com", "facebook.com", "bbc.com", "wikipedia.org", "ooni.org"]
SOFTWARE_VERSIONS = ["3.19.0", "3.20.1", "3.21.0"]


def _rand_dt(start: datetime, end: datetime) -> datetime:
    delta = end - start
    return start + timedelta(seconds=random.randint(0, int(delta.total_seconds())))


def _fmt_dt64(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _fmt_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'")


def _sql_str(s: str | None) -> str:
    if s is None:
        return "NULL"
    return f"'{_esc(s)}'"


def _sql_arr(items: list[str]) -> str:
    return "[" + ", ".join(_sql_str(i) for i in items) + "]"


def gen_citizenlab_rows(n: int, seed: int = 1) -> list[tuple]:
    rnd = random.Random(seed)
    rows = []
    for i in range(n):
        domain = rnd.choice(DOMAINS)
        rows.append((domain, f"https://{domain}/", rnd.choice(PROBE_CCS), rnd.choice(["GRP", "NEWS", "SRCH"])))
    return rows


def citizenlab_insert_statements(rows: list[tuple], batch_size: int = 500) -> list[str]:
    cols = "(domain, url, cc, category_code)"
    stmts = []
    for i in range(0, len(rows), batch_size):
        batch = rows[i : i + batch_size]
        values = ", ".join(
            f"({_sql_str(d)}, {_sql_str(u)}, {_sql_str(cc)}, {_sql_str(cat)})" for d, u, cc, cat in batch
        )
        stmts.append(f"INSERT INTO ooni.citizenlab {cols} VALUES {values}")
    return stmts


def gen_fastpath_rows(n: int, seed: int = 2) -> list[dict]:
    rnd = random.Random(seed)
    start, end = datetime(2025, 1, 1), datetime(2025, 6, 1)
    rows = []
    for i in range(n):
        mst = _rand_dt(start, end)
        rows.append(
            {
                "measurement_uid": f"seed-fp-{i:08d}",
                "report_id": f"20250101T000000Z_{i:06d}",
                "input": rnd.choice(DOMAINS),
                "probe_cc": rnd.choice(PROBE_CCS),
                "probe_asn": rnd.choice(ASNS),
                "test_name": rnd.choice(TEST_NAMES),
                "test_start_time": _fmt_dt(mst),
                "measurement_start_time": _fmt_dt(mst),
                "filename": f"{i}.json",
                "scores": "{}",
                "platform": rnd.choice(["android", "ios", "linux"]),
                "anomaly": rnd.choice(["true", "false"]),
                "confirmed": "false",
                "msm_failure": "false",
                "domain": rnd.choice(DOMAINS),
                "software_name": "ooniprobe",
                "software_version": rnd.choice(SOFTWARE_VERSIONS),
                "control_failure": "",
                "blocking_general": round(rnd.random(), 3),
                "is_ssl_expected": rnd.choice([0, 1]),
                "page_len": rnd.randint(100, 50000),
                "page_len_ratio": round(rnd.random(), 3),
                "server_cc": rnd.choice(PROBE_CCS),
                "server_asn": rnd.randint(0, 100),
                "server_as_name": "Example AS",
                "test_version": "0.1.0",
                "architecture": "amd64",
                "engine_name": "ooniprobe-engine",
                "engine_version": rnd.choice(SOFTWARE_VERSIONS),
                "test_runtime": round(rnd.uniform(0.1, 30.0), 3),
                "blocking_type": rnd.choice(["", "dns", "tcp_ip", "http-failure"]),
                "test_helper_address": "https://th.ooni.org",
                "test_helper_type": "https",
                "ooni_run_link_id": None,
            }
        )
    return rows


def fastpath_insert_statements(rows: list[dict], batch_size: int = 500) -> list[str]:
    cols = list(rows[0].keys())
    col_sql = "(" + ", ".join(cols) + ")"
    stmts = []
    for i in range(0, len(rows), batch_size):
        batch = rows[i : i + batch_size]
        value_tuples = []
        for r in batch:
            parts = []
            for c in cols:
                v = r[c]
                if v is None:
                    parts.append("NULL")
                elif isinstance(v, (int, float)):
                    parts.append(str(v))
                else:
                    parts.append(_sql_str(str(v)))
            value_tuples.append("(" + ", ".join(parts) + ")")
        stmts.append(f"INSERT INTO ooni.fastpath {col_sql} VALUES {', '.join(value_tuples)}")
    return stmts


def gen_analysis_rows(n: int, seed: int = 3) -> list[dict]:
    rnd = random.Random(seed)
    start, end = datetime(2025, 1, 1), datetime(2025, 6, 1)
    rows = []
    for i in range(n):
        mst = _rand_dt(start, end)
        uid = f"{mst.strftime('%Y%m%d%H')}_seed_an_{i:08d}"
        rows.append(
            {
                "domain": rnd.choice(DOMAINS),
                "input": f"https://{rnd.choice(DOMAINS)}/",
                "test_name": "web_connectivity",
                "probe_asn": rnd.choice(ASNS),
                "probe_as_org_name": "Example ISP",
                "probe_cc": rnd.choice(PROBE_CCS),
                "resolver_asn": rnd.choice(ASNS),
                "resolver_as_cc": rnd.choice(PROBE_CCS),
                "network_type": rnd.choice(["wifi", "mobile"]),
                "measurement_start_time": _fmt_dt64(mst),
                "measurement_uid": uid,
                "ooni_run_link_id": "0",
                "top_probe_analysis": rnd.choice([None, "ok", "blocked"]),
                "top_dns_failure": None,
                "top_tcp_failure": None,
                "top_tls_failure": None,
                "dns_blocked": round(rnd.random(), 3),
                "dns_down": round(rnd.random(), 3),
                "dns_ok": round(rnd.random(), 3),
                "tcp_blocked": round(rnd.random(), 3),
                "tcp_down": round(rnd.random(), 3),
                "tcp_ok": round(rnd.random(), 3),
                "tls_blocked": round(rnd.random(), 3),
                "tls_down": round(rnd.random(), 3),
                "tls_ok": round(rnd.random(), 3),
            }
        )
    return rows


def analysis_insert_statements(rows: list[dict], batch_size: int = 500) -> list[str]:
    cols = list(rows[0].keys())
    col_sql = "(" + ", ".join(cols) + ")"
    stmts = []
    for i in range(0, len(rows), batch_size):
        batch = rows[i : i + batch_size]
        value_tuples = []
        for r in batch:
            parts = []
            for c in cols:
                v = r[c]
                if v is None:
                    parts.append("NULL")
                elif isinstance(v, (int, float)):
                    parts.append(str(v))
                else:
                    parts.append(_sql_str(str(v)))
            value_tuples.append("(" + ", ".join(parts) + ")")
        stmts.append(f"INSERT INTO ooni.analysis_web_measurement {col_sql} VALUES {', '.join(value_tuples)}")
    return stmts


def gen_obs_web_rows(n: int, seed: int = 4) -> list[dict]:
    rnd = random.Random(seed)
    start, end = datetime(2025, 1, 1), datetime(2025, 6, 1)
    rows = []
    for i in range(n):
        mst = _rand_dt(start, end)
        uid = f"{mst.strftime('%Y%m%d%H')}_seed_ow_{i:08d}"
        has_tls = rnd.random() > 0.3
        rows.append(
            {
                "measurement_uid": uid,
                "observation_idx": i % 5,
                "input": f"https://{rnd.choice(DOMAINS)}/",
                "report_id": f"20250101T000000Z_{i:06d}",
                "ooni_run_link_id": "0",
                "measurement_start_time": _fmt_dt64(mst),
                "software_name": "ooniprobe",
                "software_version": rnd.choice(SOFTWARE_VERSIONS),
                "test_name": "web_connectivity",
                "test_version": "0.1.0",
                "bucket_date": mst.strftime("%Y-%m-%d"),
                "probe_asn": rnd.choice(ASNS),
                "probe_cc": rnd.choice(PROBE_CCS),
                "probe_as_org_name": "Example ISP",
                "probe_as_cc": rnd.choice(PROBE_CCS),
                "probe_as_name": "Example AS Name",
                "network_type": rnd.choice(["wifi", "mobile"]),
                "platform": rnd.choice(["android", "ios", "linux"]),
                "origin": "probe",
                "engine_name": "ooniprobe-engine",
                "engine_version": rnd.choice(SOFTWARE_VERSIONS),
                "architecture": "amd64",
                "resolver_ip": f"8.8.{rnd.randint(0,255)}.{rnd.randint(0,255)}",
                "resolver_asn": rnd.choice(ASNS),
                "resolver_cc": rnd.choice(PROBE_CCS),
                "resolver_as_org_name": "Example Resolver Org",
                "resolver_as_cc": rnd.choice(PROBE_CCS),
                "resolver_is_scrubbed": 0,
                "resolver_asn_probe": rnd.choice(ASNS),
                "resolver_as_org_name_probe": "Example Resolver Org",
                "created_at": _fmt_dt(mst),
                "target_id": None,
                "hostname": rnd.choice(DOMAINS),
                "transaction_id": i % 10,
                "ip": f"93.184.{rnd.randint(0,255)}.{rnd.randint(0,255)}",
                "port": 443,
                "ip_asn": rnd.choice(ASNS),
                "ip_as_org_name": "Example Host Org",
                "ip_as_cc": rnd.choice(PROBE_CCS),
                "ip_cc": rnd.choice(PROBE_CCS),
                "ip_is_bogon": 0,
                "dns_query_type": "A",
                "dns_failure": None,
                "dns_engine": "system",
                "dns_engine_resolver_address": None,
                "dns_answer_type": "A",
                "dns_answer": f"93.184.{rnd.randint(0,255)}.{rnd.randint(0,255)}",
                "dns_answer_asn": rnd.choice(ASNS),
                "dns_answer_as_org_name": "Example Org",
                "dns_t": round(rnd.uniform(0.01, 2.0), 4),
                "tcp_failure": None,
                "tcp_success": 1,
                "tcp_t": round(rnd.uniform(0.01, 2.0), 4),
                "tls_failure": None if has_tls else "connection_reset",
                "tls_server_name": rnd.choice(DOMAINS) if has_tls else None,
                "tls_outer_server_name": None,
                "tls_echconfig": None,
                "tls_version": "TLSv1.3" if has_tls else None,
                "tls_cipher_suite": "TLS_AES_128_GCM_SHA256" if has_tls else None,
                "tls_is_certificate_valid": 1 if has_tls else None,
                "tls_end_entity_certificate_fingerprint": "deadbeef" if has_tls else None,
                "tls_end_entity_certificate_subject": None,
                "tls_end_entity_certificate_subject_common_name": None,
                "tls_end_entity_certificate_issuer": None,
                "tls_end_entity_certificate_issuer_common_name": None,
                "tls_end_entity_certificate_san_list": [],
                "tls_end_entity_certificate_not_valid_after": None,
                "tls_end_entity_certificate_not_valid_before": None,
                "tls_certificate_chain_length": 2 if has_tls else None,
                "tls_certificate_chain_fingerprints": [],
                "tls_handshake_read_count": None,
                "tls_handshake_write_count": None,
                "tls_handshake_read_bytes": None,
                "tls_handshake_write_bytes": None,
                "tls_handshake_last_operation": None,
                "tls_handshake_time": round(rnd.uniform(0.01, 1.0), 4) if has_tls else None,
                "tls_t": round(rnd.uniform(0.01, 2.0), 4) if has_tls else None,
                "http_request_url": f"https://{rnd.choice(DOMAINS)}/",
                "http_network": "tcp",
                "http_alpn": "h2",
                "http_failure": None,
                "http_request_body_length": 0,
                "http_request_method": "GET",
                "http_runtime": round(rnd.uniform(0.01, 3.0), 4),
                "http_response_body_length": rnd.randint(100, 90000),
                "http_response_body_is_truncated": 0,
                "http_response_body_sha1": "0" * 40,
                "http_response_status_code": rnd.choice([200, 200, 200, 301, 403, 503]),
                "http_response_header_location": None,
                "http_response_header_server": "nginx",
                "http_request_redirect_from": None,
                "http_request_body_is_truncated": 0,
                "http_t": round(rnd.uniform(0.01, 3.0), 4),
                "probe_analysis": rnd.choice([None, "ok", "blocked"]),
            }
        )
    return rows


_ARRAY_COLS = {"tls_end_entity_certificate_san_list", "tls_certificate_chain_fingerprints"}


def obs_web_insert_statements(rows: list[dict], batch_size: int = 200) -> list[str]:
    cols = list(rows[0].keys())
    col_sql = "(" + ", ".join(cols) + ")"
    stmts = []
    for i in range(0, len(rows), batch_size):
        batch = rows[i : i + batch_size]
        value_tuples = []
        for r in batch:
            parts = []
            for c in cols:
                v = r[c]
                if c in _ARRAY_COLS:
                    parts.append(_sql_arr(v or []))
                elif v is None:
                    parts.append("NULL")
                elif isinstance(v, (int, float)):
                    parts.append(str(v))
                else:
                    parts.append(_sql_str(str(v)))
            value_tuples.append("(" + ", ".join(parts) + ")")
        stmts.append(f"INSERT INTO ooni.obs_web {col_sql} VALUES {', '.join(value_tuples)}")
    return stmts


def build_all_seed_statements(
    n_obs_web: int = 5000,
    n_analysis: int = 1000,
    n_fastpath: int = 2000,
    n_citizenlab: int = 200,
) -> dict[str, list[str]]:
    return {
        "citizenlab": citizenlab_insert_statements(gen_citizenlab_rows(n_citizenlab)),
        "fastpath": fastpath_insert_statements(gen_fastpath_rows(n_fastpath)),
        "analysis_web_measurement": analysis_insert_statements(gen_analysis_rows(n_analysis)),
        "obs_web": obs_web_insert_statements(gen_obs_web_rows(n_obs_web)),
    }
