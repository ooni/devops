#!/usr/bin/env python3
"""Compares the responses recorded before and after a ClickHouse upgrade:
    python3 compare.py BEFORE.json AFTER.json [AFTER2.json ...]
With more than one AFTER run, it can tell a response that varies on its own (row order of ties,
approximate functions, randomness) from one that changed with the upgrade. Each request gets:
  same        identical, apart from timings and generated ids
  reordered   the same rows in another order
  varies      differs between the AFTER runs too: not caused by the upgrade
  CHANGED     the same on every AFTER run, and different from BEFORE: look at it
Exits 1 if a request that answered 200 before doesn't now, or anything is CHANGED."""
import json, re, sys

VOLATILE = re.compile(r'"(query_time|elapsed_seconds|report_id)": ?("[^"]*"|[0-9.e-]+)')


def load(f):
    return {r["service"] + " " + r["method"] + " " + r["path"]: r for r in json.load(open(f))}


def plain(body):
    return VOLATILE.sub(r'"\1": 0', body)


def unordered(body):
    def s(x):
        if isinstance(x, dict):
            return {k: s(v) for k, v in x.items()}
        if isinstance(x, list):
            return sorted((s(v) for v in x), key=lambda v: json.dumps(v, sort_keys=True))
        return x
    try:
        return json.dumps(s(json.loads(plain(body))), sort_keys=True)
    except ValueError:
        return plain(body)


before, afters = load(sys.argv[1]), [load(f) for f in sys.argv[2:]]
bad = 0
for key, b in before.items():
    a = [x[key] for x in afters]
    if b["status"] == 200 and a[0]["status"] != 200:
        verdict = f"BROKEN ({b['status']} -> {a[0]['status']})"
    elif plain(b["body"]) == plain(a[0]["body"]):
        verdict = "same"
    elif len({plain(x["body"]) for x in a}) > 1:
        verdict = "varies"
    elif unordered(b["body"]) == unordered(a[0]["body"]):
        verdict = "reordered"
    else:
        verdict = "CHANGED"
    bad += verdict.startswith(("BROKEN", "CHANGED"))
    print(f"{verdict:10} {b['status']}->{a[0]['status']} {b['seconds']:6.2f}s->{a[0]['seconds']:6.2f}s {key[:120]}")
print(f"\n{len(before)} requests; {bad} to look at")
sys.exit(1 if bad else 0)
