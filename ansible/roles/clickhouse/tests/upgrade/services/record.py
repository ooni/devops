#!/usr/bin/env python3
"""Sends requests.txt to the services that run.sh started and saves every response (status,
body, time) to OUT.json:  python3 record.py OUT.json"""
import json, os, string, sys, time, urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PORTS = dict(p.split("=") for p in os.environ["SERVICE_PORTS"].split(","))
out = []
for line in open(os.path.join(HERE, "requests.txt")):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    service, method, rest = line.split(" ", 2)
    path, _, body = rest.partition(" ")
    path, body = string.Template(path).substitute(os.environ), string.Template(body).substitute(os.environ)
    req = urllib.request.Request(f"http://127.0.0.1:{PORTS[service]}{path}", data=body.encode() or None,
                                 method=method, headers={"Content-Type": "application/json"} if body else {})
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            status, text = r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode(errors="replace")
    except Exception as e:
        status, text = 0, f"{type(e).__name__}: {e}"
    out.append({"service": service, "method": method, "path": path, "status": status,
                "seconds": round(time.time() - started, 2), "body": text})
    print(f"{status} {time.time() - started:6.2f}s {service} {method} {path[:110]}", flush=True)
json.dump(out, open(sys.argv[1], "w"), indent=1)
