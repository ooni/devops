"""MinIO behind an R2-style bucket lock rule, for test_e2e.py.

Forwards every S3 request to MinIO unchanged (the signature covers the Host header, which is passed on), except
that an object under LOCK_PREFIX ("/<bucket>/<prefix>") written through the proxy less than LOCK_SECONDS ago can't
be deleted or overwritten. The refusals are R2's (developers.cloudflare.com/r2/buckets/bucket-locks/): DeleteObject
and PutObject get 409 ObjectLockedByBucketPolicy, DeleteObjects 200 with that code for each locked key. R2 would
still delete a batch's other keys; here a batch with any locked key deletes none, which is stricter: the backup
script never sends one, and the test would see it if it did."""
import http.client
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

UPSTREAM = os.environ.get("UPSTREAM", "minio:9000")
LOCK_PREFIX = os.environ["LOCK_PREFIX"]
LOCK_SECONDS = float(os.environ["LOCK_SECONDS"])
written = {}  # path of a key under LOCK_PREFIX: when it was written
LOCKED = "<Error><Code>ObjectLockedByBucketPolicy</Code><Message>Object is locked by a bucket lock rule</Message></Error>"


def held(path):
    return path.startswith(LOCK_PREFIX) and time.time() - written.get(path, float("-inf")) < LOCK_SECONDS


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            out = b""
            while True:
                n = int(self.rfile.readline().split(b";")[0], 16)
                if n == 0:
                    self.rfile.readline()
                    return out
                out += self.rfile.read(n)
                self.rfile.readline()
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def reply(self, code, xml):
        data = xml.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def handle_any(self):
        data = self.body() if self.command in ("PUT", "POST") else b""
        url = urlsplit(self.path)
        path, query = url.path, parse_qs(url.query, keep_blank_values=True)
        bucket = "/" + path.strip("/").split("/")[0]
        if self.command == "PUT" and "partNumber" not in query and held(path):
            print(f"refused overwrite {path}", flush=True)
            return self.reply(409, LOCKED)
        if self.command == "DELETE" and "uploadId" not in query and held(path):
            print(f"refused delete {path}", flush=True)
            return self.reply(409, LOCKED)
        if self.command == "POST" and "delete" in query:
            keys = [k.decode() for k in re.findall(rb"<Key>(.*?)</Key>", data)]
            locked = [k for k in keys if held(f"{bucket}/{k}")]
            if locked:
                print(f"refused DeleteObjects of {len(locked)} of {len(keys)} keys, e.g. {locked[0]}", flush=True)
                errors = "".join(f"<Error><Key>{k}</Key><Code>ObjectLockedByBucketPolicy</Code><Message>locked</Message></Error>"
                                 for k in locked)
                return self.reply(200, f'<?xml version="1.0" encoding="UTF-8"?><DeleteResult>{errors}</DeleteResult>')

        conn = http.client.HTTPConnection(UPSTREAM, timeout=600)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("transfer-encoding", "content-length")}
        if self.command in ("PUT", "POST"):
            headers["Content-Length"] = str(len(data))
        conn.request(self.command, self.path, body=data, headers=headers)
        resp = conn.getresponse()
        out = resp.read()
        # a whole object written: a PUT (or copy) other than a part, or a multipart upload completed
        if resp.status == 200 and path.startswith(LOCK_PREFIX) and (
            (self.command == "PUT" and "partNumber" not in query) or (self.command == "POST" and "uploadId" in query)
        ):
            written[path] = time.time()
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        length = resp.getheader("Content-Length") if self.command == "HEAD" else len(out)
        self.send_header("Content-Length", str(length or 0))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(out)

    do_GET = do_HEAD = do_PUT = do_POST = do_DELETE = handle_any


ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
