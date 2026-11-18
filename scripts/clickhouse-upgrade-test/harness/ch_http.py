"""
Minimal ClickHouse HTTP-interface client.

Deliberately dependency-free (stdlib only: urllib) so the test harness needs
nothing beyond a Python 3 interpreter and Docker to run.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


class ClickHouseError(RuntimeError):
    def __init__(self, query: str, status: int, body: str):
        self.query = query
        self.status = status
        self.body = body
        super().__init__(f"ClickHouse query failed (HTTP {status}): {body.strip()}\n--- query ---\n{query}")


@dataclass
class ChNode:
    name: str          # e.g. "ch1" -- must match docker-compose service/hostname
    http_port: int      # host-mapped port for the HTTP interface (8123 default)
    host: str = "127.0.0.1"

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.http_port}/"

    def query(self, sql: str, timeout: float = 30.0, fmt: str | None = "JSONEachRow") -> str:
        """Execute a query and return the raw response body (text)."""
        q = sql
        if fmt and sql.strip().lower().startswith("select"):
            q = f"{sql}\nFORMAT {fmt}"
        data = q.encode("utf-8")
        req = urllib.request.Request(self.base_url, data=data, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise ClickHouseError(sql, e.code, body) from None
        except urllib.error.URLError as e:
            raise ClickHouseError(sql, -1, str(e.reason)) from None

    def query_rows(self, sql: str, timeout: float = 30.0) -> list[dict]:
        body = self.query(sql, timeout=timeout, fmt="JSONEachRow")
        rows = []
        for line in body.splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
        return rows

    def query_scalar(self, sql: str, timeout: float = 30.0):
        rows = self.query_rows(sql, timeout=timeout)
        if not rows:
            return None
        return next(iter(rows[0].values()))

    def execute(self, sql: str, timeout: float = 60.0) -> None:
        """Run a statement where we don't care about the result body (DDL, INSERT)."""
        self.query(sql, timeout=timeout, fmt=None)

    def ping(self, timeout: float = 3.0) -> bool:
        try:
            req = urllib.request.Request(self.base_url + "ping", method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status == 200
        except Exception:
            return False

    def version(self) -> str:
        return self.query_scalar("SELECT version()")
