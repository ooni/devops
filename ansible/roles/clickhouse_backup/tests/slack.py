"""Stands in for Slack's incoming webhook: keeps what Alertmanager posts, and
returns it all, as a JSON list, to GET."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

messages = []


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        messages.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.reply(b"ok")

    def do_GET(self):
        self.reply(json.dumps(messages).encode())

    def reply(self, body):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("", 8080), Handler).serve_forever()
