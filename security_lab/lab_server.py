"""Local training lab: a tiny mock website on 127.0.0.1.

Used for safe scanner tests and classroom demonstrations. It is
deliberately insecure in the ways a scanner should notice (missing
security headers, a reflected search parameter, a fake .env file, an
open /admin page, public API docs) and deliberately harmless in every
other way:

- It binds 127.0.0.1 only and serves only GET.
- The search page HTML-escapes its input; the scanner's inert markers
  are alphanumeric, so escaping does not hide reflection.
- The /.env body is clearly labelled FAKE and holds no real secret.
- Nothing here is a real application, account, or credential.

Run standalone: ``python -m security_lab.lab_server`` (prints the URL
and serves until Ctrl+C).
"""

from __future__ import annotations

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

INDEX_HTML = """<!doctype html><html><head><title>Security Lab (training site)</title>
<meta name="generator" content="LabServer/1.0"></head>
<body><h1>Security Lab training site</h1>
<p>This is an intentionally misconfigured local training target.</p>
<ul><li><a href="/search?q=hello">Search</a></li>
<li><a href="/login">Login (fake)</a></li>
<li><a href="/api">API</a></li>
<li><a href="/admin">Admin (fake)</a></li>
<li><a href="/robots.txt">robots.txt</a></li></ul>
</body></html>"""


class LabHandler(BaseHTTPRequestHandler):
    server_version = "LabServer/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep test output clean
        pass

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Deliberately no CSP, HSTS, X-Frame-Options, nosniff: the
        # scanner is supposed to notice.
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/":
            self._send(200, INDEX_HTML.encode(), "text/html")
        elif path == "/search":
            q = query.get("q", [""])[0]
            body = ("<!doctype html><html><head><title>Search</title></head>"
                    f"<body><h1>Results for {html.escape(q)}</h1>"
                    "<p>No real search is performed.</p></body></html>")
            self._send(200, body.encode(), "text/html")
        elif path == "/login":
            body = ("<!doctype html><html><body><h1>Login (fake)</h1>"
                    '<form action="/login" method="post">'
                    '<input type="text" name="username">'
                    '<input type="password" name="password">'
                    '<button>Sign in</button></form></body></html>')
            self._send(200, body.encode(), "text/html")
        elif path == "/api":
            self._send(200, json.dumps(
                {"status": "ok", "version": "1.0-lab"}).encode(),
                "application/json")
        elif path == "/openapi.json":
            self._send(200, json.dumps(
                {"openapi": "3.0.0-lab",
                 "info": {"title": "Lab API", "version": "1.0-lab"},
                 "paths": {}}).encode(), "application/json")
        elif path == "/admin":
            self._send(200, b"<!doctype html><html><body><h1>Admin (fake)</h1>"
                            b"<p>No real admin functions exist here.</p></body></html>",
                            "text/html")
        elif path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin/\n", "text/plain")
        elif path == "/.env":
            # FAKE content, labelled as such. The scanner must never
            # store this body (sensitive-path rule: status/length only).
            self._send(200, b"LAB-FAKE-ENV\nAPP_ENV=lab\n"
                            b"DB_PASSWORD=FAKE-NOT-A-REAL-SECRET\n",
                            "text/plain")
        elif path == "/uploads/":
            self._send(200, b"<!doctype html><html><head><title>Index of /uploads/</title>"
                            b"</head><body><h1>Index of /uploads/</h1></body></html>",
                            "text/html")
        else:
            self._send(404, b"<!doctype html><html><body><h1>Not found</h1>"
                            b"</body></html>", "text/html")

    def do_POST(self) -> None:
        self._send(405, b"Method not allowed (lab serves GET only)", "text/plain")

    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST


def start_lab_server() -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    """Start the lab on an ephemeral loopback port. Returns (server, thread, base_url)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    return server, thread, f"http://127.0.0.1:{port}"


def stop_lab_server(server: ThreadingHTTPServer) -> None:
    server.shutdown()
    server.server_close()


if __name__ == "__main__":
    _server, _thread, url = start_lab_server()
    print(f"Security Lab training site running at {url} (Ctrl+C to stop)")
    try:
        _thread.join()
    except KeyboardInterrupt:
        stop_lab_server(_server)
