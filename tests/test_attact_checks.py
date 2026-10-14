"""ATTACT checks + runner tests via a local mock HTTP server."""
from __future__ import annotations
import http.server, threading, urllib.parse, json, socket, time
import pytest
from ATTACT.runner import run_assessment
from ATTACT.scope import ScopeError

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *a): pass
    def do_GET(self):
        parsed=urllib.parse.urlparse(self.path)
        path=parsed.path; qs=parsed.query
        if path=="/redirect":
            self.send_response(302); self.send_header("Location","http://93.184.216.34/"); self.end_headers(); return
        if path=="/.env":
            self.send_response(404); self.end_headers(); return
        if path=="/__attact_no_such_route_9f3a1b":
            self.send_response(404); self.send_header("Content-Type","text/html"); self.end_headers(); self.wfile.write(b"<h1>404 Not Found</h1>"); return
        body=f"<html>hello {qs}</html>".encode()
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("X-Frame-Options","DENY")
        self.send_header("Referrer-Policy","strict-origin-when-cross-origin")
        self.send_header("Content-Security-Policy","default-src 'self'")
        self.send_header("Set-Cookie","csrf_token=abc123; Path=/; SameSite=Lax")
        self.send_header("Set-Cookie","session=xyz; Path=/; HttpOnly; SameSite=Lax")
        self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        self.send_response(403); self.end_headers(); self.wfile.write(b"forbidden")
    def do_OPTIONS(self):
        self.send_response(204); self.send_header("Allow","GET, POST, OPTIONS"); self.end_headers()

@pytest.fixture(scope="module")
def srv():
    s=http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t=threading.Thread(target=s.serve_forever, daemon=True); t.start()
    time.sleep(0.05)
    yield f"http://127.0.0.1:{s.server_address[1]}"
    s.shutdown()

def test_runner_basic(srv):
    r=run_assessment(target_url=srv, confirm_authorized=True, checks=["security_headers","cookie_security","cors","info_disclosure","csrf","input_validation"], max_requests=80)
    assert r.request_count>0
    assert any(f.check=="security_headers" for f in r.findings)
    assert r.target.startswith("http://127.0.0.1")

def test_runner_request_limit(srv):
    r=run_assessment(target_url=srv, confirm_authorized=True, max_requests=2)
    assert r.request_count<=2
    assert any(f.status=="not_run" for f in r.findings)

def test_runner_json_export(tmp_path, srv):
    r=run_assessment(target_url=srv, confirm_authorized=True, checks=["security_headers"], max_requests=20)
    from ATTACT.report import write_json
    p=write_json(r, tmp_path/"out.json")
    data=json.loads(p.read_text(encoding="utf-8"))
    assert data["tool"]=="ATTACT" and "findings" in data and "limitations" in data

def test_cli_help_and_list():
    import subprocess, sys
    out=subprocess.check_output([sys.executable,"-m","ATTACT","--help"], text=True)
    assert "ATTACT" in out
    out2=subprocess.check_output([sys.executable,"-m","ATTACT","--list-checks"], text=True)
    assert "security_headers" in out2

def test_cli_scope_blocks_external():
    import subprocess, sys
    r=subprocess.run([sys.executable,"-m","ATTACT","--target","http://93.184.216.34/","--confirm-authorized"], capture_output=True, text=True)
    assert r.returncode==2 and "Scope error" in r.stderr

def test_redirect_scope(srv):
    from ATTACT.http_client import BoundedClient
    c=BoundedClient(timeout=2, max_requests=10, allowlist=set())
    # following a redirect to external host must raise ScopeError
    with pytest.raises(ScopeError):
        c.get(srv+"/redirect")
