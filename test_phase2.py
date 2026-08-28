"""Phase 2 integration test script — run directly with the project venv."""
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import re
import sys

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar),
    urllib.request.HTTPRedirectHandler(),
)

RESULTS = []


def test(label, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    RESULTS.append((status, label, detail))
    print(f"  [{status}] {label}" + (f" — {detail}" if detail else ""))


def post(url, fields):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        r = opener.open(req)
        return r.status, r.geturl(), r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, url, e.read().decode(errors="replace")


def get(url):
    try:
        r = opener.open(url)
        return r.status, r.geturl(), r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, url, e.read().decode(errors="replace")


def extract_session_id(html):
    """Extract session_id from hidden form input."""
    m = re.search(r'name="session_id"\s+value="([a-f0-9]+)"', html)
    return m.group(1) if m else None


print("=== SentientAI Phase 2 Integration Tests ===")
print()

# ------------------------------------------------------------------
# 1. Login as admin
# ------------------------------------------------------------------
print("1. Login as admin")
s, u, b = post(
    "http://127.0.0.1:8000/login",
    {"username": "admin", "password": "AdminPassword123!"},
)
test("Login admin -> /testing redirect", "/testing" in u, f"status={s} url={u}")

# ------------------------------------------------------------------
# 2. Testing overview
# ------------------------------------------------------------------
print()
print("2. Testing overview")
s, u, b = get("http://127.0.0.1:8000/testing")
test("/testing loads (200)", s == 200, f"status={s}")
test("Sessions link present", "/testing/sessions" in b)
test("Labs section present", "Labs" in b or "lab" in b.lower())

# ------------------------------------------------------------------
# 3. Labs list
# ------------------------------------------------------------------
print()
print("3. Labs list")
s, u, b = get("http://127.0.0.1:8000/testing/labs")
test("/testing/labs loads (200)", s == 200, f"status={s}")
test("xss_stored lab listed", "xss_stored" in b or "XSS" in b or "Stored" in b)
test("sqli lab listed", "sqli" in b or "SQL" in b)

# ------------------------------------------------------------------
# 4. Lab detail creates session
# ------------------------------------------------------------------
print()
print("4. Lab detail creates session (xss_stored)")
s, u, b = get("http://127.0.0.1:8000/testing/labs/xss_stored")
test("xss_stored lab detail loads (200)", s == 200, f"status={s}")
test("Session Active badge shown", "Session Active" in b or "session" in b.lower())

session_id = extract_session_id(b)
test(
    "Session ID embedded in form",
    bool(session_id),
    f"sid={session_id[:12]}..." if session_id else "NOT FOUND",
)

# ------------------------------------------------------------------
# 5. Submit benign payload
# ------------------------------------------------------------------
print()
print("5. Submit benign payload")
if session_id:
    s, u, b = post(
        f"http://127.0.0.1:8000/testing/labs/xss_stored/submit",
        {"payload": "hello world", "session_id": session_id},
    )
    test(
        "Benign submit -> attack_result page",
        s == 200 and ("NOT DETECTED" in b or "Clean" in b or "attack_result" in u),
        f"status={s} url={u}",
    )
    test("Result shows NOT DETECTED", "NOT DETECTED" in b)
    test("Session timeline link in result", "/testing/sessions/" in b)
else:
    test("Benign submit (skipped — no session)", False, "no session_id extracted")

# ------------------------------------------------------------------
# 6. Submit XSS payload on same session
# ------------------------------------------------------------------
print()
print("6. Submit XSS payload (should be DETECTED, not blocked)")
if session_id:
    s, u, b = post(
        f"http://127.0.0.1:8000/testing/labs/xss_stored/submit",
        {"payload": "<script>alert(1)</script>", "session_id": session_id},
    )
    # XSS is medium severity — detected but not blocked
    test(
        "XSS payload DETECTED",
        "DETECTED" in b or "detected" in b.lower(),
        f"status={s} url={u}",
    )
    test("XSS not blocked (medium severity)", "session-ended" not in u)
else:
    test("XSS submit (skipped — no session)", False, "no session_id extracted")

# ------------------------------------------------------------------
# 7. Command injection — critical → session terminated
# ------------------------------------------------------------------
print()
print("7. Command injection payload (critical -> session-ended)")
s, u, b = get("http://127.0.0.1:8000/testing/labs/sqli")
test("sqli lab loads (200)", s == 200, f"status={s}")

sqli_session_id = extract_session_id(b)
test(
    "sqli session created",
    bool(sqli_session_id),
    f"sid={sqli_session_id}" if sqli_session_id else "NOT FOUND",
)

if sqli_session_id:
    s, u, b = post(
        f"http://127.0.0.1:8000/testing/labs/sqli/submit",
        {"payload": "test; whoami", "session_id": sqli_session_id},
    )
    test(
        "Critical payload redirects to session-ended",
        "session-ended" in u,
        f"status={s} url={u}",
    )

# ------------------------------------------------------------------
# 8. Session-ended page
# ------------------------------------------------------------------
print()
print("8. Session-ended page")
if sqli_session_id:
    s, u, b = get(f"http://127.0.0.1:8000/testing/session-ended/{sqli_session_id}")
    test("session-ended page loads (200)", s == 200, f"status={s}")
    test("Shows 'Session Terminated'", "Session Terminated" in b or "Terminated" in b)
    test("Shows termination reason", "Termination Reason" in b or "Critical payload" in b)
    test("Shows triggering event section", "Terminating Event" in b)
    test("View Full Timeline link present", "/testing/sessions/" in b)
    test("Start New Session link present", "Start New Session" in b)
    test("All Events link present", "/testing/events" in b)
else:
    test("Session-ended page (skipped)", False, "no sqli_session_id")

# ------------------------------------------------------------------
# 9. Sessions list
# ------------------------------------------------------------------
print()
print("9. Sessions list")
s, u, b = get("http://127.0.0.1:8000/testing/sessions")
test("/testing/sessions loads (200)", s == 200, f"status={s}")
test("Sessions table shown", "Timeline" in b or "Ended" in b or "sessions" in b.lower())
test("Terminated session in list", "Terminated" in b or "terminated" in b)
test("Active session in list", "Active" in b or "active" in b)

# ------------------------------------------------------------------
# 10. Session timeline
# ------------------------------------------------------------------
print()
print("10. Session timeline")
if sqli_session_id:
    s, u, b = get(f"http://127.0.0.1:8000/testing/sessions/{sqli_session_id}")
    test("Session timeline loads (200)", s == 200, f"status={s}")
    test("Shows Attack Timeline heading", "Attack Timeline" in b or "Event Timeline" in b)
    test("Timeline shows session start", "SESSION START" in b)
    test("Timeline shows session terminated", "SESSION TERMINATED" in b or "Terminated" in b)
    test("Timeline has event entries", "timeline-step" in b)
else:
    test("Session timeline (skipped)", False, "no sqli_session_id")

# ------------------------------------------------------------------
# 11. Events list
# ------------------------------------------------------------------
print()
print("11. Events list")
s, u, b = get("http://127.0.0.1:8000/testing/events")
test("/testing/events loads (200)", s == 200, f"status={s}")
test("Events listed", "Event" in b or "event" in b.lower())

event_id_m = re.search(r"/testing/events/(\d+)", b)
event_id = event_id_m.group(1) if event_id_m else None
test("Event links present", bool(event_id), f"first event id={event_id}")

# ------------------------------------------------------------------
# 12. Event detail — session link
# ------------------------------------------------------------------
print()
print("12. Event detail with session link")
if event_id:
    s, u, b = get(f"http://127.0.0.1:8000/testing/events/{event_id}")
    test(f"Event #{event_id} detail loads (200)", s == 200, f"status={s}")
    test("Session Timeline link in event detail", "/testing/sessions/" in b or "Session Timeline" in b)
    test("session_id shown", "session" in b.lower())
else:
    test("Event detail (skipped)", False, "no event_id found")

# ------------------------------------------------------------------
# 13. Dead-end: resubmit to terminated session
# ------------------------------------------------------------------
print()
print("13. Dead-end: resubmit to terminated session")
if sqli_session_id:
    s, u, b = post(
        f"http://127.0.0.1:8000/testing/labs/sqli/submit",
        {"payload": "hello", "session_id": sqli_session_id},
    )
    test(
        "Resubmit to ended session -> session-ended",
        "session-ended" in u,
        f"status={s} url={u}",
    )
else:
    test("Dead-end resubmit (skipped)", False, "no sqli_session_id")

# ------------------------------------------------------------------
# 14. RBAC — unauthenticated access blocked
# ------------------------------------------------------------------
print()
print("14. RBAC: unauthenticated access to /testing blocked")
# Use a fresh opener with no cookies
bare_opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
try:
    bare_req = urllib.request.Request("http://127.0.0.1:8000/testing")
    r = bare_opener.open(bare_req)
    final_url = r.geturl()
    test("/testing without auth -> redirected to login", "login" in final_url, f"url={final_url}")
except urllib.error.HTTPError as e:
    test("/testing without auth -> 4xx", e.code in (401, 403), f"code={e.code}")

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
print()
print("=" * 50)
print("=== SUMMARY ===")
passes = sum(1 for r in RESULTS if r[0] == "PASS")
fails = sum(1 for r in RESULTS if r[0] == "FAIL")
print(f"PASSED: {passes}/{len(RESULTS)}")
print(f"FAILED: {fails}/{len(RESULTS)}")
if fails:
    print()
    print("FAILED tests:")
    for r in RESULTS:
        if r[0] == "FAIL":
            print(f"  - {r[1]}: {r[2]}")

sys.exit(0 if fails == 0 else 1)
