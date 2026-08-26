"""XSS simulation labs — Stored and Reflected.

All rendering is server-side simulation. No actual browser-side script
execution occurs. The lab checks for XSS patterns and shows what
*would* happen in a vulnerable application.
"""
import html
from typing import Dict, Any, List
from app.labs import register_lab

# In-memory "guestbook" for stored XSS simulation
_stored_comments: List[Dict[str, str]] = [
    {"author": "alice", "comment": "Great platform! Learning a lot."},
    {"author": "bob", "comment": "The SQL injection lab was really helpful."},
]

XSS_STORED_DESCRIPTION = """
## Stored XSS Lab

This lab simulates a vulnerable comment/guestbook feature. User input is
stored and displayed back without sanitization — a classic Stored XSS
vulnerability.

**Your task:** Try to inject a script that would execute when other users
view the page.

**Example inputs to try:**
- `Hello world` (normal comment)
- `<script>alert('XSS')</script>` (basic script injection)
- `<img src=x onerror=alert('XSS')>` (event handler injection)
- `<svg onload=alert('XSS')>` (SVG-based injection)

All execution is simulated. No real scripts run in the browser.
"""

XSS_REFLECTED_DESCRIPTION = """
## Reflected XSS Lab

This lab simulates a vulnerable search feature that reflects user input
directly in the response without encoding — a classic Reflected XSS
vulnerability.

**Your task:** Craft input that would execute JavaScript if rendered
unsanitized in a real page.

**Example inputs to try:**
- `cybersecurity` (normal search)
- `<script>document.cookie</script>` (cookie theft attempt)
- `"><img src=x onerror=alert(1)>` (attribute breakout)
- `javascript:alert(1)` (URI scheme injection)

All execution is simulated server-side.
"""


def handle_stored_xss(payload: str) -> Dict[str, Any]:
    """Simulate stored XSS — store comment and render all comments."""
    comment_text = payload.strip()
    if not comment_text:
        return {
            "vulnerable": False,
            "output": "Empty comment — nothing stored.",
            "comments": _stored_comments[:],
        }

    # Check for XSS patterns
    lower = comment_text.lower()
    xss_indicators = [
        "<script", "onerror", "onload", "onclick", "onmouseover",
        "javascript:", "eval(", "document.", "<iframe", "<svg",
        "alert(", "confirm(", "prompt(",
    ]
    is_xss = any(indicator in lower for indicator in xss_indicators)

    # Store the comment (in-memory only, resets on restart)
    new_comment = {"author": "you", "comment": comment_text}
    _stored_comments.append(new_comment)

    if is_xss:
        # Show what would happen
        safe_display = html.escape(comment_text)
        return {
            "vulnerable": True,
            "output": (
                "⚠ STORED XSS DETECTED\n\n"
                "Your comment was stored and would be rendered as:\n\n"
                f"  Raw HTML: {comment_text}\n\n"
                "In a vulnerable application, this would execute in every user's "
                "browser when they view this page.\n\n"
                f"  Safe version: {safe_display}\n\n"
                "Current guestbook contents:\n"
                + "\n".join(
                    f"  [{c['author']}]: {html.escape(c['comment'])}"
                    for c in _stored_comments[-5:]
                )
            ),
            "injected_html": comment_text,
            "comments": _stored_comments[:],
        }
    else:
        return {
            "vulnerable": False,
            "output": (
                "Comment stored successfully.\n\n"
                "No XSS payload detected in this input.\n\n"
                "Current guestbook contents:\n"
                + "\n".join(
                    f"  [{c['author']}]: {c['comment']}"
                    for c in _stored_comments[-5:]
                )
            ),
            "comments": _stored_comments[:],
        }


def handle_reflected_xss(payload: str) -> Dict[str, Any]:
    """Simulate reflected XSS — reflect search input in response."""
    search_term = payload.strip()
    if not search_term:
        return {
            "vulnerable": False,
            "output": "Empty search query.",
        }

    lower = search_term.lower()
    xss_indicators = [
        "<script", "onerror", "onload", "onclick", "onmouseover",
        "javascript:", "eval(", "document.", "<iframe", "<svg",
        "alert(", "confirm(", "prompt(",
    ]
    is_xss = any(indicator in lower for indicator in xss_indicators)

    # Fake search results
    fake_results = ["Introduction to Firewalls", "Network Security Basics", "OWASP Top 10 Guide"]

    if is_xss:
        safe_display = html.escape(search_term)
        return {
            "vulnerable": True,
            "output": (
                "⚠ REFLECTED XSS DETECTED\n\n"
                f"The page would render:\n\n"
                f'  <h2>Search results for: {search_term}</h2>\n\n'
                "In a vulnerable application, the injected content would execute "
                "immediately in the user's browser.\n\n"
                f"  Safe rendering: Search results for: {safe_display}\n\n"
                "The key difference: without output encoding, the raw HTML/JS is "
                "interpreted by the browser instead of displayed as text."
            ),
            "reflected_html": search_term,
        }
    else:
        return {
            "vulnerable": False,
            "output": (
                f"Search results for: {search_term}\n\n"
                + "\n".join(f"  • {r}" for r in fake_results)
                + "\n\nNo XSS payload detected."
            ),
        }


# Register both labs
register_lab(
    lab_id="xss_stored",
    name="Stored XSS Lab",
    category="xss",
    difficulty="Beginner",
    description=XSS_STORED_DESCRIPTION,
    handler=handle_stored_xss,
)

register_lab(
    lab_id="xss_reflected",
    name="Reflected XSS Lab",
    category="xss",
    difficulty="Beginner",
    description=XSS_REFLECTED_DESCRIPTION,
    handler=handle_reflected_xss,
)
