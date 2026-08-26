"""SQL Injection simulation lab.

Uses a fake in-memory 'database' — no real SQL executed with user input.
The lab deliberately concatenates user input into a fake query string
to demonstrate the vulnerability, then evaluates against fake data.
"""
from typing import Dict, Any
from app.labs import register_lab

# Fake user database — completely isolated, no real data
FAKE_USERS_DB = [
    {"id": 1, "username": "alice", "email": "alice@example.com", "role": "user", "balance": "$150.00"},
    {"id": 2, "username": "bob", "email": "bob@example.com", "role": "user", "balance": "$320.50"},
    {"id": 3, "username": "charlie", "email": "charlie@example.com", "role": "admin", "balance": "$999.00"},
    {"id": 4, "username": "diana", "email": "diana@example.com", "role": "user", "balance": "$45.75"},
    {"id": 5, "username": "eve", "email": "eve@example.com", "role": "user", "balance": "$0.00"},
]

SQLI_DESCRIPTION = """
## SQL Injection Target

This target simulates a vulnerable user query endpoint. The service constructs
an unparameterized query string by directly concatenating user-supplied input.

**Testing Objective:** Attempt authentication/query logic bypass or unauthorized data exfiltration.

**Test Vectors:**
- `alice` (baseline query)
- `' OR '1'='1` (boolean tautology bypass)
- `' UNION SELECT * FROM users --` (union schema extraction)
- `'; DROP TABLE users --` (destructive query simulation)

All operations are strictly contained within an isolated mock data layer.
"""


def handle_sqli_lab(payload: str) -> Dict[str, Any]:
    """Simulate SQL injection against fake data.

    Builds a fake query string (for demonstration), then checks if the
    input matches injection patterns to determine 'success'.
    """
    username_input = payload.strip()

    # Build the "vulnerable" query string for display
    fake_query = f"SELECT * FROM users WHERE username = '{username_input}'"

    # Check for injection patterns
    lower_input = username_input.lower()

    # Tautology-based injection: ' OR '1'='1, ' OR 1=1, etc.
    is_tautology = any(p in lower_input for p in [
        "' or '1'='1", "' or 1=1", "or 1=1", "or '1'='1",
        "' or ''='", "or true", "' or 'a'='a",
    ])

    # UNION-based injection
    is_union = "union" in lower_input and "select" in lower_input

    # Destructive injection
    is_destructive = any(cmd in lower_input for cmd in [
        "drop ", "delete ", "update ", "insert ", "alter ",
    ])

    # Comment termination
    has_comment = "--" in username_input or "/*" in username_input

    if is_tautology:
        # "Successful" injection — returns all fake users
        return {
            "vulnerable": True,
            "output": (
                f"Query executed: {fake_query}\n\n"
                f"Result: {len(FAKE_USERS_DB)} rows returned (ALL USERS EXPOSED)\n\n"
                + "\n".join(
                    f"  [{u['id']}] {u['username']} | {u['email']} | {u['role']} | {u['balance']}"
                    for u in FAKE_USERS_DB
                )
            ),
            "query": fake_query,
            "rows_returned": len(FAKE_USERS_DB),
        }

    elif is_union:
        return {
            "vulnerable": True,
            "output": (
                f"Query executed: {fake_query}\n\n"
                "Result: UNION query succeeded — additional data extracted:\n\n"
                "  [INJECTED] admin | admin@internal.local | superadmin | $999,999.00\n"
                "  (This data was retrieved from a simulated joined table)"
            ),
            "query": fake_query,
            "rows_returned": 1,
        }

    elif is_destructive:
        return {
            "vulnerable": True,
            "output": (
                f"Query attempted: {fake_query}\n\n"
                "Result: DESTRUCTIVE QUERY DETECTED\n"
                "In a real system, this could have deleted or modified data.\n"
                "(No actual data was affected — this is a simulation)"
            ),
            "query": fake_query,
            "rows_returned": 0,
        }

    elif has_comment:
        # Partial injection with comment
        return {
            "vulnerable": True,
            "output": (
                f"Query executed: {fake_query}\n\n"
                "Result: Query terminated early via comment injection.\n"
                "The remaining query conditions were bypassed."
            ),
            "query": fake_query,
            "rows_returned": 0,
        }

    else:
        # Normal lookup
        found = [u for u in FAKE_USERS_DB if u["username"].lower() == username_input.lower()]
        if found:
            u = found[0]
            return {
                "vulnerable": False,
                "output": (
                    f"Query executed: {fake_query}\n\n"
                    f"Result: 1 row returned\n\n"
                    f"  [{u['id']}] {u['username']} | {u['email']} | {u['role']}"
                ),
                "query": fake_query,
                "rows_returned": 1,
            }
        else:
            return {
                "vulnerable": False,
                "output": (
                    f"Query executed: {fake_query}\n\n"
                    "Result: 0 rows returned — user not found."
                ),
                "query": fake_query,
                "rows_returned": 0,
            }


# Register the target
register_lab(
    lab_id="sqli",
    name="SQL Injection Target",
    category="sqli",
    difficulty="Intermediate",
    description=SQLI_DESCRIPTION,
    handler=handle_sqli_lab,
)
