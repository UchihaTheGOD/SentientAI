"""Rule-based detection engine.

Pattern-matches common attack signatures in lab payloads.
This is the component CyberLLM will eventually replace/augment.
"""
import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class DetectionResult:
    detected: bool = False
    attack_category: str = "unknown"
    severity: str = "low"
    patterns_matched: List[str] = field(default_factory=list)
    explanation: str = ""
    defense_recommendation: str = ""
    should_block: bool = False


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

SQL_INJECTION_PATTERNS = [
    (r"('\s*(OR|AND)\s+.*=.*)", "Tautology-based SQL injection"),
    (r"(;\s*(DROP|DELETE|UPDATE|INSERT|ALTER)\s)", "Destructive SQL statement"),
    (r"(UNION\s+(ALL\s+)?SELECT)", "UNION-based SQL injection"),
    (r"(';\s*--)", "Comment-based SQL injection termination"),
    (r"(1\s*=\s*1)", "Always-true condition"),
    (r"('\s*OR\s+')", "String-based OR injection"),
    (r"(--\s*$)", "SQL comment terminator"),
    (r"(/\*.*\*/)", "Block comment injection"),
    (r"(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)", "Time-based blind injection"),
]

XSS_PATTERNS = [
    (r"(<script[\s>])", "Script tag injection"),
    (r"(on\w+\s*=)", "Event handler attribute injection"),
    (r"(javascript\s*:)", "JavaScript URI injection"),
    (r"(<iframe[\s>])", "Iframe injection"),
    (r"(<img\s+[^>]*onerror)", "Image error handler injection"),
    (r"(document\.(cookie|location|write))", "DOM manipulation attempt"),
    (r"(eval\s*\()", "Eval call injection"),
    (r"(<svg[\s>].*onload)", "SVG onload injection"),
    (r"(alert\s*\(|confirm\s*\(|prompt\s*\()", "Dialog function call"),
]

PATH_TRAVERSAL_PATTERNS = [
    (r"(\.\./|\.\.\\)", "Directory traversal sequence"),
    (r"(%2e%2e[/\\%])", "URL-encoded directory traversal"),
    (r"(/etc/passwd|/etc/shadow)", "Unix sensitive file access"),
    (r"(C:\\Windows\\|C:\\Users\\)", "Windows system path access"),
    (r"(%00)", "Null byte injection"),
]

COMMAND_INJECTION_PATTERNS = [
    (r"(;\s*(ls|cat|whoami|id|uname|pwd|dir|type|net\s))", "Command chaining"),
    (r"(\|\s*(ls|cat|whoami|id|uname|pwd))", "Pipe-based command injection"),
    (r"(`[^`]+`)", "Backtick command substitution"),
    (r"(\$\([^)]+\))", "Subshell command substitution"),
    (r"(&&\s*\w+|$\|\|\s*\w+)", "Logical operator command chaining"),
    (r"(>\s*/)", "Output redirection to root"),
]

AUTH_BYPASS_PATTERNS = [
    (r"(admin|root|administrator)", "Privileged username attempt"),
    (r"(password|123456|qwerty|letmein)", "Common weak password"),
]

# Severity ranking — higher value = more dangerous. Used to ensure the most
# severe classification wins when multiple categories match a single payload.
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

CATEGORY_CONFIG = {
    "sqli": {
        "patterns": SQL_INJECTION_PATTERNS,
        "name": "SQL Injection",
        "severity": "high",
        "defense": (
            "Use parameterized queries or prepared statements. Never concatenate "
            "user input directly into SQL queries. Apply input validation and "
            "use an ORM like SQLAlchemy with bound parameters."
        ),
    },
    "xss": {
        "patterns": XSS_PATTERNS,
        "name": "Cross-Site Scripting (XSS)",
        "severity": "medium",
        "defense": (
            "Sanitize and encode all user-supplied output before rendering it in HTML. "
            "Use Content-Security-Policy headers. Apply context-aware output encoding "
            "(HTML entity encoding, JavaScript encoding, URL encoding)."
        ),
    },
    "path_traversal": {
        "patterns": PATH_TRAVERSAL_PATTERNS,
        "name": "Path Traversal",
        "severity": "high",
        "defense": (
            "Validate and canonicalize file paths. Use an allowlist of permitted files. "
            "Never construct file paths from raw user input. Use chroot or sandboxed "
            "file access where possible."
        ),
    },
    "command_injection": {
        "patterns": COMMAND_INJECTION_PATTERNS,
        "name": "Command Injection",
        "severity": "critical",
        "defense": (
            "Never pass user input to shell commands. Use language-native APIs instead "
            "of system/exec calls. If shell interaction is unavoidable, use strict "
            "allowlists and avoid string interpolation."
        ),
    },
    "auth_bypass": {
        "patterns": AUTH_BYPASS_PATTERNS,
        "name": "Authentication Bypass",
        "severity": "medium",
        "defense": (
            "Enforce strong password policies. Implement account lockout after failed "
            "attempts. Use multi-factor authentication. Never rely on client-side "
            "authentication checks alone."
        ),
    },
}


def detect(payload: str, lab_category: str) -> DetectionResult:
    """Run detection against a payload for a given lab category.

    Args:
        payload: The raw user input / request body.
        lab_category: One of the keys in CATEGORY_CONFIG (e.g. 'sqli', 'xss').

    Returns:
        DetectionResult with findings.

    Note:
        Command injection is always checked regardless of lab_category, because
        it is critical severity and should always be blocked across all labs.
    """
    result = DetectionResult()

    if lab_category not in CATEGORY_CONFIG:
        # Run all categories
        categories_to_check = list(CATEGORY_CONFIG.keys())
    else:
        # Always include command_injection — critical, must block everywhere.
        # Use a deterministic list (not a set) so iteration order is stable.
        categories_to_check = [lab_category]
        if lab_category != "command_injection":
            categories_to_check.append("command_injection")

    for cat_key in categories_to_check:
        config = CATEGORY_CONFIG[cat_key]
        for pattern, description in config["patterns"]:
            if re.search(pattern, payload, re.IGNORECASE):
                result.detected = True
                result.patterns_matched.append(description)

                # Keep the most severe classification — never downgrade.
                current_sev = SEVERITY_ORDER.get(config["severity"], 0)
                best_sev = SEVERITY_ORDER.get(result.severity, 0)
                if current_sev >= best_sev:
                    result.attack_category = config["name"]
                    result.severity = config["severity"]
                    result.defense_recommendation = config["defense"]

    if result.detected:
        matched_str = "; ".join(result.patterns_matched)
        result.explanation = (
            f"The input matched known attack signatures: {matched_str}. "
            f"This is consistent with a {result.attack_category} attack."
        )
        # Block critical severity attacks
        if result.severity == "critical":
            result.should_block = True

    return result

