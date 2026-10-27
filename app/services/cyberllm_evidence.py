"""Deterministic evidence-consistency checks for CyberLLM outputs.

The model is not trusted for factual fields that can be read directly
from the input. If the input says "5 failed authentication attempts
within 60 seconds" and the model summary says "6 seconds", that is a
contradiction, not a paraphrase — the API must downgrade to
needs_review and say so, never silently rewrite the model's numbers
to match the input (that would hide the model's error).

Checked only when the input itself states a value unambiguously:
- failed-attempt count, time window, ISO timestamp, IP address (+port),
  HTTP status code, URL/domain
- claimed outcome (success vs failure) when the input states one
- internal contradictions inside the model output itself

False-positive control: the API passes only summary + reasoning +
indicators to this module, not recommended_actions, so a recommendation
("block port 443", "return 403") is not mistaken for an observed fact.
A mismatch never rewrites anything — it downgrades to needs_review
with the mismatch quoted in limitations, preserving the original
model classification in model_classification.
"""
from __future__ import annotations

import re

_WORD_NUMBERS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
    "twelve": 12, "fifteen": 15, "twenty": 20, "thirty": 30, "sixty": 60,
}
_NUM = r"(\d+|" + "|".join(_WORD_NUMBERS) + r")"


def _to_int(token: str) -> int:
    token = token.lower()
    return int(token) if token.isdigit() else _WORD_NUMBERS[token]


def _to_seconds(value: int, unit: str) -> int:
    unit = unit.lower()
    if unit.startswith("minute"):
        return value * 60
    if unit.startswith("hour"):
        return value * 3600
    return value


def input_failed_count(text: str) -> int | None:
    lowered = text.lower()
    patterns = [
        rf"{_NUM}\s+(?:failed|unsuccessful)\s+(?:login|logins|authentication|auth|attempts?)",
        rf"(?:failed|unsuccessful)\s+(?:login|logins|authentication|auth)\s+(?:attempts?\s+)?{_NUM}\s+times?",
        rf"{_NUM}\s+failed\s+attempts?",
    ]
    for pattern in patterns:
        match = re.search(pattern, lowered)
        if match:
            return _to_int(match.group(1))
    return None


def input_time_window_seconds(text: str) -> int | None:
    lowered = text.lower()
    match = re.search(
        rf"(?:within|in|over|during)\s+{_NUM}\s+(seconds?|minutes?|hours?)",
        lowered,
    )
    if match:
        return _to_seconds(_to_int(match.group(1)), match.group(2))
    return None


def _output_time_windows(text: str) -> list[int]:
    lowered = text.lower()
    values = []
    for match in re.finditer(
        rf"{_NUM}\s+(seconds?|minutes?|hours?)", lowered
    ):
        values.append(_to_seconds(_to_int(match.group(1)), match.group(2)))
    return values


def _output_failed_counts(text: str) -> list[int]:
    lowered = text.lower()
    values = []
    for pattern in [
        rf"{_NUM}\s+(?:failed|unsuccessful)\s+(?:login|logins|authentication|auth|attempts?)",
        rf"(?:failed|unsuccessful)\s+(?:login|logins|authentication|auth)\s+(?:attempts?\s+)?{_NUM}\s+times?",
    ]:
        for match in re.finditer(pattern, lowered):
            values.append(_to_int(match.group(1)))
    return values


_IP_RE = r"(?:\d{1,3}\.){3}\d{1,3}"
_URL_RE = r"https?://[^\s,;\"']+"
_DOMAIN_RE = r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|co|uk|edu|gov|app|xyz)\b"
_TIMESTAMP_RE = r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?\b"
_STATUS_RE = r"\b(?:status|responded with|returned|response code)\s*:?\s*(100|200|201|204|301|302|400|401|403|404|500|502|503)\b"
_SUCCESS_PHRASES = (
    "successfully logged in", "successful login", "gained access",
    "data exfiltrated", "exfiltrated data", "account compromised",
    "attacker succeeded", "breach succeeded",
)
_FAILURE_PHRASES = (
    "login failed", "failed login", "access denied", "blocked",
    "authentication failed", "login attempt failed",
)


def _ips(text: str) -> set[str]:
    return set(re.findall(_IP_RE, text.lower()))


def _ip_ports(text: str) -> set[str]:
    return set(re.findall(rf"{_IP_RE}:(\d{{1,5}})", text.lower()))


def _domains(text: str) -> set[str]:
    found = set(re.findall(_DOMAIN_RE, text.lower()))
    for url in re.findall(_URL_RE, text.lower()):
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
        if host:
            found.add(host)
    return found


def _timestamps(text: str) -> set[str]:
    return set(re.findall(_TIMESTAMP_RE, text))


def _statuses(text: str) -> set[str]:
    return set(re.findall(_STATUS_RE, text.lower()))


def _input_statuses(text: str) -> set[str]:
    """Observed status in an HTTP request line (GET /path 401), plus
    the phrased forms. Bare 3-digit numbers elsewhere are NOT treated
    as a status code, to avoid flagging counts, ports, or years."""
    found = _statuses(text)
    found.update(re.findall(
        r"\b(?:get|post|put|delete|head|options)\s+\S+\s+(100|200|201|204|301|302|400|401|403|404|500|502|503)\b",
        text.lower(),
    ))
    return found


def _outcome(text: str) -> str | None:
    lowered = text.lower()
    if any(p in lowered for p in _SUCCESS_PHRASES):
        return "success"
    if any(p in lowered for p in _FAILURE_PHRASES):
        return "failure"
    return None


def check_evidence(input_text: str, model_text: str) -> list[str]:
    """Return mismatch descriptions, or [] when consistent / unchecked."""
    mismatches: list[str] = []
    expected_count = input_failed_count(input_text)
    if expected_count is not None:
        for found in _output_failed_counts(model_text):
            if found != expected_count:
                mismatches.append(
                    f"failed-attempt count: input says {expected_count}, "
                    f"model output says {found}"
                )
                break
    expected_window = input_time_window_seconds(input_text)
    if expected_window is not None:
        for found in _output_time_windows(model_text):
            if found != expected_window:
                mismatches.append(
                    f"time window: input says {expected_window} seconds, "
                    f"model output says {found} seconds"
                )
                break
    # Internal contradictions: the model disagrees with itself.
    distinct_counts = set(_output_failed_counts(model_text))
    if len(distinct_counts) > 1:
        mismatches.append(
            f"contradictory evidence in model output: failed-attempt counts {sorted(distinct_counts)}"
        )
    distinct_windows = set(_output_time_windows(model_text))
    if len(distinct_windows) > 1:
        mismatches.append(
            f"contradictory evidence in model output: time windows {sorted(distinct_windows)} seconds"
        )
    # IP addresses (and IP:port) stated in the input.
    input_ips = _ips(input_text)
    if input_ips:
        for ip in sorted(_ips(model_text) - input_ips):
            mismatches.append(f"IP address not in input: model output says {ip}")
            break
    input_ports = _ip_ports(input_text)
    if input_ports:
        for port in sorted(_ip_ports(model_text) - input_ports):
            mismatches.append(f"port not in input: model output says {port}")
            break
    # Timestamps: a single unambiguous event time in the input.
    input_ts = _timestamps(input_text)
    if len(input_ts) == 1:
        model_ts = _timestamps(model_text)
        if model_ts and model_ts != input_ts:
            mismatches.append(
                f"timestamp: input says {sorted(input_ts)[0]}, "
                f"model output says {sorted(model_ts)[0]}"
            )
    # HTTP status codes, only when phrased as an observed response.
    input_status = _input_statuses(input_text)
    if input_status:
        model_status = _statuses(model_text)
        if model_status and model_status != input_status:
            mismatches.append(
                f"HTTP status: input says {sorted(input_status)[0]}, "
                f"model output says {sorted(model_status)[0]}"
            )
    # URLs / domains stated in the input.
    input_domains = _domains(input_text)
    if input_domains:
        for domain in sorted(_domains(model_text) - input_domains):
            mismatches.append(f"domain not in input: model output says {domain}")
            break
    # Claimed outcome vs observed outcome.
    input_outcome = _outcome(input_text)
    model_outcome = _outcome(model_text)
    if input_outcome and model_outcome and input_outcome != model_outcome:
        mismatches.append(
            f"claimed outcome: input shows {input_outcome}, "
            f"model output claims {model_outcome}"
        )
    return mismatches
