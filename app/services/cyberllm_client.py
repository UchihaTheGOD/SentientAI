"""CyberLLM client interface — mock and real adapter architecture.

Architecture:
  CyberLLMClientInterface   ← abstract contract
      ├── MockCyberLLMClient  ← deterministic rule-based mock (always available)
      └── RealSentinelClient  ← HTTP adapter for SentinelSmolLM2-360M-V9 inference

Finding classification:
  OBSERVED  — directly seen in the request/payload (concrete evidence)
  INFERRED  — logically concluded from observed evidence (model assessment)
  UNKNOWN   — cannot be determined from available telemetry (honest gap)

The real client MUST NOT invent telemetry that was not observed.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List
from app.config import settings


# ---------------------------------------------------------------------------
# Confidence classification
# ---------------------------------------------------------------------------

class AnalysisConfidence(str, Enum):
    OBSERVED = "OBSERVED"   # concrete, directly seen
    INFERRED = "INFERRED"   # logically derived from evidence
    UNKNOWN  = "UNKNOWN"    # cannot be determined


@dataclass
class SentinelFinding:
    """A single finding from Sentinel analysis with confidence classification."""
    statement: str
    confidence: AnalysisConfidence


@dataclass
class AttackAnalysis:
    attack_type: str = "unknown"
    confidence: float = 0.0
    explanation: str = ""
    technique_description: str = ""
    defense_recommendation: str = ""
    severity: str = "low"
    cwe_id: Optional[str] = None
    mitre_id: Optional[str] = None
    # Structured findings (used by RealSentinelClient; optional for mock)
    findings: List[SentinelFinding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

class CyberLLMClientInterface:
    """Abstract interface — defines what any CyberLLM client must implement."""

    def analyze_attack(self, event: Dict[str, Any]) -> AttackAnalysis:
        raise NotImplementedError

    def classify_attack(self, event: Dict[str, Any]) -> str:
        raise NotImplementedError

    def explain_attack(self, event: Dict[str, Any]) -> str:
        raise NotImplementedError

    def generate_training_example(self, event: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Mock implementation (deterministic, always available)
# ---------------------------------------------------------------------------

class MockCyberLLMClient(CyberLLMClientInterface):
    """Mock implementation using the rule-based detection results.

    Formats detection output into educational CyberLLM-style analysis.
    No external calls — fully deterministic.
    """

    ATTACK_DESCRIPTIONS = {
        "SQL Injection": (
            "SQL Injection occurs when an attacker inserts malicious SQL code into "
            "application queries through user input fields. This can allow unauthorized "
            "data access, modification, or deletion. The attacker exploits insufficient "
            "input validation to manipulate the database query logic."
        ),
        "Cross-Site Scripting (XSS)": (
            "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts "
            "into web pages viewed by other users. This can lead to session hijacking, "
            "credential theft, defacement, or redirection to malicious sites. XSS exploits "
            "the trust a user has in a particular website."
        ),
        "Path Traversal": (
            "Path Traversal (Directory Traversal) attacks attempt to access files and "
            "directories outside the intended scope by manipulating file path references. "
            "Attackers use sequences like ../ to navigate up the directory tree and access "
            "sensitive system files."
        ),
        "Command Injection": (
            "Command Injection occurs when an attacker can execute arbitrary operating "
            "system commands on the host through a vulnerable application. This typically "
            "happens when user input is passed unsanitized to system shell functions."
        ),
        "Authentication Bypass": (
            "Authentication Bypass attacks attempt to circumvent login mechanisms through "
            "weak credentials, default passwords, or logic flaws in the authentication "
            "process. Successful bypass grants unauthorized access to protected resources."
        ),
    }

    def analyze_attack(self, event: Dict[str, Any]) -> AttackAnalysis:
        attack_type = event.get("attack_category", "unknown")
        description = self.ATTACK_DESCRIPTIONS.get(attack_type, "Unknown attack technique.")
        defense = event.get("defense_recommendation", "Apply defense-in-depth principles.")
        detected = event.get("detected", False)

        findings = []
        if detected:
            matched = event.get("patterns_matched", [])
            for pattern in matched:
                findings.append(SentinelFinding(
                    statement=pattern,
                    confidence=AnalysisConfidence.OBSERVED,
                ))
            findings.append(SentinelFinding(
                statement=f"Input is likely a {attack_type} attempt",
                confidence=AnalysisConfidence.INFERRED,
            ))
            findings.append(SentinelFinding(
                statement="Whether exploitation would succeed against a live target",
                confidence=AnalysisConfidence.UNKNOWN,
            ))

        return AttackAnalysis(
            attack_type=attack_type,
            confidence=0.85 if detected else 0.1,
            explanation=event.get("explanation", "No analysis available."),
            technique_description=description,
            defense_recommendation=defense,
            severity=event.get("severity", "low"),
            findings=findings,
        )

    def classify_attack(self, event: Dict[str, Any]) -> str:
        return event.get("attack_category", "unknown")

    def explain_attack(self, event: Dict[str, Any]) -> str:
        attack_type = event.get("attack_category", "unknown")
        return self.ATTACK_DESCRIPTIONS.get(
            attack_type, "No explanation available for this attack type."
        )

    def generate_training_example(self, event: Dict[str, Any]) -> Dict[str, Any]:
        attack_type = event.get("attack_category", "unknown")
        payload = event.get("sanitized_payload", "")
        explanation = event.get("explanation", "")
        defense = event.get("defense_recommendation", "")

        return {
            "instruction": (
                f"Analyze the following input for {attack_type} vulnerabilities "
                f"and explain the security implications."
            ),
            "input": payload,
            "output": (
                f"Attack detected: {attack_type}. {explanation} "
                f"Recommended defense: {defense}"
            ),
            "attack_type": attack_type,
            "severity": event.get("severity", "low"),
            "source": "sentientai_lab",
            "approved": False,
        }


# ---------------------------------------------------------------------------
# Real HTTP adapter — connects to SentinelSmolLM2-360M-V9 inference server
# ---------------------------------------------------------------------------

class RealSentinelClient(CyberLLMClientInterface):
    """HTTP adapter for the SentinelSmolLM2-360M-V9 inference server.

    Expected server API:
      POST /analyze
      Body: { "payload": str, "context": { ... } }
      Response: { "attack_type": str, "confidence": float, "explanation": str,
                  "findings": [ {"statement": str, "confidence": "OBSERVED"|"INFERRED"|"UNKNOWN"} ],
                  "defense": str, "severity": str }

    Falls back to MockCyberLLMClient transparently on any connection failure.
    Never fabricates telemetry — if the server returns nothing, we say UNKNOWN.
    """

    def __init__(self, api_url: str, api_key: Optional[str] = None):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self._mock_fallback = MockCyberLLMClient()

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _post(self, endpoint: str, body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make a POST request; returns None on any failure."""
        try:
            import httpx
            response = httpx.post(
                f"{self.api_url}{endpoint}",
                json=body,
                headers=self._headers(),
                timeout=10.0,
            )
            response.raise_for_status()
            return response.json()
        except Exception:
            # Connection failure, timeout, non-200, etc. — fall back to mock
            return None

    def analyze_attack(self, event: Dict[str, Any]) -> AttackAnalysis:
        body = {
            "payload": event.get("sanitized_payload", ""),
            "context": {
                "detected": event.get("detected", False),
                "patterns_matched": event.get("patterns_matched", []),
                "attack_category": event.get("attack_category", ""),
                "severity": event.get("severity", ""),
            },
        }
        data = self._post("/analyze", body)
        if data is None:
            return self._mock_fallback.analyze_attack(event)

        # Parse server findings with OBSERVED/INFERRED/UNKNOWN classification
        raw_findings = data.get("findings", [])
        findings = []
        for f in raw_findings:
            try:
                conf = AnalysisConfidence(f.get("confidence", "UNKNOWN"))
            except ValueError:
                conf = AnalysisConfidence.UNKNOWN
            findings.append(SentinelFinding(
                statement=f.get("statement", ""),
                confidence=conf,
            ))

        return AttackAnalysis(
            attack_type=data.get("attack_type", "unknown"),
            confidence=float(data.get("confidence", 0.0)),
            explanation=data.get("explanation", ""),
            technique_description=data.get("technique", ""),
            defense_recommendation=data.get("defense", ""),
            severity=data.get("severity", "low"),
            cwe_id=data.get("cwe_id"),
            mitre_id=data.get("mitre_id"),
            findings=findings,
        )

    def classify_attack(self, event: Dict[str, Any]) -> str:
        data = self._post("/classify", {"payload": event.get("sanitized_payload", "")})
        if data is None:
            return self._mock_fallback.classify_attack(event)
        return data.get("attack_type", "unknown")

    def explain_attack(self, event: Dict[str, Any]) -> str:
        data = self._post("/explain", {"payload": event.get("sanitized_payload", "")})
        if data is None:
            return self._mock_fallback.explain_attack(event)
        return data.get("explanation", "")

    def generate_training_example(self, event: Dict[str, Any]) -> Dict[str, Any]:
        # Training example generation always uses the mock for now
        # (training pipeline requires human review — not auto-learned from model output)
        return self._mock_fallback.generate_training_example(event)


# ---------------------------------------------------------------------------
# Factory — returns real client when API is configured, mock otherwise
# ---------------------------------------------------------------------------

def get_cyberllm_client() -> CyberLLMClientInterface:
    if settings.CYBERLLM_API_URL:
        return RealSentinelClient(
            api_url=settings.CYBERLLM_API_URL,
            api_key=settings.CYBERLLM_API_KEY or None,
        )
    return MockCyberLLMClient()
