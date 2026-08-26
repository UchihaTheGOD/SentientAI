"""CyberLLM client interface — mock implementation.

This is the integration point for the real CyberLLM/Sentinel model.
Currently returns structured mock analysis. When the model is ready,
swap MockCyberLLMClient for a real HTTP client implementation.
"""
from dataclasses import dataclass
from typing import Optional, Dict, Any
from app.config import settings


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


class MockCyberLLMClient(CyberLLMClientInterface):
    """Mock implementation using the rule-based detection results.

    Formats detection output into educational CyberLLM-style analysis.
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

        return AttackAnalysis(
            attack_type=attack_type,
            confidence=0.85 if event.get("detected") else 0.1,
            explanation=event.get("explanation", "No analysis available."),
            technique_description=description,
            defense_recommendation=defense,
            severity=event.get("severity", "low"),
        )

    def classify_attack(self, event: Dict[str, Any]) -> str:
        return event.get("attack_category", "unknown")

    def explain_attack(self, event: Dict[str, Any]) -> str:
        attack_type = event.get("attack_category", "unknown")
        return self.ATTACK_DESCRIPTIONS.get(attack_type, "No explanation available for this attack type.")

    def generate_training_example(self, event: Dict[str, Any]) -> Dict[str, Any]:
        attack_type = event.get("attack_category", "unknown")
        payload = event.get("sanitized_payload", "")
        explanation = event.get("explanation", "")
        defense = event.get("defense_recommendation", "")

        return {
            "instruction": f"Analyze the following input for {attack_type} vulnerabilities and explain the security implications.",
            "input": payload,
            "output": f"Attack detected: {attack_type}. {explanation} Recommended defense: {defense}",
            "attack_type": attack_type,
            "severity": event.get("severity", "low"),
            "source": "sentientai_lab",
            "approved": False,
        }


# ---------------------------------------------------------------------------
# Factory — returns real client when API is configured, mock otherwise
# ---------------------------------------------------------------------------

def get_cyberllm_client() -> CyberLLMClientInterface:
    if settings.CYBERLLM_API_URL:
        # Future: return RealCyberLLMClient(settings.CYBERLLM_API_URL, settings.CYBERLLM_API_KEY)
        pass
    return MockCyberLLMClient()
