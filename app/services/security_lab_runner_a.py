"""Runner A shim — preserved for import compatibility.

Real implementation is in app/services/security_lab.py (_TEST_LOCK,
validate_target_url, _synthetic_evidence, CANARYForType) and the runner in
app/services/security_lab_runner.py (run_lab_test). This file only re-exports
run_lab_test so old import paths keep working. Safe to delete once no caller
imports app.services.security_lab_runner_a directly (none do today).
"""
from app.services.security_lab_runner import run_lab_test  # re-export

__all__ = ["run_lab_test"]
