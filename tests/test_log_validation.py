"""Log validation tests — input limits preserved after the prompt-service removal."""
import pytest

from app.services.log_validation import MAX_LOG_CHARS, validate_log_text


def test_validate_ok():
    assert validate_log_text("  hello log  ") == "hello log"


def test_validate_empty_rejected():
    with pytest.raises(ValueError):
        validate_log_text("")
    with pytest.raises(ValueError):
        validate_log_text("   ")
    with pytest.raises(ValueError):
        validate_log_text(None)


def test_validate_oversize_rejected():
    with pytest.raises(ValueError):
        validate_log_text("x" * (MAX_LOG_CHARS + 1))


def test_validate_strips_null_bytes():
    assert "\x00" not in validate_log_text("a\x00b")
