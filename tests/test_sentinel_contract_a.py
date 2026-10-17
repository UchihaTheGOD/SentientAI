from app.services.sentinel_schema import validate_sentinel_output, parse_model_text

def test_validate_accepts_valid():
    valid=("Summary:\nBenign log with normal access.\nIndicators:\n- 2024-01-01 10:00:00 INFO GET / 200\n- IP 192.168.1.1 single request\nReasoning:\nSingle benign request with 200 status, no repeated failures.\nProvisional assessment: likely_benign\nInput status: valid")
    r=validate_sentinel_output(valid,"ok")
    assert r["valid"] is True and r["verdict"]=="likely_benign" and r["input_status"]=="valid"
def test_validate_rejects_missing():
    r=validate_sentinel_output("Provisional assessment: likely_benign\nInput status: valid","ok")
    assert r["valid"] is False and "missing Summary section" in r["errors"]
def test_validate_rejects_empty():
    r=validate_sentinel_output("","ok")
    assert r["valid"] is False and "empty output" in r["errors"]
def test_validate_rejects_empty_status():
    valid=("Summary:\nBenign log.\nIndicators:\n- None observed\nReasoning:\nNo evidence.\nProvisional assessment: likely_benign\nInput status: valid")
    r=validate_sentinel_output(valid,"empty")
    assert r["valid"] is False and any("inference status not ok" in e for e in r["errors"])
def test_validate_empty_input_status():
    empty_case=("Summary:\nNo evidence supplied; log was empty.\nIndicators:\n- None observed\nReasoning:\nNo log content was provided. Cannot assess threat without evidence.\nProvisional assessment: likely_benign\nInput status: empty")
    r=validate_sentinel_output(empty_case,"ok")
    assert r["valid"] is True and r["input_status"]=="empty"
def test_rejects_multiple_verdicts():
    bad=("Summary:\nTest.\nIndicators:\n- None observed\nReasoning:\nTest.\nProvisional assessment: likely_benign likely_threat\nInput status: valid")
    r=validate_sentinel_output(bad,"ok")
    assert r["valid"] is False and any("multiple verdicts" in e for e in r["errors"])
def test_rejects_invalid_verdict_value():
    bad=("Summary:\nTest.\nIndicators:\n- None observed\nReasoning:\nTest.\nProvisional assessment: definitely_threat\nInput status: valid")
    r=validate_sentinel_output(bad,"ok")
    assert r["valid"] is False and any("invalid provisional verdict value" in e for e in r["errors"])
def test_rejects_invalid_input_status():
    bad=("Summary:\nTest.\nIndicators:\n- None observed\nReasoning:\nTest.\nProvisional assessment: likely_benign\nInput status: maybe")
    r=validate_sentinel_output(bad,"ok")
    assert r["valid"] is False and any("invalid input status value" in e for e in r["errors"])
def test_parse_invalid_not_valid():
    r=parse_model_text("likely_threat attack confirmed!!!","ok")
    assert r["structured_valid"] is False
def test_parse_empty_status():
    r=parse_model_text("","empty")
    assert r["structured_valid"] is False and "empty or error status" in r["validation_errors"]
