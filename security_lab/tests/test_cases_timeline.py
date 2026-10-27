"""Case store + timeline behaviour (including note/status guards)."""

import pytest

from ..cases import CaseStore
from ..scanner.findings import Finding
from ..timeline import Timeline


def _finding():
    return Finding("Test finding", "Test", "High", "high", "suspected",
                   "explanation", "evidence", "http://127.0.0.1:1/",
                   "impact", "fix")


def test_case_lifecycle(tmp_path):
    store = CaseStore(tmp_path / "cases.json")
    case = store.create_from_finding(_finding())
    assert case.id == 1
    assert case.status == "New"
    store.set_status(case.id, "Investigating")
    store.add_note(case.id, "checked the log")
    assert store.get(case.id).status == "Investigating"
    assert store.get(case.id).notes[0]["text"] == "checked the log"
    assert store.summary_counts()["Investigating"] == 1
    assert store.summary_counts()["total"] == 1
    # Reloading from disk preserves the case.
    reloaded = CaseStore(tmp_path / "cases.json")
    assert reloaded.get(1).status == "Investigating"


def test_case_status_validation(tmp_path):
    store = CaseStore(tmp_path / "cases.json")
    case = store.create("title", "Low", "http://x/", "finding", "evidence")
    with pytest.raises(ValueError):
        store.set_status(case.id, "Bogus")
    with pytest.raises(KeyError):
        store.set_status(999, "Resolved")
    with pytest.raises(KeyError):
        store.add_note(999, "note")


def test_case_exports(tmp_path):
    store = CaseStore(tmp_path / "cases.json")
    store.create("title", "Low", "http://x/", "finding", "evidence")
    store.export_json(tmp_path / "cases.json.out")
    store.export_csv(tmp_path / "cases.csv")
    assert (tmp_path / "cases.json.out").exists()
    assert (tmp_path / "cases.csv").exists()


def test_timeline_redacts_and_reads(tmp_path):
    timeline = Timeline(tmp_path / "timeline.jsonl")
    timeline.append("scan", "api_key=abcdef123456 secret", source="scanner")
    entries = timeline.read_all()
    assert len(entries) == 1
    assert "abcdef123456" not in entries[0]["detail"]
    assert entries[0]["source"] == "scanner"
    assert entries[0]["event"] == "scan"
