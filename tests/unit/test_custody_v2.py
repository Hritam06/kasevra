import json

import pytest

from kasevra.custody.chain import (
    CustodyLogError,
    append_event,
    validate_chain,
)
from kasevra.custody.events import create_event


def test_create_event_has_valid_hash():
    event = create_event(
        case_id="case-1",
        operator="examiner",
        action="acquired",
        details={"method": "filesystem"},
    )
    assert len(event.event_hash) == 64
    assert event.previous_event_hash == "0" * 64


def test_append_and_validate_multiple_events(tmp_path):
    log = tmp_path / "custody.jsonl"
    append_event(
        log,
        case_id="case-1",
        operator="examiner",
        action="acquired",
        evidence_id="evidence-1",
    )
    append_event(
        log,
        case_id="case-1",
        operator="examiner",
        action="verified",
        evidence_id="evidence-1",
    )
    result = validate_chain(log)
    assert result["status"] == "PASS"
    assert result["event_count"] == 2


def test_detects_modified_event(tmp_path):
    log = tmp_path / "custody.jsonl"
    append_event(log, case_id="case-1", operator="examiner", action="acquired")
    records = [json.loads(line) for line in log.read_text().splitlines()]
    records[0]["action"] = "modified"
    log.write_text(json.dumps(records[0]) + "\n")
    assert validate_chain(log)["status"] == "ERROR"


def test_detects_deleted_event(tmp_path):
    log = tmp_path / "custody.jsonl"
    append_event(log, case_id="case-1", operator="examiner", action="first")
    append_event(log, case_id="case-1", operator="examiner", action="second")
    records = log.read_text().splitlines()
    log.write_text(records[1] + "\n")
    assert validate_chain(log)["status"] == "ERROR"


def test_detects_reordered_events(tmp_path):
    log = tmp_path / "custody.jsonl"
    append_event(log, case_id="case-1", operator="examiner", action="first")
    append_event(log, case_id="case-1", operator="examiner", action="second")
    records = log.read_text().splitlines()
    log.write_text("\n".join(reversed(records)) + "\n")
    assert validate_chain(log)["status"] == "ERROR"


def test_refuses_append_to_tampered_log(tmp_path):
    log = tmp_path / "custody.jsonl"
    append_event(log, case_id="case-1", operator="examiner", action="first")
    log.write_text("{}\n")
    with pytest.raises(CustodyLogError):
        append_event(log, case_id="case-1", operator="examiner", action="second")


def test_refuses_symlink_log(tmp_path):
    log = tmp_path / "custody.jsonl"
    outside = tmp_path / "outside.jsonl"
    outside.write_text("")
    log.symlink_to(outside)
    with pytest.raises(CustodyLogError):
        append_event(log, case_id="case-1", operator="examiner", action="first")


def test_rejects_incomplete_final_line(tmp_path):
    log = tmp_path / "custody.jsonl"
    append_event(log, case_id="case-1", operator="examiner", action="first")
    log.write_bytes(log.read_bytes().rstrip(b"\n"))
    assert validate_chain(log)["status"] == "ERROR"


def test_custody_writer_lock_blocks_concurrent_append(tmp_path):
    log = tmp_path / "custody.jsonl"
    lock = tmp_path / "custody.jsonl.lock"
    lock.write_text("another writer")
    with pytest.raises(CustodyLogError):
        append_event(log, case_id="case-1", operator="examiner", action="blocked")
    assert not log.exists()


def test_custody_rejects_non_json_event_details():
    with pytest.raises((TypeError, ValueError)):
        create_event(
            case_id="case-1",
            operator="examiner",
            action="invalid",
            details={"unsafe": object()},
        )


def test_custody_lock_is_removed_after_successful_append(tmp_path):
    log = tmp_path / "custody.jsonl"
    append_event(log, case_id="case-1", operator="examiner", action="recorded")
    assert not (tmp_path / "custody.jsonl.lock").exists()
    assert validate_chain(log)["status"] == "PASS"
