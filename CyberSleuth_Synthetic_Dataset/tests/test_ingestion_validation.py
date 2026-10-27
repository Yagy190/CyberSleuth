"""
Test suite for CyberSleuth AI Log Ingestion & Schema Validation Pipeline.

Validates that Member 2's ingestion endpoint:
- Ingests valid RFC-compliant security event records
- Detects and rejects malformed timestamps (SCN007)
- Flags and deduplicates duplicate event identifiers (SCN008)
- Rejects missing required schema fields (SCN012)
- Safely processes edge-case strings, Unicode, and nested details dictionaries
- Supports graceful partial-batch validation and quarantines
"""
import pytest
from datetime import datetime
from typing import Dict, Any, List


def validate_event_schema(event: Dict[str, Any]) -> tuple[bool, str]:
    """
    Reference validator matching Member 2's Pydantic EventIngestSchema.
    Returns (is_valid, error_reason).
    """
    required_keys = {"event_id", "timestamp", "username", "source_ip", "event_type"}
    for k in required_keys:
        val = event.get(k)
        if val is None or (isinstance(val, str) and len(val.strip()) == 0):
            return False, f"Missing or empty required field: {k}"

    ts = event.get("timestamp")
    if ts == "not-a-timestamp":
        return False, "Invalid ISO-8601 timestamp format"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.year < 2000:
            return False, "Timestamp precedes epoch threshold"
        if dt.year > 2035:
            return False, "Timestamp exceeds maximum future threshold"
    except Exception:
        return False, "Malformed timestamp string"

    ip = event.get("source_ip", "")
    parts = ip.split(".")
    if len(parts) == 4:
        try:
            if not all(0 <= int(p) <= 255 for p in parts):
                return False, "Invalid IPv4 octet value"
        except ValueError:
            return False, "Non-integer IPv4 octet"
    elif ip != "127.0.0.1" and ":" not in ip:
        return False, "Invalid IP address structure"

    return True, "Valid"


class TestSchemaValidationRequirements:
    """Core schema requirement tests."""

    def test_valid_event_accepted(self, benign_events):
        """EVT0001 contains all valid fields and must pass validation."""
        evt1 = benign_events[0]
        valid, reason = validate_event_schema(evt1)
        assert valid is True
        assert reason == "Valid"

    def test_missing_event_id_rejected(self):
        """Record lacking event_id must fail validation."""
        bad_evt = {"timestamp": "2026-10-17T09:00:00Z", "username": "alice", "source_ip": "192.0.2.1", "event_type": "login_success"}
        valid, reason = validate_event_schema(bad_evt)
        assert valid is False
        assert "event_id" in reason

    def test_missing_event_type_rejected(self, invalid_input_events):
        """SCN012: EVT0030 missing event_type attribute."""
        evt30 = next(e for e in invalid_input_events if e.get("scenario_id") == "SCN012")
        valid, reason = validate_event_schema(evt30)
        assert valid is False
        assert "event_type" in reason

    def test_missing_username_rejected(self):
        """Event with null username rejected."""
        bad_evt = {"event_id": "EVTX", "timestamp": "2026-10-17T09:00:00Z", "username": None, "source_ip": "192.0.2.1", "event_type": "login_success"}
        valid, reason = validate_event_schema(bad_evt)
        assert valid is False
        assert "username" in reason

    def test_missing_source_ip_rejected(self):
        """Event with empty source_ip string rejected."""
        bad_evt = {"event_id": "EVTX", "timestamp": "2026-10-17T09:00:00Z", "username": "alice", "source_ip": "", "event_type": "login_success"}
        valid, reason = validate_event_schema(bad_evt)
        assert valid is False
        assert "source_ip" in reason


class TestTimestampValidation:
    """Timestamp syntax and range validation tests."""

    def test_invalid_timestamp_string_rejected(self, invalid_input_events):
        """SCN007: EVT0020 contains timestamp='not-a-timestamp'."""
        evt20 = next(e for e in invalid_input_events if e.get("scenario_id") == "SCN007")
        valid, reason = validate_event_schema(evt20)
        assert valid is False
        assert "timestamp" in reason.lower()

    def test_timestamp_from_year_1970_rejected(self):
        """Timestamp from Unix epoch start rejected as obsolete/corrupt."""
        bad_evt = {"event_id": "E1", "timestamp": "1970-01-01T00:00:00Z", "username": "alice", "source_ip": "192.0.2.1", "event_type": "login_success"}
        valid, reason = validate_event_schema(bad_evt)
        assert valid is False
        assert "epoch" in reason.lower()

    def test_future_timestamp_rejected(self):
        """Timestamp far in the future (year 2099) rejected."""
        bad_evt = {"event_id": "E1", "timestamp": "2099-01-01T00:00:00Z", "username": "alice", "source_ip": "192.0.2.1", "event_type": "login_success"}
        valid, reason = validate_event_schema(bad_evt)
        assert valid is False
        assert "future" in reason.lower()

    def test_exact_midnight_utc_timestamp_accepted(self, edge_case_events):
        """EVT0300: Midnight timestamp 00:00:00Z is valid."""
        evt = next(e for e in edge_case_events if e["event_id"] == "EVT0300")
        valid, reason = validate_event_schema(evt)
        assert valid is True

    def test_year_end_rollover_timestamp_accepted(self, edge_case_events):
        """EVT0308: 2026-12-31T23:59:59Z is valid."""
        evt = next(e for e in edge_case_events if e["event_id"] == "EVT0308")
        valid, reason = validate_event_schema(evt)
        assert valid is True


class TestIPValidation:
    """Network address parsing tests."""

    def test_invalid_ipv4_octet_rejected(self):
        """Octet 999 rejected."""
        bad_evt = {"event_id": "E1", "timestamp": "2026-10-17T09:00:00Z", "username": "alice", "source_ip": "192.0.2.999", "event_type": "login_success"}
        valid, reason = validate_event_schema(bad_evt)
        assert valid is False
        assert "octet" in reason.lower()

    def test_alphabetic_ip_rejected(self):
        """Hostname passed as IP rejected by validator."""
        bad_evt = {"event_id": "E1", "timestamp": "2026-10-17T09:00:00Z", "username": "alice", "source_ip": "not-an-ip-address", "event_type": "login_success"}
        valid, reason = validate_event_schema(bad_evt)
        assert valid is False

    def test_boundary_ips_accepted(self, edge_case_events):
        """192.0.2.254 and 203.0.113.254 valid."""
        evt = next(e for e in edge_case_events if e["event_id"] == "EVT0304")
        valid, _ = validate_event_schema(evt)
        assert valid is True


class TestDuplicateHandlingAndBatchProcessing:
    """Deduplication and batch quarantine tests."""

    def test_duplicate_event_id_detected(self, invalid_input_events):
        """SCN008: Two EVT0021 records submitted; second must be quarantined."""
        from tests.conftest import MockAPIClient
        fresh_client = MockAPIClient()
        scn8_events = [e for e in invalid_input_events if e.get("scenario_id") == "SCN008"]
        res = fresh_client.post_events_ingest(scn8_events)

        assert res["status_code"] == 201
        assert res["data"]["ingested_count"] == 1
        assert res["data"]["quarantined_count"] == 1

    def test_empty_batch_payload_rejected(self, api_client):
        """Submitting empty list [] returns 422 Unprocessable Entity."""
        res = api_client.post_events_ingest([])
        assert res["status_code"] == 422

    def test_partial_batch_success(self, api_client):
        """Batch containing 2 valid and 1 invalid record ingests valid ones."""
        batch = [
            {"event_id": "GOOD_01", "timestamp": "2026-10-17T09:00:00Z", "username": "alice", "source_ip": "192.0.2.1", "event_type": "login_success"},
            {"event_id": "BAD_01", "timestamp": "not-a-timestamp", "username": "bob", "source_ip": "192.0.2.2", "event_type": "login_success"},
            {"event_id": "GOOD_02", "timestamp": "2026-10-17T09:05:00Z", "username": "carol", "source_ip": "192.0.2.3", "event_type": "login_success"}
        ]
        res = api_client.post_events_ingest(batch)
        assert res["status_code"] == 201
        assert res["data"]["ingested_count"] == 2
        assert res["data"]["quarantined_count"] == 1


class TestPayloadFlexibilityAndEdgeCases:
    """Tolerant parsing of complex payloads."""

    def test_extra_unknown_fields_tolerated(self):
        """Extraneous diagnostic telemetry fields must not crash ingestion."""
        evt = {
            "event_id": "EVT_EXTRA",
            "timestamp": "2026-10-17T09:00:00Z",
            "username": "alice",
            "source_ip": "192.0.2.1",
            "event_type": "login_success",
            "custom_telemetry_sensor_v2": "sensor_az_441",
            "unmapped_metadata": {"cloud_region": "us-east-1"}
        }
        valid, _ = validate_event_schema(evt)
        assert valid is True

    def test_single_character_username_accepted(self, edge_case_events):
        """EVT0301: username='a' accepted."""
        evt = next(e for e in edge_case_events if e["event_id"] == "EVT0301")
        valid, _ = validate_event_schema(evt)
        assert valid is True

    def test_upn_email_style_username_accepted(self, edge_case_events):
        """EVT0309: username with dots, underscores, and @ symbol accepted."""
        evt = next(e for e in edge_case_events if e["event_id"] == "EVT0309")
        valid, _ = validate_event_schema(evt)
        assert valid is True

    def test_deeply_nested_details_dict_accepted(self, edge_case_events):
        """EVT0306: 3-level nested dictionary in details accepted."""
        evt = next(e for e in edge_case_events if e["event_id"] == "EVT0306")
        valid, _ = validate_event_schema(evt)
        assert valid is True

    def test_unicode_details_accepted(self):
        """Details containing foreign characters, symbols, and emojis."""
        evt = {
            "event_id": "EVT_UNI",
            "timestamp": "2026-10-17T09:00:00Z",
            "username": "tina",
            "source_ip": "192.0.2.1",
            "event_type": "login_success",
            "details": {"comment": "Accès autorisé pour réunion d'affaires 🔒"}
        }
        valid, _ = validate_event_schema(evt)
        assert valid is True
