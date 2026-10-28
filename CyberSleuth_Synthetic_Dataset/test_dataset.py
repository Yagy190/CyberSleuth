"""Starter tests for the synthetic dataset itself.

Run from this folder:
    python -m pip install pytest
    python -m pytest -v

These tests validate the fixtures. They do not test the CyberSleuth application yet.
"""
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent

def load_json(name):
    return json.loads((DATA_DIR / name).read_text(encoding="utf-8"))

def test_scenario_definitions_have_required_fields():
    scenarios = load_json("scenario_definitions.json")
    required = {"scenario_id", "name", "description", "expected_outcome", "ground_truth", "expected_event_ids"}
    assert scenarios
    for scenario in scenarios:
        assert required.issubset(scenario.keys())
        assert scenario["expected_event_ids"]

def test_dataset_contains_benign_and_suspicious_events():
    events = load_json("all_events.json")
    labels = {event["ground_truth"] for event in events}
    assert "benign" in labels
    assert "suspicious" in labels

def test_prompt_injection_fixture_is_present():
    events = load_json("adversarial_input_events.json")
    assert any("Ignore all rules" in event.get("details", {}).get("message", "") for event in events)

def test_invalid_fixtures_are_intentionally_invalid():
    events = load_json("invalid_input_events.json")
    assert any(not isinstance(event.get("timestamp"), str) or event.get("timestamp") == "not-a-timestamp" for event in events)
    assert any("event_type" not in event for event in events)

def test_duplicate_event_id_fixture_is_present():
    events = load_json("all_events.json")
    ids = [event.get("event_id") for event in events]
    assert len(ids) > len(set(ids))
