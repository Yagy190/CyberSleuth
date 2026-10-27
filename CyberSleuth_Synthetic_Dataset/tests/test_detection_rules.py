"""
Test suite for CyberSleuth AI Detection Engine rules.

Validates:
- Brute force detection thresholds and windows (SCN002)
- Failed logins followed by success correlation (SCN003)
- Unauthorized privilege change alerting (SCN005)
- Suspicious outbound connection detection (SCN006)
- Coordinated multi-stage attack sequence correlation (SCN011)
- Lateral movement across hosts (SCN019)
- DNS tunneling indicators (SCN024)
- Zero false alerts on benign operational scenarios (SCN001, SCN004, SCN009, SCN013, SCN027)
- Edge-case handling (empty inputs, single events, thresholds)
"""
import pytest
from typing import List, Dict, Any


class TestBruteForceDetection:
    """Tests for repeated failed login detection."""

    def test_detects_standard_brute_force_scenario(self, detection_engine, suspicious_events):
        """SCN002: 8 failed logins for alice should trigger alert."""
        scn2_events = [e for e in suspicious_events if e.get("scenario_id") == "SCN002"]
        alerts = detection_engine.detect_brute_force(scn2_events, threshold=5)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["rule_name"] == "repeated_failed_logins"
        assert alert["target_user"] == "alice"
        assert len(alert["event_ids"]) == 8
        assert alert["mitre_technique"] == "T1110"

    def test_brute_force_below_threshold_does_not_fire(self, detection_engine):
        """4 failed logins should NOT trigger when threshold is 5."""
        events = [
            {"event_id": f"E{i}", "event_type": "login_failed", "username": "dave"}
            for i in range(4)
        ]
        alerts = detection_engine.detect_brute_force(events, threshold=5)
        assert len(alerts) == 0

    def test_brute_force_exact_threshold_boundary(self, detection_engine):
        """Exactly 5 failed logins should trigger when threshold is 5."""
        events = [
            {"event_id": f"E{i}", "event_type": "login_failed", "username": "eve"}
            for i in range(5)
        ]
        alerts = detection_engine.detect_brute_force(events, threshold=5)
        assert len(alerts) == 1
        assert len(alerts[0]["event_ids"]) == 5

    def test_brute_force_multiple_distinct_users(self, detection_engine):
        """Failed attempts across separate users tracked independently."""
        events = (
            [{"event_id": f"A{i}", "event_type": "login_failed", "username": "user_a"} for i in range(6)] +
            [{"event_id": f"B{i}", "event_type": "login_failed", "username": "user_b"} for i in range(2)]
        )
        alerts = detection_engine.detect_brute_force(events, threshold=5)
        assert len(alerts) == 1
        assert alerts[0]["target_user"] == "user_a"

    def test_benign_successful_logins_do_not_trigger_brute_force(self, detection_engine, benign_events):
        """Benign logins should produce zero brute force alerts."""
        alerts = detection_engine.detect_brute_force(benign_events)
        assert len(alerts) == 0


class TestFailedThenSuccessDetection:
    """Tests for credential guessing followed by successful intrusion."""

    def test_detects_failed_then_success_sequence(self, detection_engine, suspicious_events):
        """SCN003: Bob has multiple failures followed by login_success."""
        scn3_events = [e for e in suspicious_events if e.get("scenario_id") == "SCN003"]
        alerts = detection_engine.detect_failed_then_success(scn3_events)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["rule_name"] == "failed_logins_followed_by_success"
        assert alert["target_user"] == "bob"
        assert "EVT0015" in alert["event_ids"]  # the successful login
        assert alert["severity"] == "high"

    def test_success_from_different_ip_not_flagged_under_same_ip_rule(self, detection_engine):
        """Failed logins from IP A followed by success from IP B should not falsely correlate."""
        events = [
            {"event_id": "E1", "event_type": "login_failed", "username": "carol", "source_ip": "192.0.2.10"},
            {"event_id": "E2", "event_type": "login_failed", "username": "carol", "source_ip": "192.0.2.10"},
            {"event_id": "E3", "event_type": "login_success", "username": "carol", "source_ip": "198.51.100.99"}
        ]
        alerts = detection_engine.detect_failed_then_success(events)
        assert len(alerts) == 0

    def test_only_successful_logins_do_not_trigger(self, detection_engine):
        """Series of normal successful logins should not trigger."""
        events = [
            {"event_id": f"S{i}", "event_type": "login_success", "username": "dan", "source_ip": "192.0.2.1"}
            for i in range(5)
        ]
        alerts = detection_engine.detect_failed_then_success(events)
        assert len(alerts) == 0


class TestPrivilegeChangeDetection:
    """Tests for unauthorized privilege escalation."""

    def test_detects_unapproved_privilege_change(self, detection_engine, suspicious_events):
        """SCN005: EVT0017 privilege change without ticket and approved=false."""
        scn5_events = [e for e in suspicious_events if e.get("scenario_id") == "SCN005"]
        alerts = detection_engine.detect_unauthorized_privilege_change(scn5_events)

        assert len(alerts) == 1
        assert alerts[0]["rule_name"] == "unauthorized_privilege_change"
        assert "EVT0017" in alerts[0]["event_ids"]
        assert alerts[0]["mitre_technique"] == "T1548"

    def test_approved_privilege_change_is_not_alerted(self, detection_engine, benign_events):
        """SCN004: EVT0016 administrator privilege change with CHG-1042 approved=true."""
        scn4_events = [e for e in benign_events if e.get("scenario_id") == "SCN004"]
        alerts = detection_engine.detect_unauthorized_privilege_change(scn4_events)
        assert len(alerts) == 0

    def test_privilege_change_with_missing_details(self, detection_engine):
        """Privilege change event with empty or null details should trigger caution."""
        events = [
            {"event_id": "E_PRIV", "event_type": "privilege_change", "username": "root", "details": None}
        ]
        alerts = detection_engine.detect_unauthorized_privilege_change(events)
        assert len(alerts) == 1


class TestSuspiciousOutboundDetection:
    """Tests for network beaconing and data egress detection."""

    def test_detects_high_connection_count(self, detection_engine, suspicious_events):
        """SCN006: EVT0019 outbound connection count 12 (threshold 10)."""
        scn6_events = [e for e in suspicious_events if e.get("scenario_id") == "SCN006"]
        alerts = detection_engine.detect_suspicious_outbound(scn6_events, connection_threshold=10)

        assert len(alerts) == 1
        assert alerts[0]["rule_name"] == "suspicious_outbound_activity"
        assert "EVT0019" in alerts[0]["event_ids"]

    def test_detects_large_data_egress(self, detection_engine, expanded_suspicious_events):
        """SCN020: Wendy transfers 128MB outbound."""
        scn20_events = [e for e in expanded_suspicious_events if e.get("scenario_id") == "SCN020"]
        alerts = detection_engine.detect_suspicious_outbound(scn20_events)
        assert len(alerts) >= 1
        assert any(a["severity"] == "high" for a in alerts)

    def test_normal_low_volume_outbound_does_not_alert(self, detection_engine):
        """Standard 1-2 connection outbound HTTP requests should not alert."""
        events = [
            {"event_id": "O1", "event_type": "outbound_connection", "details": {"connection_count": 2, "bytes_sent": 1024}}
        ]
        alerts = detection_engine.detect_suspicious_outbound(events)
        assert len(alerts) == 0


class TestCorrelatedSequenceDetection:
    """Tests for full attack chain correlation."""

    def test_detects_coordinated_intrusion_sequence(self, detection_engine, suspicious_events):
        """SCN011: Gina experiences brute force -> success -> privilege change -> outbound egress."""
        scn11_events = [e for e in suspicious_events if e.get("scenario_id") == "SCN011"]
        alerts = detection_engine.detect_correlated_sequence(scn11_events)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["rule_name"] == "correlated_attack_chain"
        assert alert["severity"] == "critical"
        assert alert["target_user"] == "gina"
        # Links all 6 events: EVT0024 to EVT0029
        assert len(alert["event_ids"]) == 6

    def test_partial_sequence_does_not_trigger_full_correlation(self, detection_engine):
        """Only failed login + success without privilege change should not trigger full chain."""
        events = [
            {"event_id": "E1", "event_type": "login_failed", "username": "fred"},
            {"event_id": "E2", "event_type": "login_success", "username": "fred"}
        ]
        alerts = detection_engine.detect_correlated_sequence(events)
        assert len(alerts) == 0


class TestAdvancedAttackDetection:
    """Tests for expanded threat scenarios (Lateral Movement, DNS Tunneling)."""

    def test_detects_lateral_movement_across_workstations(self, detection_engine, expanded_suspicious_events):
        """SCN019: Victor accesses 4 internal workstations sequentially."""
        scn19_events = [e for e in expanded_suspicious_events if e.get("scenario_id") == "SCN019"]
        alerts = detection_engine.detect_lateral_movement(scn19_events)

        assert len(alerts) == 1
        assert alerts[0]["rule_name"] == "lateral_movement_multihost"
        assert alerts[0]["target_user"] == "victor"
        assert alerts[0]["mitre_technique"] == "T1021"

    def test_detects_dns_tunneling_indicators(self, detection_engine, expanded_suspicious_events):
        """SCN024: Bursts of high entropy TXT DNS queries on workstation-06."""
        scn24_events = [e for e in expanded_suspicious_events if e.get("scenario_id") == "SCN024"]
        alerts = detection_engine.detect_dns_tunneling(scn24_events)

        assert len(alerts) == 1
        assert alerts[0]["rule_name"] == "dns_covert_tunneling"
        assert alerts[0]["mitre_technique"] == "T1071.004"


class TestControlGroupZeroFalsePositives:
    """Validates baseline control groups generate 0 false alarms."""

    def test_large_scale_baseline_zero_false_positives(self, detection_engine, large_scale_benign_baseline):
        """100 baseline enterprise operations records must produce 0 false alerts."""
        alerts = detection_engine.run_all_rules(large_scale_benign_baseline)
        assert len(alerts) == 0

    def test_expanded_benign_workday_zero_false_positives(self, detection_engine, expanded_benign_events):
        """84 routine workday operations events must produce 0 false alerts."""
        alerts = detection_engine.run_all_rules(expanded_benign_events)
        assert len(alerts) == 0


class TestEdgeCaseRobustness:
    """Validates engine behavior on empty, single, and boundary inputs."""

    def test_empty_event_list_returns_empty_alerts(self, detection_engine):
        alerts = detection_engine.run_all_rules([])
        assert alerts == []

    def test_single_benign_event_returns_empty_alerts(self, detection_engine):
        ev = [{"event_id": "EVT1", "event_type": "login_success", "username": "alice"}]
        alerts = detection_engine.run_all_rules(ev)
        assert alerts == []

    def test_events_with_missing_optional_attributes(self, detection_engine):
        """Events missing host, details, or source_ip should not cause unhandled exceptions."""
        events = [
            {"event_id": "EVT_MIN", "event_type": "login_failed", "username": "bob"}
        ]
        alerts = detection_engine.run_all_rules(events)
        assert isinstance(alerts, list)
