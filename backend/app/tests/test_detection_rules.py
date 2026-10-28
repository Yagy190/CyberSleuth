"""
CyberSleuth AI – Detection Rules Unit Tests
Member 2: Backend, Detection & Data Engineering
"""
from datetime import datetime, timezone, timedelta
from app.models.event import Event, EventType
from app.detection.rules import run_detection_on_events


def test_brute_force_rule(db_session):
    now = datetime.now(timezone.utc)
    events = []

    # 6 failed logins within 5 minutes
    for i in range(6):
        events.append(
            Event(
                event_id=f"BF_FAIL_{i}",
                timestamp=now + timedelta(seconds=i * 20),
                event_type=EventType.LOGIN_FAILURE,
                username="alice",
                host="srv-app",
                source_ip="10.0.0.50",
            )
        )

    alerts = run_detection_on_events(events, db_session)
    assert len(alerts) >= 1
    alert_names = [a.rule_name for a in alerts]
    assert "BruteForce" in alert_names or "BruteForceSuccess" in alert_names


def test_privilege_escalation_rule(db_session):
    now = datetime.now(timezone.utc)
    events = [
        Event(
            event_id="LOGIN_SUCC_01",
            timestamp=now,
            event_type=EventType.LOGIN_SUCCESS,
            username="bob",
            host="srv-app",
            source_ip="10.0.0.22",
        ),
        Event(
            event_id="PRIV_CHANGE_01",
            timestamp=now + timedelta(minutes=5),
            event_type=EventType.PRIVILEGE_CHANGE,
            username="bob",
            host="srv-app",
            source_ip="10.0.0.22",
        ),
    ]

    alerts = run_detection_on_events(events, db_session)
    assert any(a.rule_name == "PrivilegeChangeAfterLogin" for a in alerts)


def test_lateral_movement_rule(db_session):
    now = datetime.now(timezone.utc)
    events = [
        Event(
            event_id="LAT_01",
            timestamp=now,
            event_type=EventType.LOGIN_SUCCESS,
            username="charlie",
            host="host-alpha",
            source_ip="10.0.0.5",
        ),
        Event(
            event_id="LAT_02",
            timestamp=now + timedelta(minutes=3),
            event_type=EventType.LOGIN_SUCCESS,
            username="charlie",
            host="host-beta",
            source_ip="10.0.0.5",
        ),
    ]

    alerts = run_detection_on_events(events, db_session)
    assert any(a.rule_name == "LateralMovement" for a in alerts)
