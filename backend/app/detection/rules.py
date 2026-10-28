"""
CyberSleuth AI – Deterministic Detection Rules
Member 2: Backend & Data Engineering

Rules:
  1. BruteForce       – ≥5 login failures from same source in 15 min
  2. BruteForceSuccess– ≥5 failures followed by a success (same user)
  3. PrivilegeChange  – privilege_change event after recent login
  4. LateralMovement  – same user, different hosts within 10 min
  5. UnusualOutbound  – network_outbound from host with recent alerts

Each rule creates an Alert row in the database.
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import List
from sqlalchemy.orm import Session

from app.models.event import Event, EventType
from app.models.alert import Alert, AlertSeverity, AlertStatus


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_alert(
    rule_name: str,
    severity: AlertSeverity,
    description: str,
    evidence: List[str],
    username: str | None,
    host: str | None,
    source_ip: str | None,
) -> Alert:
    return Alert(
        alert_id=str(uuid.uuid4()),
        rule_name=rule_name,
        severity=severity,
        status=AlertStatus.OPEN,
        username=username,
        host=host,
        source_ip=source_ip,
        description=description,
        evidence_events=evidence,
    )


# ── Rule 1 & 2: Brute Force ────────────────────────────────────────────────────

def _rule_brute_force(events: List[Event], db: Session) -> List[Alert]:
    alerts: List[Alert] = []
    WINDOW = timedelta(minutes=15)
    THRESHOLD = 5

    # group failures by (username, source_ip)
    from collections import defaultdict
    failures: dict = defaultdict(list)
    successes: dict = defaultdict(list)

    for e in events:
        key = (e.username, e.source_ip)
        if e.event_type == EventType.LOGIN_FAILURE:
            failures[key].append(e)
        elif e.event_type == EventType.LOGIN_SUCCESS:
            successes[key].append(e)

    for key, fail_list in failures.items():
        fail_list.sort(key=lambda x: x.timestamp)
        # sliding window
        for i, start_event in enumerate(fail_list):
            window_fails = [
                f for f in fail_list[i:]
                if f.timestamp - start_event.timestamp <= WINDOW
            ]
            if len(window_fails) >= THRESHOLD:
                username, source_ip = key
                evidence = [f.event_id for f in window_fails]

                # Check if followed by success → BruteForceSuccess
                last_fail_ts = window_fails[-1].timestamp
                success_after = [
                    s for s in successes.get(key, [])
                    if s.timestamp > last_fail_ts and s.username == username
                ]
                if success_after:
                    alerts.append(_make_alert(
                        rule_name="BruteForceSuccess",
                        severity=AlertSeverity.CRITICAL,
                        description=(
                            f"User '{username}' had {len(window_fails)} failed logins from "
                            f"{source_ip} then succeeded — possible credential compromise."
                        ),
                        evidence=evidence + [s.event_id for s in success_after],
                        username=username,
                        host=window_fails[0].host,
                        source_ip=source_ip,
                    ))
                else:
                    alerts.append(_make_alert(
                        rule_name="BruteForce",
                        severity=AlertSeverity.HIGH,
                        description=(
                            f"User '{username}' had {len(window_fails)} failed logins "
                            f"from {source_ip} within 15 minutes."
                        ),
                        evidence=evidence,
                        username=username,
                        host=window_fails[0].host,
                        source_ip=source_ip,
                    ))
                break   # one alert per (user, ip) burst

    return alerts


# ── Rule 3: Privilege Change After Login ──────────────────────────────────────

def _rule_privilege_change(events: List[Event], db: Session) -> List[Alert]:
    alerts: List[Alert] = []
    WINDOW = timedelta(minutes=30)

    priv_events = [e for e in events if e.event_type == EventType.PRIVILEGE_CHANGE]
    login_events = [e for e in events if e.event_type == EventType.LOGIN_SUCCESS]

    for priv in priv_events:
        recent_login = next(
            (l for l in login_events
             if l.username == priv.username
             and 0 <= (priv.timestamp - l.timestamp).total_seconds() <= WINDOW.total_seconds()),
            None,
        )
        if recent_login:
            alerts.append(_make_alert(
                rule_name="PrivilegeChangeAfterLogin",
                severity=AlertSeverity.HIGH,
                description=(
                    f"User '{priv.username}' had a privilege change on '{priv.host}' "
                    f"within 30 min of login — possible privilege escalation."
                ),
                evidence=[recent_login.event_id, priv.event_id],
                username=priv.username,
                host=priv.host,
                source_ip=priv.source_ip,
            ))

    return alerts


# ── Rule 4: Lateral Movement ──────────────────────────────────────────────────

def _rule_lateral_movement(events: List[Event], db: Session) -> List[Alert]:
    alerts: List[Alert] = []
    WINDOW = timedelta(minutes=10)
    from collections import defaultdict

    by_user: dict = defaultdict(list)
    for e in events:
        if e.event_type == EventType.LOGIN_SUCCESS and e.username:
            by_user[e.username].append(e)

    for username, logins in by_user.items():
        logins.sort(key=lambda x: x.timestamp)
        for i in range(len(logins) - 1):
            a, b = logins[i], logins[i + 1]
            if (b.timestamp - a.timestamp) <= WINDOW and a.host != b.host:
                alerts.append(_make_alert(
                    rule_name="LateralMovement",
                    severity=AlertSeverity.HIGH,
                    description=(
                        f"User '{username}' logged into '{a.host}' then '{b.host}' "
                        f"within 10 minutes — possible lateral movement."
                    ),
                    evidence=[a.event_id, b.event_id],
                    username=username,
                    host=b.host,
                    source_ip=b.source_ip,
                ))

    return alerts


# ── Rule 5: Unusual Outbound ──────────────────────────────────────────────────

def _rule_unusual_outbound(events: List[Event], db: Session) -> List[Alert]:
    alerts: List[Alert] = []
    outbound = [e for e in events if e.event_type == EventType.NETWORK_OUTBOUND]

    for e in outbound:
        # Flag if dest_port is unusual (not 80/443/53) and there's no prior record
        if e.dest_port and e.dest_port not in (80, 443, 53, 22, 25, 587):
            alerts.append(_make_alert(
                rule_name="UnusualOutboundConnection",
                severity=AlertSeverity.MEDIUM,
                description=(
                    f"Host '{e.host}' made an outbound connection to {e.dest_ip}:{e.dest_port} — "
                    f"uncommon destination port may indicate C2 activity."
                ),
                evidence=[e.event_id],
                username=e.username,
                host=e.host,
                source_ip=e.source_ip,
            ))

    return alerts


# ── Main entry point ──────────────────────────────────────────────────────────

def run_detection_on_events(events: List[Event], db: Session) -> List[Alert]:
    """Run all detection rules on a batch of events and persist alerts."""
    all_alerts: List[Alert] = []

    for rule_fn in [
        _rule_brute_force,
        _rule_privilege_change,
        _rule_lateral_movement,
        _rule_unusual_outbound,
    ]:
        try:
            new_alerts = rule_fn(events, db)
            all_alerts.extend(new_alerts)
        except Exception as exc:
            # Don't let one rule failure crash ingestion
            print(f"[Detection] Rule {rule_fn.__name__} failed: {exc}")

    for alert in all_alerts:
        db.add(alert)

    if all_alerts:
        db.commit()

    return all_alerts
