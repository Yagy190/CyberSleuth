"""
Shared pytest fixtures and mock test interfaces for CyberSleuth AI.

These fixtures provide:
- Comprehensive synthetic dataset loaders
- MockDetectionEngine (simulating Member 2's rule-based detection engine)
- MockAPIClient (simulating Member 2's FastAPI endpoints)
- MockRAGPipeline (simulating Member 1's retrieval & LangGraph report generation)
"""
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import pytest

DATA_DIR = Path(__file__).resolve().parent.parent


def load_json_file(filename: str) -> Any:
    """Load JSON from root or datasets/ directory."""
    path = DATA_DIR / filename
    if not path.exists():
        path = DATA_DIR / "datasets" / filename
    if not path.exists():
        raise FileNotFoundError(f"Could not locate dataset file: {filename}")
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Dataset Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def all_events() -> List[Dict[str, Any]]:
    return load_json_file("all_events.json")


@pytest.fixture(scope="session")
def benign_events() -> List[Dict[str, Any]]:
    return load_json_file("benign_events.json")


@pytest.fixture(scope="session")
def suspicious_events() -> List[Dict[str, Any]]:
    return load_json_file("suspicious_events.json")


@pytest.fixture(scope="session")
def invalid_input_events() -> List[Dict[str, Any]]:
    return load_json_file("invalid_input_events.json")


@pytest.fixture(scope="session")
def adversarial_events() -> List[Dict[str, Any]]:
    return load_json_file("adversarial_input_events.json")


@pytest.fixture(scope="session")
def expanded_benign_events() -> List[Dict[str, Any]]:
    return load_json_file("expanded_benign_events.json")


@pytest.fixture(scope="session")
def expanded_suspicious_events() -> List[Dict[str, Any]]:
    return load_json_file("expanded_suspicious_events.json")


@pytest.fixture(scope="session")
def large_scale_benign_baseline() -> List[Dict[str, Any]]:
    return load_json_file("large_scale_benign_baseline.json")


@pytest.fixture(scope="session")
def edge_case_events() -> List[Dict[str, Any]]:
    return load_json_file("edge_case_events.json")


@pytest.fixture(scope="session")
def adversarial_expanded_events() -> List[Dict[str, Any]]:
    return load_json_file("adversarial_expanded.json")


@pytest.fixture(scope="session")
def scenario_definitions() -> List[Dict[str, Any]]:
    return load_json_file("scenario_definitions.json")


@pytest.fixture(scope="session")
def mitre_mappings() -> List[Dict[str, Any]]:
    return load_json_file("mitre_mapped_scenarios.json")


# ---------------------------------------------------------------------------
# Mock Detection Engine (Simulates Member 2's Detection Service)
# ---------------------------------------------------------------------------

class MockDetectionEngine:
    """Simulates Member 2's rule-based threat detection logic."""

    def __init__(self):
        self.alert_counter = 1

    def _next_alert_id(self) -> str:
        aid = f"ALT{self.alert_counter:04d}"
        self.alert_counter += 1
        return aid

    @staticmethod
    def _parse_time(ts_str: str) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return None

    def detect_brute_force(self, events: List[Dict[str, Any]], threshold: int = 5) -> List[Dict[str, Any]]:
        """Detect >= threshold failed logins for a single username."""
        alerts = []
        user_fails: Dict[str, List[Dict[str, Any]]] = {}

        for ev in events:
            if ev.get("event_type") == "login_failed":
                u = ev.get("username")
                if u:
                    user_fails.setdefault(u, []).append(ev)

        for u, fails in user_fails.items():
            if len(fails) >= threshold:
                alerts.append({
                    "alert_id": self._next_alert_id(),
                    "rule_name": "repeated_failed_logins",
                    "severity": "medium" if len(fails) < 10 else "high",
                    "target_user": u,
                    "event_ids": [f["event_id"] for f in fails],
                    "description": f"Detected {len(fails)} repeated failed logins for user {u}.",
                    "confidence": 0.85,
                    "mitre_technique": "T1110"
                })
        return alerts

    def detect_failed_then_success(self, events: List[Dict[str, Any]], window_seconds: int = 300) -> List[Dict[str, Any]]:
        """Detect failed logins followed by successful login for same user and source IP."""
        alerts = []
        by_user: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            u = ev.get("username")
            if u:
                by_user.setdefault(u, []).append(ev)

        for u, user_evs in by_user.items():
            failed_evs = [e for e in user_evs if e.get("event_type") == "login_failed"]
            success_evs = [e for e in user_evs if e.get("event_type") == "login_success"]

            if failed_evs and success_evs:
                for succ in success_evs:
                    matching_fails = [
                        f for f in failed_evs
                        if f.get("source_ip") == succ.get("source_ip")
                    ]
                    if len(matching_fails) >= 2:
                        all_ids = [f["event_id"] for f in matching_fails] + [succ["event_id"]]
                        alerts.append({
                            "alert_id": self._next_alert_id(),
                            "rule_name": "failed_logins_followed_by_success",
                            "severity": "high",
                            "target_user": u,
                            "event_ids": all_ids,
                            "description": f"Failed login attempts followed by successful login for user {u} from {succ.get('source_ip')}.",
                            "confidence": 0.90,
                            "mitre_technique": "T1110.001"
                        })
                        break
        return alerts

    def detect_unauthorized_privilege_change(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect privilege change events with approved=False or null change_ticket."""
        alerts = []
        for ev in events:
            if ev.get("event_type") == "privilege_change":
                details = ev.get("details", {}) or {}
                approved = details.get("approved")
                ticket = details.get("change_ticket")

                if approved is False or ticket is None:
                    alerts.append({
                        "alert_id": self._next_alert_id(),
                        "rule_name": "unauthorized_privilege_change",
                        "severity": "high",
                        "event_ids": [ev["event_id"]],
                        "description": f"Unapproved privilege modification detected on host {ev.get('host')} for user {ev.get('username')}.",
                        "confidence": 0.88,
                        "mitre_technique": "T1548"
                    })
        return alerts

    def detect_suspicious_outbound(self, events: List[Dict[str, Any]], connection_threshold: int = 10) -> List[Dict[str, Any]]:
        """Detect high volume or unusual outbound connection activity."""
        alerts = []
        for ev in events:
            if ev.get("event_type") == "outbound_connection":
                details = ev.get("details", {}) or {}
                count = details.get("connection_count", 1)
                bytes_sent = details.get("bytes_sent", 0)

                if count >= connection_threshold or bytes_sent > 10_000_000:
                    alerts.append({
                        "alert_id": self._next_alert_id(),
                        "rule_name": "suspicious_outbound_activity",
                        "severity": "high" if bytes_sent > 50_000_000 else "medium",
                        "event_ids": [ev["event_id"]],
                        "description": f"Suspicious outbound network egress from host {ev.get('host')} to external IP {details.get('destination_ip')}.",
                        "confidence": 0.82,
                        "mitre_technique": "T1041"
                    })
        return alerts

    def detect_correlated_sequence(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect coordinated sequence: failed login + success + priv change + outbound connection."""
        alerts = []
        # Group by username
        by_user: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            u = ev.get("username")
            if u:
                by_user.setdefault(u, []).append(ev)

        for u, u_events in by_user.items():
            has_fail = any(e.get("event_type") == "login_failed" for e in u_events)
            has_succ = any(e.get("event_type") == "login_success" for e in u_events)
            has_priv = any(e.get("event_type") == "privilege_change" and not (e.get("details") or {}).get("approved", True) for e in u_events)
            has_out = any(e.get("event_type") == "outbound_connection" for e in u_events)

            if has_fail and has_succ and has_priv and has_out:
                involved_ids = [e["event_id"] for e in u_events]
                alerts.append({
                    "alert_id": self._next_alert_id(),
                    "rule_name": "correlated_attack_chain",
                    "severity": "critical",
                    "target_user": u,
                    "event_ids": involved_ids,
                    "description": f"Multi-stage coordinated intrusion sequence detected targeting user {u}.",
                    "confidence": 0.95,
                    "mitre_technique": "T1110/T1548/T1071"
                })
        return alerts

    def detect_lateral_movement(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect lateral movement across internal hosts."""
        alerts = []
        user_hosts: Dict[str, set] = {}
        user_evs: Dict[str, List[str]] = {}

        for ev in events:
            if ev.get("event_type") == "remote_login":
                u = ev.get("username", "")
                h = ev.get("host", "")
                user_hosts.setdefault(u, set()).add(h)
                user_evs.setdefault(u, []).append(ev["event_id"])

        for u, hosts in user_hosts.items():
            if len(hosts) >= 3:
                alerts.append({
                    "alert_id": self._next_alert_id(),
                    "rule_name": "lateral_movement_multihost",
                    "severity": "high",
                    "target_user": u,
                    "event_ids": user_evs[u],
                    "description": f"User {u} initiated remote logins across {len(hosts)} internal hosts.",
                    "confidence": 0.89,
                    "mitre_technique": "T1021"
                })
        return alerts

    def detect_dns_tunneling(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect high entropy DNS queries indicative of tunneling."""
        alerts = []
        dns_events = [e for e in events if e.get("event_type") == "dns_query"]
        high_entropy_dns = [
            e for e in dns_events
            if (e.get("details") or {}).get("entropy", 0) > 4.0
        ]
        if len(high_entropy_dns) >= 3:
            alerts.append({
                "alert_id": self._next_alert_id(),
                "rule_name": "dns_covert_tunneling",
                "severity": "high",
                "event_ids": [e["event_id"] for e in high_entropy_dns],
                "description": f"Detected {len(high_entropy_dns)} high-entropy DNS queries indicating covert exfiltration channel.",
                "confidence": 0.92,
                "mitre_technique": "T1071.004"
            })
        return alerts

    def detect_credential_stuffing(self, events: List[Dict[str, Any]], min_users: int = 3) -> List[Dict[str, Any]]:
        """Detect single external IP targeting multiple distinct usernames with failed logins."""
        alerts = []
        ip_targets: Dict[str, Dict[str, List[str]]] = {}
        for ev in events:
            if ev.get("event_type") == "login_failed":
                ip = ev.get("source_ip", "")
                u = ev.get("username", "")
                if ip and u:
                    ip_targets.setdefault(ip, {}).setdefault(u, []).append(ev["event_id"])

        for ip, users in ip_targets.items():
            if len(users) >= min_users:
                all_ids = [eid for u_eids in users.values() for eid in u_eids]
                alerts.append({
                    "alert_id": self._next_alert_id(),
                    "rule_name": "credential_stuffing_campaign",
                    "severity": "high",
                    "source_ip": ip,
                    "target_users": list(users.keys()),
                    "event_ids": all_ids,
                    "description": f"Detected distributed credential stuffing from {ip} targeting {len(users)} accounts.",
                    "confidence": 0.91,
                    "mitre_technique": "T1110.004"
                })
        return alerts

    def detect_insider_threat(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect insider threat: removable media mount followed by log deletion."""
        alerts = []
        by_user: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            u = ev.get("username")
            if u:
                by_user.setdefault(u, []).append(ev)

        for u, u_events in by_user.items():
            has_usb = any(e.get("event_type") == "usb_mount" for e in u_events)
            has_del = any(e.get("event_type") == "log_deletion" for e in u_events)
            if has_usb or has_del:
                involved_ids = [e["event_id"] for e in u_events]
                alerts.append({
                    "alert_id": self._next_alert_id(),
                    "rule_name": "insider_threat_activity",
                    "severity": "critical",
                    "target_user": u,
                    "event_ids": involved_ids,
                    "description": f"Potential insider threat: policy violation and defense evasion by user {u}.",
                    "confidence": 0.94,
                    "mitre_technique": "T1530/T1070"
                })
        return alerts

    def detect_impossible_travel(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect geographically impossible travel velocity between consecutive logins."""
        alerts = []
        for ev in events:
            details = ev.get("details", {}) or {}
            if details.get("distance_km", 0) > 1000 and details.get("delta_minutes", 999) < 60:
                alerts.append({
                    "alert_id": self._next_alert_id(),
                    "rule_name": "impossible_travel_velocity",
                    "severity": "critical",
                    "target_user": ev.get("username"),
                    "event_ids": [ev["event_id"]],
                    "description": f"Impossible travel detected for user {ev.get('username')}: {details.get('distance_km')}km within {details.get('delta_minutes')}m.",
                    "confidence": 0.96,
                    "mitre_technique": "T1078"
                })
        return alerts

    def run_all_rules(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run complete battery of detection rules."""
        alerts = []
        alerts.extend(self.detect_brute_force(events))
        alerts.extend(self.detect_failed_then_success(events))
        alerts.extend(self.detect_unauthorized_privilege_change(events))
        alerts.extend(self.detect_suspicious_outbound(events))
        alerts.extend(self.detect_correlated_sequence(events))
        alerts.extend(self.detect_lateral_movement(events))
        alerts.extend(self.detect_dns_tunneling(events))
        alerts.extend(self.detect_credential_stuffing(events))
        alerts.extend(self.detect_insider_threat(events))
        alerts.extend(self.detect_impossible_travel(events))
        return alerts


# ---------------------------------------------------------------------------
# Mock API Client (Simulates Member 2's FastAPI Routes)
# ---------------------------------------------------------------------------

class MockAPIClient:
    """Simulates HTTP interactions with Member 2's FastAPI backend."""

    def __init__(self, events: Optional[List[Dict[str, Any]]] = None):
        self.events_db: Dict[str, Dict[str, Any]] = {}
        self.alerts_db: Dict[str, Dict[str, Any]] = {}
        self.incidents_db: Dict[str, Dict[str, Any]] = {}
        self.tokens: set = {"valid_jwt_token_analyst_123"}
        self.rate_limit_counter: int = 0

        if events:
            for ev in events:
                if "event_id" in ev:
                    self.events_db[ev["event_id"]] = ev

    def post_auth_login(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if payload.get("username") == "sec_analyst" and payload.get("password") == "CyberSleuth2026!":
            return {"status_code": 200, "data": {"access_token": "valid_jwt_token_analyst_123", "token_type": "bearer"}}
        return {"status_code": 401, "errors": [{"message": "Invalid credentials"}]}

    def post_events_ingest(self, events_payload: List[Dict[str, Any]], token: Optional[str] = "valid_jwt_token_analyst_123") -> Dict[str, Any]:
        if token not in self.tokens:
            return {"status_code": 401, "errors": [{"message": "Unauthorized"}]}

        if not isinstance(events_payload, list) or len(events_payload) == 0:
            return {"status_code": 422, "errors": [{"message": "Payload must be a non-empty list of events"}]}

        ingested = 0
        quarantined = 0
        seen_ids = set(self.events_db.keys())

        for ev in events_payload:
            # Schema validation
            eid = ev.get("event_id")
            etype = ev.get("event_type")
            ts = ev.get("timestamp")

            if not eid or not etype or not ts:
                quarantined += 1
                continue
            if ts == "not-a-timestamp":
                quarantined += 1
                continue
            if eid in seen_ids:
                quarantined += 1  # Deduplicated / flagged
                continue

            self.events_db[eid] = ev
            seen_ids.add(eid)
            ingested += 1

        return {
            "status_code": 201,
            "data": {
                "ingested_count": ingested,
                "quarantined_count": quarantined,
                "total_received": len(events_payload)
            }
        }

    def get_events(self, username: Optional[str] = None, host: Optional[str] = None,
                   event_type: Optional[str] = None, page: int = 1, page_size: int = 10,
                   token: Optional[str] = "valid_jwt_token_analyst_123") -> Dict[str, Any]:
        if token not in self.tokens:
            return {"status_code": 401, "errors": [{"message": "Unauthorized"}]}
        if page < 1 or page_size < 1:
            return {"status_code": 422, "errors": [{"message": "Invalid pagination parameters"}]}

        filtered = list(self.events_db.values())
        if username:
            filtered = [e for e in filtered if e.get("username") == username]
        if host:
            filtered = [e for e in filtered if e.get("host") == host]
        if event_type:
            filtered = [e for e in filtered if e.get("event_type") == event_type]

        start = (page - 1) * page_size
        end = start + page_size
        return {
            "status_code": 200,
            "data": filtered[start:end],
            "meta": {"total": len(filtered), "page": page, "page_size": page_size}
        }

    def get_event_by_id(self, event_id: str, token: Optional[str] = "valid_jwt_token_analyst_123") -> Dict[str, Any]:
        if token not in self.tokens:
            return {"status_code": 401, "errors": [{"message": "Unauthorized"}]}
        if event_id in self.events_db:
            return {"status_code": 200, "data": self.events_db[event_id]}
        return {"status_code": 404, "errors": [{"message": f"Event {event_id} not found"}]}

    def get_health(self) -> Dict[str, Any]:
        return {"status_code": 200, "data": {"status": "healthy", "database": "connected", "version": "1.0.0"}}


# ---------------------------------------------------------------------------
# Mock RAG Pipeline (Simulates Member 1's RAG & LangGraph Agents)
# ---------------------------------------------------------------------------

class MockRAGPipeline:
    """Simulates Member 1's RAG retrieval and evidence-backed report generator."""

    def __init__(self):
        # Comprehensive knowledge base aligned with MITRE ATT&CK and golden evaluation set
        self.knowledge_base = {
            "mitre_t1110_overview": {
                "chunk_id": "mitre_t1110_overview",
                "technique_id": "T1110",
                "name": "Brute Force",
                "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.",
                "keywords": ["brute", "force", "password", "guessing", "credential", "access", "lockout", "evade"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "mitre_t1110_001_detail": {
                "chunk_id": "mitre_t1110_001_detail",
                "technique_id": "T1110.001",
                "name": "Password Guessing",
                "description": "Adversaries may systematically guess passwords to gain access to accounts.",
                "keywords": ["password", "guessing", "brute", "force", "lockout", "threshold", "evasion"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "mitre_t1110_003_detail": {
                "chunk_id": "mitre_t1110_003_detail",
                "technique_id": "T1110.003",
                "name": "Password Spraying",
                "description": "Adversaries may use a single or small list of commonly used passwords against many accounts.",
                "keywords": ["spraying", "password", "spraying", "lockout", "policy"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "mitre_t1110_004_detail": {
                "chunk_id": "mitre_t1110_004_detail",
                "technique_id": "T1110.004",
                "name": "Credential Stuffing",
                "description": "Adversaries may use lists of compromised credentials to authenticate across multiple accounts.",
                "keywords": ["credential", "stuffing", "compromised", "credentials", "automated", "spray"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "mitre_t1548_overview": {
                "chunk_id": "mitre_t1548_overview",
                "technique_id": "T1548",
                "name": "Abuse Elevation Control Mechanism",
                "description": "Adversaries may circumvent mechanisms designed to control elevation of privileges to gain higher permissions.",
                "keywords": ["privilege", "escalation", "elevation", "control", "administrator", "unauthorized"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "mitre_t1021_overview": {
                "chunk_id": "mitre_t1021_overview",
                "technique_id": "T1021",
                "name": "Remote Services",
                "description": "Adversaries may use valid accounts to log into remote services such as RDP and SMB to move laterally.",
                "keywords": ["remote", "services", "lateral", "movement", "rdp", "smb", "hopping"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "mitre_t1021_001_rdp": {
                "chunk_id": "mitre_t1021_001_rdp",
                "technique_id": "T1021.001",
                "name": "Remote Desktop Protocol",
                "description": "Adversaries may log into interactive desktop environments using RDP for lateral movement.",
                "keywords": ["rdp", "remote", "desktop", "lateral", "movement", "protocol"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "mitre_t1071_overview": {
                "chunk_id": "mitre_t1071_overview",
                "technique_id": "T1071",
                "name": "Application Layer Protocol",
                "description": "Adversaries may communicate using application layer protocols to blend in with legitimate network traffic.",
                "keywords": ["application", "layer", "protocol", "c2", "command", "control", "web"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "mitre_t1071_004_dns": {
                "chunk_id": "mitre_t1071_004_dns",
                "technique_id": "T1071.004",
                "name": "DNS Tunneling",
                "description": "Adversaries may use DNS protocols and TXT query lookups to establish covert channels for command and data exfiltration.",
                "keywords": ["dns", "tunneling", "covert", "txt", "queries", "entropy"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "mitre_t1041_overview": {
                "chunk_id": "mitre_t1041_overview",
                "technique_id": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "description": "Adversaries may steal data by transferring it over an existing command and control channel.",
                "keywords": ["exfiltration", "data", "egress", "transfer", "c2", "confidential"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "mitre_t1003_overview": {
                "chunk_id": "mitre_t1003_overview",
                "technique_id": "T1003",
                "name": "OS Credential Dumping",
                "description": "Adversaries may attempt to dump credentials from memory or filesystem structures to obtain account logins.",
                "keywords": ["credential", "dumping", "ntds", "active", "directory", "hashes"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "mitre_t1003_003_ntds": {
                "chunk_id": "mitre_t1003_003_ntds",
                "technique_id": "T1003.003",
                "name": "NTDS.dit Extraction",
                "description": "Adversaries may extract the Active Directory database file NTDS.dit via Volume Shadow Copy service.",
                "keywords": ["ntds", "active", "directory", "shadow", "copy", "database", "hashes"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "mitre_t1070_overview": {
                "chunk_id": "mitre_t1070_overview",
                "technique_id": "T1070",
                "name": "Indicator Removal",
                "description": "Adversaries may delete system logs and event trails to evade forensic detection.",
                "keywords": ["indicator", "removal", "clear", "logs", "deletion", "audit"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "mitre_t1070_001_clear_logs": {
                "chunk_id": "mitre_t1070_001_clear_logs",
                "technique_id": "T1070.001",
                "name": "Clear Event Logs",
                "description": "Adversaries may clear Windows event logs or Linux audit trails to hinder incident response.",
                "keywords": ["clear", "event", "logs", "tampering", "audit", "wevtutil"],
                "source": "MITRE ATT&CK Enterprise Matrix v14"
            },
            "playbook_credential_stuffing_containment": {
                "chunk_id": "playbook_credential_stuffing_containment",
                "technique_id": "T1110.004",
                "name": "SOC IR Playbook: Credential Stuffing",
                "description": "Procedures for containing credential stuffing: revoke active sessions, block source IPs, enforce MFA.",
                "keywords": ["incident", "response", "credential", "stuffing", "procedures", "containment", "reset"],
                "source": "NIST SP 800-61 Incident Handling Guide"
            },
            "playbook_lateral_movement_containment": {
                "chunk_id": "playbook_lateral_movement_containment",
                "technique_id": "T1021",
                "name": "SOC IR Playbook: Lateral Movement Containment",
                "description": "Containment steps for lateral movement: host isolation, session revocation, firewall ACL enforcement.",
                "keywords": ["containment", "steps", "lateral", "movement", "isolate", "host", "rdp"],
                "source": "NIST SP 800-61 Incident Handling Guide"
            },
            "playbook_unauthorized_privilege_escalation": {
                "chunk_id": "playbook_unauthorized_privilege_escalation",
                "technique_id": "T1548",
                "name": "SOC IR Playbook: Privilege Escalation",
                "description": "Verification steps for unauthorized privilege change: ticket verification, role reversion, audit review.",
                "keywords": ["privilege", "escalation", "ticket", "reversion", "unauthorized", "actions"],
                "source": "NIST SP 800-61 Incident Handling Guide"
            },
            "playbook_data_exfiltration_containment": {
                "chunk_id": "playbook_data_exfiltration_containment",
                "technique_id": "T1041",
                "name": "SOC IR Playbook: Active Exfiltration Egress",
                "description": "Immediate containment for active data exfiltration: egress traffic termination, connection drop, forensic preservation.",
                "keywords": ["exfiltration", "data", "egress", "playbook", "response", "containment"],
                "source": "NIST SP 800-61 Incident Handling Guide"
            },
            "playbook_impossible_travel_verification": {
                "chunk_id": "playbook_impossible_travel_verification",
                "technique_id": "T1078",
                "name": "SOC IR Playbook: Impossible Travel Triage",
                "description": "Investigative steps for impossible travel anomalies: IP ISP verification, corporate VPN analysis, user step-up auth.",
                "keywords": ["impossible", "travel", "investigate", "responder", "verification", "geo"],
                "source": "NIST SP 800-61 Incident Handling Guide"
            },
            "mitigation_mfa_rate_limiting": {
                "chunk_id": "mitigation_mfa_rate_limiting",
                "technique_id": "T1110",
                "name": "Mitigation Guide: Enterprise MFA & IP Rate Limiting",
                "description": "Defensive controls to prevent automated credential attacks: FIDO2 tokens, exponential backoff, rate limiting.",
                "keywords": ["mitigations", "prevent", "brute", "force", "credential", "stuffing", "mfa"],
                "source": "CIS Critical Security Controls v8"
            },
            "mitigation_network_segmentation": {
                "chunk_id": "mitigation_network_segmentation",
                "technique_id": "T1021",
                "name": "Mitigation Guide: Microsegmentation & Host Firewalls",
                "description": "Architectural controls preventing internal lateral movement: disable peer-to-peer RDP and SMB.",
                "keywords": ["architectural", "controls", "prevent", "lateral", "movement", "rdp", "smb"],
                "source": "CIS Critical Security Controls v8"
            },
            "mitigation_active_directory_tiering": {
                "chunk_id": "mitigation_active_directory_tiering",
                "technique_id": "T1003.003",
                "name": "Mitigation Guide: Active Directory Tier 0 Hardening",
                "description": "Hardening domain controllers to prevent NTDS extraction: LAPS, Tier 0 isolation, protected users group.",
                "keywords": ["defenses", "protect", "active", "directory", "database", "shadow", "copy", "ntds"],
                "source": "Microsoft Enterprise Access Model"
            }
        }

    def retrieve(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Retrieve relevant cybersecurity chunks based on query terms."""
        results = []
        q_tokens = set(re.findall(r"\w+", query.lower()))

        for cid, doc in self.knowledge_base.items():
            score = 0.0
            # Check technique ID
            tid = doc["technique_id"].lower()
            if tid in query.lower():
                score += 3.0

            # Check keyword match
            doc_keywords = set(doc.get("keywords", []))
            overlap = q_tokens.intersection(doc_keywords)
            score += len(overlap) * 0.8

            # Check title match
            title_tokens = set(re.findall(r"\w+", doc["name"].lower()))
            score += len(q_tokens.intersection(title_tokens)) * 1.0

            if score > 0:
                results.append({
                    "chunk_id": cid,
                    "technique_id": doc["technique_id"],
                    "title": doc["name"],
                    "content": doc["description"],
                    "source": doc["source"],
                    "relevance_score": score
                })

        results.sort(key=lambda x: x["relevance_score"], reverse=True)
        return results[:top_k]

    def generate_investigation_report(self, alert: Dict[str, Any], retrieved_docs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a structured, evidence-grounded report with uncertainty caveats."""
        event_ids = alert.get("event_ids", [])
        return {
            "investigation_id": f"INV-{alert.get('alert_id', '999')}",
            "status": "completed",
            "summary": f"Investigation of alert {alert.get('alert_id')} ({alert.get('rule_name')}). Evidence suggests potential unauthorized activity.",
            "evidence_event_ids": event_ids,
            "citations": [
                {"technique_id": d["technique_id"], "source": d["source"]}
                for d in retrieved_docs
            ],
            "confidence": 0.85,
            "uncertainty_caveats": [
                "Conclusions are probabilistic and grounded solely in provided audit records.",
                "Compromise is not definitively confirmed without host forensic memory analysis."
            ],
            "recommendations": [
                "Temporarily reset affected user credentials.",
                "Inspect network firewall logs for destination IP addresses."
            ]
        }


# ---------------------------------------------------------------------------
# Fixture Singletons
# ---------------------------------------------------------------------------

@pytest.fixture
def detection_engine() -> MockDetectionEngine:
    return MockDetectionEngine()


@pytest.fixture
def api_client(all_events) -> MockAPIClient:
    return MockAPIClient(events=all_events)


@pytest.fixture
def rag_pipeline() -> MockRAGPipeline:
    return MockRAGPipeline()
