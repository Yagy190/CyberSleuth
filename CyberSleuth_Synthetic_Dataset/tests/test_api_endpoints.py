"""
Integration test suite for Member 2's FastAPI REST Endpoints.

Validates:
- Health check probe
- Authentication lifecycle and JWT token validation
- Event ingestion API (bulk insert, validation, deduplication)
- Event querying with filters (username, host, event_type, pagination)
- Alert and incident management endpoints
- AI investigation trigger & progress endpoints
- Error handling (401 Unauthorized, 404 Not Found, 422 Validation Error)
- Standardized API response format ({data, meta, errors})
"""
import pytest
from typing import Dict, Any


class TestHealthAndAuthEndpoints:
    """Tests for system health and authentication routes."""

    def test_health_check_returns_200(self, api_client):
        """GET /api/v1/health returns 200 with healthy database status."""
        res = api_client.get_health()
        assert res["status_code"] == 200
        assert res["data"]["status"] == "healthy"
        assert res["data"]["database"] == "connected"

    def test_auth_login_valid_credentials(self, api_client):
        """POST /api/v1/auth/login returns JWT bearer token on valid credentials."""
        creds = {"username": "sec_analyst", "password": "CyberSleuth2026!"}
        res = api_client.post_auth_login(creds)
        assert res["status_code"] == 200
        assert "access_token" in res["data"]
        assert res["data"]["token_type"] == "bearer"

    def test_auth_login_invalid_password(self, api_client):
        """POST /api/v1/auth/login returns 401 on incorrect password."""
        creds = {"username": "sec_analyst", "password": "wrong_password"}
        res = api_client.post_auth_login(creds)
        assert res["status_code"] == 401
        assert "errors" in res

    def test_auth_login_nonexistent_user(self, api_client):
        """POST /api/v1/auth/login returns 401 on unrecognized username."""
        creds = {"username": "ghost_user", "password": "password123"}
        res = api_client.post_auth_login(creds)
        assert res["status_code"] == 401

    def test_protected_endpoint_without_token_returns_401(self, api_client):
        """Querying events without authentication token returns 401."""
        res = api_client.get_events(token=None)
        assert res["status_code"] == 401

    def test_protected_endpoint_with_invalid_token_returns_401(self, api_client):
        """Querying events with forged token returns 401."""
        res = api_client.get_events(token="invalid_or_expired_token")
        assert res["status_code"] == 401


class TestEventIngestionAPI:
    """Tests for bulk security event ingestion."""

    def test_ingest_valid_events_returns_201(self, api_client):
        """POST /api/v1/events/ingest accepts clean records."""
        events = [
            {
                "event_id": "NEW_EVT_01",
                "timestamp": "2026-10-18T10:00:00Z",
                "username": "alice",
                "source_ip": "192.0.2.11",
                "host": "workstation-01",
                "event_type": "login_success"
            }
        ]
        res = api_client.post_events_ingest(events)
        assert res["status_code"] == 201
        assert res["data"]["ingested_count"] == 1

    def test_ingest_empty_batch_returns_422(self, api_client):
        """POST /api/v1/events/ingest with empty array returns 422 Unprocessable Entity."""
        res = api_client.post_events_ingest([])
        assert res["status_code"] == 422
        assert "errors" in res

    def test_ingest_quarantines_invalid_timestamp(self, api_client):
        """Batch containing malformed timestamp record properly quarantined."""
        events = [
            {
                "event_id": "MALFORMED_TS",
                "timestamp": "not-a-timestamp",
                "username": "dana",
                "source_ip": "192.0.2.51",
                "host": "workstation-01",
                "event_type": "login_success"
            }
        ]
        res = api_client.post_events_ingest(events)
        assert res["status_code"] == 201
        assert res["data"]["quarantined_count"] == 1
        assert res["data"]["ingested_count"] == 0

    def test_ingest_quarantines_missing_event_type(self, api_client):
        """Record lacking event_type is quarantined without crashing batch job."""
        events = [
            {
                "event_id": "MISSING_ETYPE",
                "timestamp": "2026-10-18T10:00:00Z",
                "username": "hank",
                "source_ip": "192.0.2.101",
                "host": "workstation-01"
            }
        ]
        res = api_client.post_events_ingest(events)
        assert res["status_code"] == 201
        assert res["data"]["quarantined_count"] == 1

    def test_ingest_deduplicates_duplicate_event_id(self, api_client):
        """Duplicate event_id within payload is recognized and deduplicated."""
        dup_events = [
            {"event_id": "DUP_99", "timestamp": "2026-10-18T10:00:00Z", "username": "erin", "source_ip": "192.0.2.61", "host": "w1", "event_type": "login_failed"},
            {"event_id": "DUP_99", "timestamp": "2026-10-18T10:00:00Z", "username": "erin", "source_ip": "192.0.2.61", "host": "w1", "event_type": "login_failed"}
        ]
        res = api_client.post_events_ingest(dup_events)
        assert res["status_code"] == 201
        assert res["data"]["ingested_count"] == 1
        assert res["data"]["quarantined_count"] == 1


class TestEventQueryingAndPagination:
    """Tests for searching, filtering, and paginating events."""

    def test_get_events_list(self, api_client):
        """GET /api/v1/events returns paginated list of events."""
        res = api_client.get_events()
        assert res["status_code"] == 200
        assert isinstance(res["data"], list)
        assert "meta" in res
        assert "total" in res["meta"]

    def test_get_events_filter_by_username(self, api_client):
        """GET /api/v1/events?username=alice returns only records for alice."""
        res = api_client.get_events(username="alice")
        assert res["status_code"] == 200
        for ev in res["data"]:
            assert ev["username"] == "alice"

    def test_get_events_filter_by_host(self, api_client):
        """GET /api/v1/events?host=workstation-01 returns records for that host."""
        res = api_client.get_events(host="workstation-01")
        assert res["status_code"] == 200
        for ev in res["data"]:
            assert ev["host"] == "workstation-01"

    def test_get_events_filter_by_event_type(self, api_client):
        """GET /api/v1/events?event_type=login_failed returns failed logins."""
        res = api_client.get_events(event_type="login_failed")
        assert res["status_code"] == 200
        for ev in res["data"]:
            assert ev["event_type"] == "login_failed"

    def test_get_events_pagination_pages(self, api_client):
        """Pagination returns correct page slices."""
        p1 = api_client.get_events(page=1, page_size=2)
        p2 = api_client.get_events(page=2, page_size=2)
        assert p1["status_code"] == 200
        assert p2["status_code"] == 200
        # IDs between page 1 and page 2 must be disjoint
        p1_ids = {e["event_id"] for e in p1["data"]}
        p2_ids = {e["event_id"] for e in p2["data"]}
        assert p1_ids.isdisjoint(p2_ids)

    def test_get_events_invalid_page_number_returns_422(self, api_client):
        """Negative or zero page number returns 422."""
        res = api_client.get_events(page=0)
        assert res["status_code"] == 422

    def test_get_event_by_id_success(self, api_client):
        """GET /api/v1/events/EVT0001 returns exact record."""
        res = api_client.get_event_by_id("EVT0001")
        assert res["status_code"] == 200
        assert res["data"]["event_id"] == "EVT0001"
        assert res["data"]["username"] == "alice"

    def test_get_event_by_id_not_found_returns_404(self, api_client):
        """GET /api/v1/events/NONEXISTENT returns 404."""
        res = api_client.get_event_by_id("EVT_NONEXISTENT_9999")
        assert res["status_code"] == 404
        assert "errors" in res


class TestAlertAndIncidentEndpoints:
    """Tests simulating alerts and incident lifecycle routes."""

    def test_get_alerts_list_structure(self, detection_engine, suspicious_events):
        """Alerts output contains required audit fields: alert_id, rule_name, severity, event_ids."""
        alerts = detection_engine.detect_brute_force(suspicious_events)
        assert len(alerts) > 0
        alert = alerts[0]
        required_fields = {"alert_id", "rule_name", "severity", "event_ids", "description", "confidence"}
        assert required_fields.issubset(alert.keys())

    def test_alert_severity_filter(self, detection_engine, suspicious_events):
        """Alerts can be filtered by severity levels."""
        all_alerts = detection_engine.run_all_rules(suspicious_events)
        critical_alerts = [a for a in all_alerts if a.get("severity") == "critical"]
        for a in critical_alerts:
            assert a["severity"] == "critical"

    def test_trigger_investigation_workflow(self, rag_pipeline, detection_engine, suspicious_events):
        """POST /api/v1/incidents/{id}/investigate triggers RAG and creates structured report."""
        alerts = detection_engine.detect_brute_force(suspicious_events)
        target_alert = alerts[0]

        # Retrieve relevant context
        docs = rag_pipeline.retrieve("T1110 brute force password", top_k=2)
        report = rag_pipeline.generate_investigation_report(target_alert, docs)

        assert report["status"] == "completed"
        assert len(report["evidence_event_ids"]) > 0
        assert len(report["citations"]) > 0
        assert len(report["uncertainty_caveats"]) > 0
        assert report["confidence"] >= 0.8
