"""
CyberSleuth AI – Backend API Unit Tests
Tests Authentication, Events, Ingestion, and Alerts endpoints.
"""
from datetime import datetime, timezone


def test_health_check(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_auth_registration_and_login(client):
    # Register
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "new_analyst",
            "email": "analyst@test.com",
            "password": "SecurePassword123!",
        },
    )
    assert reg_resp.status_code == 201
    assert reg_resp.json()["username"] == "new_analyst"

    # Login
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "new_analyst", "password": "SecurePassword123!"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    assert token is not None

    # Me
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "new_analyst"


def test_unauthenticated_request_fails(client):
    resp = client.get("/api/v1/events")
    assert resp.status_code == 403 or resp.status_code == 401


def test_events_ingest_and_search(client, auth_headers):
    # Ingest 2 events
    now_str = datetime.now(timezone.utc).isoformat()
    events_payload = [
        {
            "event_id": "EVT_TEST_001",
            "timestamp": now_str,
            "event_type": "login_failure",
            "username": "victim_user",
            "host": "workstation-01",
            "source_ip": "192.168.1.105",
            "ground_truth": "suspicious",
            "label_reason": "Brute force attempt test",
        },
        {
            "event_id": "EVT_TEST_002",
            "timestamp": now_str,
            "event_type": "login_success",
            "username": "victim_user",
            "host": "workstation-01",
            "source_ip": "192.168.1.105",
            "ground_truth": "suspicious",
            "label_reason": "Brute force success test",
        },
    ]

    resp = client.post("/api/v1/events/ingest", json=events_payload, headers=auth_headers)
    assert resp.status_code == 201
    assert resp.json()["ingested"] == 2

    # Duplicate should skip
    dup_resp = client.post("/api/v1/events/ingest", json=events_payload, headers=auth_headers)
    assert dup_resp.status_code == 201
    assert dup_resp.json()["skipped"] == 2

    # Read-only search tool
    search_resp = client.post(
        "/api/v1/events/search",
        json={"username": "victim_user"},
        headers=auth_headers,
    )
    assert search_resp.status_code == 200
    results = search_resp.json()
    assert len(results) == 2
    assert results[0]["event_id"] == "EVT_TEST_001"
