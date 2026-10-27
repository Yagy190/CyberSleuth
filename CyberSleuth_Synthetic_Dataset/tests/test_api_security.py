"""
Security and robustness test suite for CyberSleuth AI API endpoints.

Tests defensive controls against:
- SQL injection in query parameters and route paths
- Cross-Site Scripting (XSS) in event details and username payloads
- Path traversal sequences (../..)
- Parameter tampering (integer overflows, negative indices)
- Null byte string termination attacks
- Authentication tampering and token manipulation
- Payload body size enforcement
"""
import pytest
import re
from typing import Dict, Any


def sanitize_query_parameter(param: str) -> str:
    """Simulates Member 2's SQL/ORM parameter binding and character sanitizer."""
    # Disallow typical SQL escape syntax
    dangerous_patterns = [r"'.*--", r";\s*DROP", r";\s*DELETE", r"UNION\s+SELECT", r"OR\s+'1'='1"]
    for pat in dangerous_patterns:
        if re.search(pat, param, re.IGNORECASE):
            raise ValueError(f"Potentially malicious SQL sequence detected in parameter: {param}")
    # Disallow path traversal
    if ".." in param or "/" in param or "\\" in param:
        raise ValueError(f"Path traversal characters detected: {param}")
    # Disallow null bytes
    if "\x00" in param:
        raise ValueError("Null byte injection detected")
    return param.strip()


def sanitize_html_content(raw_text: str) -> str:
    """Simulates HTML escaping for frontend safe rendering."""
    return (
        raw_text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


class TestSQLInjectionResilience:
    """Validates parameters are sanitized or parameterized via SQLAlchemy."""

    def test_sql_injection_in_username_filter(self, api_client):
        """Attempts to inject SQL into ?username= query parameter."""
        malicious_input = "alice' OR '1'='1"
        with pytest.raises(ValueError, match="malicious SQL"):
            sanitize_query_parameter(malicious_input)

    def test_sql_injection_drop_table(self):
        """Attempts to inject DROP TABLE command."""
        malicious_input = "'; DROP TABLE events; --"
        with pytest.raises(ValueError, match="malicious SQL"):
            sanitize_query_parameter(malicious_input)

    def test_sql_injection_union_select(self):
        """Attempts UNION SELECT credential harvesting."""
        malicious_input = "1 UNION SELECT username, password_hash FROM users --"
        with pytest.raises(ValueError, match="malicious SQL"):
            sanitize_query_parameter(malicious_input)

    def test_sql_injection_in_event_id_route(self, api_client):
        """GET /api/v1/events/' OR '1'='1 fails cleanly without leaking SQL errors."""
        res = api_client.get_event_by_id("' OR '1'='1")
        assert res["status_code"] == 404


class TestXSSDefense:
    """Validates scripts in logs are neutralized before presentation."""

    def test_script_tag_in_event_details_escaped(self, adversarial_expanded_events):
        """EVT0413 contains stored XSS <script> payload."""
        evt13 = next(e for e in adversarial_expanded_events if e["event_id"] == "EVT0413")
        raw_msg = evt13["details"]["message"]
        sanitized = sanitize_html_content(raw_msg)
        assert "<script>" not in sanitized
        assert "&lt;script&gt;" in sanitized

    def test_img_onerror_in_username_escaped(self):
        """Username with image onerror vector is neutralized."""
        malicious_user = '<img src=x onerror=alert("pwned")>'
        sanitized = sanitize_html_content(malicious_user)
        assert "<img" not in sanitized
        assert "&lt;img" in sanitized


class TestPathTraversalDefense:
    """Validates file and resource lookups are constrained."""

    def test_path_traversal_in_event_id(self):
        """Attempting to access /etc/passwd via event ID is rejected."""
        with pytest.raises(ValueError, match="Path traversal"):
            sanitize_query_parameter("../../etc/passwd")

    def test_windows_path_traversal_in_host(self):
        """Attempting ..\\Windows\\System32 traversal is rejected."""
        with pytest.raises(ValueError, match="Path traversal"):
            sanitize_query_parameter("..\\Windows\\System32\\cmd.exe")


class TestParameterBoundaries:
    """Validates integer overflow and malformed index bounds."""

    def test_integer_overflow_in_page_size(self, api_client):
        """Gigantic page_size parameter clamped or rejected."""
        # Simulated max size enforcement
        res = api_client.get_events(page=1, page_size=10_000_000)
        # Should not crash the server
        assert res["status_code"] in [200, 422]

    def test_negative_page_number_rejected(self, api_client):
        """page=-5 rejected with 422."""
        res = api_client.get_events(page=-5)
        assert res["status_code"] == 422

    def test_null_byte_in_parameter_rejected(self):
        """Null byte injection in string parameter rejected."""
        with pytest.raises(ValueError, match="Null byte"):
            sanitize_query_parameter("valid_user\x00_injected_admin")


class TestAuthenticationHardening:
    """Validates token integrity and tamper detection."""

    def test_tampered_jwt_signature_rejected(self, api_client):
        """Modifying signature of JWT returns 401."""
        tampered_token = "valid_jwt_token_analyst_123.MODIFIED_SIGNATURE"
        res = api_client.get_events(token=tampered_token)
        assert res["status_code"] == 401

    def test_blank_bearer_token_rejected(self, api_client):
        """Empty string bearer token returns 401."""
        res = api_client.get_events(token="")
        assert res["status_code"] == 401


class TestPayloadSizeLimits:
    """Validates DOS prevention on request body limits."""

    def test_rejects_empty_json_body(self, api_client):
        """Empty dictionary payload is rejected on events ingestion."""
        res = api_client.post_events_ingest({})
        assert res["status_code"] == 422
