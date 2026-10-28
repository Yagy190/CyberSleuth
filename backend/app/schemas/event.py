"""Pydantic schemas for Event & Alert endpoints."""
from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel


# ── Events ─────────────────────────────────────────────────────────────────────

class EventIngest(BaseModel):
    """Single event from bulk ingest (JSON/CSV row)."""
    event_id: str
    timestamp: datetime
    event_type: str
    username: Optional[str] = None
    host: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    ground_truth: Optional[str] = "unknown"
    label_reason: Optional[str] = None
    scenario_id: Optional[str] = None
    raw_details: Optional[Dict[str, Any]] = None


class EventResponse(BaseModel):
    id: int
    event_id: str
    timestamp: datetime
    event_type: str
    username: Optional[str]
    host: Optional[str]
    source_ip: Optional[str]
    severity_score: float
    ground_truth: str
    ingested_at: datetime

    model_config = {"from_attributes": True}


class EventSearchRequest(BaseModel):
    """Read-only search used by AI agents."""
    username: Optional[str] = None
    host: Optional[str] = None
    source_ip: Optional[str] = None
    event_type: Optional[str] = None
    from_time: Optional[datetime] = None
    to_time: Optional[datetime] = None
    limit: int = 50


# ── Alerts ─────────────────────────────────────────────────────────────────────

class AlertResponse(BaseModel):
    id: int
    alert_id: str
    rule_name: str
    severity: str
    status: str
    username: Optional[str]
    host: Optional[str]
    triggered_at: datetime
    description: Optional[str]
    anomaly_score: float
    evidence_events: Optional[List[str]]

    model_config = {"from_attributes": True}


class AlertStatusUpdate(BaseModel):
    status: str   # open | investigating | resolved | false_positive
    analyst_note: Optional[str] = None
