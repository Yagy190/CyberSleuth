"""Pydantic schemas for Incident endpoints."""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class IncidentRunRequest(BaseModel):
    """Trigger an AI investigation from one or more alert IDs."""
    alert_ids: List[str]
    title: Optional[str] = None


class IncidentResponse(BaseModel):
    id: int
    incident_id: str
    title: str
    status: str
    severity: str
    confidence: float
    summary: Optional[str]
    report_markdown: Optional[str]
    graph_data: Optional[Dict[str, Any]]
    timeline: Optional[List[Dict[str, Any]]]
    mitre_techniques: Optional[List[str]]
    recommendations: Optional[List[str]]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FeedbackRequest(BaseModel):
    analyst_feedback: str
