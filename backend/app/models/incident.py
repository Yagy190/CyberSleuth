"""
CyberSleuth AI – Incident ORM Model
Member 2: Backend & Data Engineering

An incident is a grouped, AI-investigated security event cluster.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, JSON, Enum as SAEnum, Text, Float
import enum

from app.core.database import Base


class IncidentStatus(str, enum.Enum):
    PENDING      = "pending"
    INVESTIGATING = "investigating"
    COMPLETED    = "completed"
    CLOSED       = "closed"


class Incident(Base):
    __tablename__ = "incidents"

    id              = Column(Integer, primary_key=True, index=True)
    incident_id     = Column(String(64), unique=True, index=True, nullable=False)
    title           = Column(String(256), nullable=False)
    status          = Column(SAEnum(IncidentStatus), nullable=False, default=IncidentStatus.PENDING)
    severity        = Column(String(16), default="medium")
    confidence      = Column(Float, default=0.0)          # 0.0–1.0
    summary         = Column(Text, nullable=True)          # short human-readable
    report_markdown = Column(Text, nullable=True)          # full AI report
    graph_data      = Column(JSON, nullable=True)          # {nodes: [], edges: []}
    timeline        = Column(JSON, nullable=True)          # ordered event list
    mitre_techniques= Column(JSON, nullable=True)          # list of technique IDs
    recommendations = Column(JSON, nullable=True)          # list of action strings
    alert_ids       = Column(JSON, nullable=True)          # alert IDs linked to incident
    event_ids       = Column(JSON, nullable=True)          # all event IDs
    analyst_feedback= Column(Text, nullable=True)
    created_at      = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at      = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                             onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        return f"<Incident {self.incident_id} | {self.status}>"
