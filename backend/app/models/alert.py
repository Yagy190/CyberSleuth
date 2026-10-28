"""
CyberSleuth AI – Alert ORM Model
Member 2: Backend & Data Engineering

An alert is raised by the detection engine when suspicious patterns are found.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Float, JSON, ForeignKey, Enum as SAEnum, Text
import enum

from app.core.database import Base


class AlertSeverity(str, enum.Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    OPEN         = "open"
    INVESTIGATING = "investigating"
    RESOLVED     = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(Base):
    __tablename__ = "alerts"

    id              = Column(Integer, primary_key=True, index=True)
    alert_id        = Column(String(64), unique=True, index=True, nullable=False)
    rule_name       = Column(String(128), nullable=False)   # e.g. "BruteForce"
    severity        = Column(SAEnum(AlertSeverity), nullable=False, default=AlertSeverity.MEDIUM)
    status          = Column(SAEnum(AlertStatus), nullable=False, default=AlertStatus.OPEN)
    username        = Column(String(128), index=True, nullable=True)
    host            = Column(String(256), index=True, nullable=True)
    source_ip       = Column(String(45), nullable=True)
    triggered_at    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    evidence_events = Column(JSON, nullable=True)     # list of event_ids
    description     = Column(Text, nullable=True)
    anomaly_score   = Column(Float, default=0.0)
    incident_id     = Column(Integer, ForeignKey("incidents.id"), nullable=True)

    def __repr__(self) -> str:
        return f"<Alert {self.alert_id} | {self.rule_name} | {self.severity}>"
