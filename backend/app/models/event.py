"""
CyberSleuth AI – Security Event ORM Model
Member 2: Backend & Data Engineering

Represents a single normalized security log entry.
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, DateTime, Float,
    JSON, Text, Enum as SAEnum
)
from sqlalchemy.orm import relationship
import enum

from app.core.database import Base


class EventType(str, enum.Enum):
    LOGIN_FAILURE   = "login_failure"
    LOGIN_SUCCESS   = "login_success"
    PRIVILEGE_CHANGE = "privilege_change"
    NETWORK_OUTBOUND = "network_outbound"
    FILE_ACCESS     = "file_access"
    PROCESS_EXEC    = "process_exec"
    UNKNOWN         = "unknown"


class GroundTruth(str, enum.Enum):
    BENIGN      = "benign"
    SUSPICIOUS  = "suspicious"
    UNKNOWN     = "unknown"


class Event(Base):
    __tablename__ = "events"

    id            = Column(Integer, primary_key=True, index=True)
    event_id      = Column(String(64), unique=True, index=True, nullable=False)
    scenario_id   = Column(String(64), index=True, nullable=True)
    timestamp     = Column(DateTime(timezone=True), index=True, nullable=False)
    event_type    = Column(SAEnum(EventType), nullable=False, default=EventType.UNKNOWN)
    username      = Column(String(128), index=True, nullable=True)
    host          = Column(String(256), index=True, nullable=True)
    source_ip     = Column(String(45), index=True, nullable=True)   # supports IPv6
    dest_ip       = Column(String(45), nullable=True)
    dest_port     = Column(Integer, nullable=True)
    severity_score = Column(Float, default=0.0)
    ground_truth  = Column(SAEnum(GroundTruth), default=GroundTruth.UNKNOWN)
    label_reason  = Column(Text, nullable=True)
    raw_details   = Column(JSON, nullable=True)  # original details_json
    ingested_at   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        return f"<Event {self.event_id} | {self.event_type} | {self.timestamp}>"
