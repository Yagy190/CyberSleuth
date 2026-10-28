"""
CyberSleuth AI – Events Router
Member 2: Backend & Data Engineering

Endpoints:
  POST /api/v1/events/ingest         – bulk-ingest a list of events (JSON)
  GET  /api/v1/events                – list events with optional filters
  GET  /api/v1/events/{event_id}     – get a single event
  POST /api/v1/events/search         – read-only search used by AI agents
"""
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.models.event import Event, EventType, GroundTruth
from app.schemas.event import EventIngest, EventResponse, EventSearchRequest
from app.detection.rules import run_detection_on_events

router = APIRouter()


# ── Ingest ─────────────────────────────────────────────────────────────────────

@router.post("/ingest", response_model=dict, status_code=201)
def ingest_events(
    events: List[EventIngest],
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Bulk-ingest normalized events. Skips duplicates by event_id."""
    new_count = 0
    skip_count = 0
    new_events = []

    for e in events:
        exists = db.query(Event.id).filter(Event.event_id == e.event_id).first()
        if exists:
            skip_count += 1
            continue
        obj = Event(
            event_id=e.event_id,
            scenario_id=e.scenario_id,
            timestamp=e.timestamp,
            event_type=e.event_type,
            username=e.username,
            host=e.host,
            source_ip=e.source_ip,
            dest_ip=e.dest_ip,
            dest_port=e.dest_port,
            ground_truth=e.ground_truth or GroundTruth.UNKNOWN,
            label_reason=e.label_reason,
            raw_details=e.raw_details,
        )
        db.add(obj)
        new_events.append(obj)
        new_count += 1

    db.commit()

    # Run detection rules on newly ingested events
    if new_events:
        db.refresh(new_events[0])  # ensure IDs are populated
        run_detection_on_events(new_events, db)

    return {"ingested": new_count, "skipped": skip_count}


# ── List / Get ─────────────────────────────────────────────────────────────────

@router.get("", response_model=List[EventResponse])
def list_events(
    username: Optional[str] = Query(None),
    host: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = db.query(Event)
    if username:
        q = q.filter(Event.username == username)
    if host:
        q = q.filter(Event.host == host)
    if event_type:
        q = q.filter(Event.event_type == event_type)
    return q.order_by(Event.timestamp.desc()).offset(offset).limit(limit).all()


@router.get("/{event_id}", response_model=EventResponse)
def get_event(
    event_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    obj = db.query(Event).filter(Event.event_id == event_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Event not found")
    return obj


# ── Agent Read-Only Search ─────────────────────────────────────────────────────

@router.post("/search", response_model=List[EventResponse])
def search_events(
    body: EventSearchRequest,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Read-only structured search used by AI agents.
    Agents may NEVER write to the database through this endpoint.
    """
    filters = []
    if body.username:
        filters.append(Event.username == body.username)
    if body.host:
        filters.append(Event.host == body.host)
    if body.source_ip:
        filters.append(Event.source_ip == body.source_ip)
    if body.event_type:
        filters.append(Event.event_type == body.event_type)
    if body.from_time:
        filters.append(Event.timestamp >= body.from_time)
    if body.to_time:
        filters.append(Event.timestamp <= body.to_time)

    return (
        db.query(Event)
        .filter(and_(*filters) if filters else True)
        .order_by(Event.timestamp.asc())
        .limit(body.limit)
        .all()
    )
