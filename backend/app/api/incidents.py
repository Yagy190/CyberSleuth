"""
CyberSleuth AI – Incidents Router
Member 2: Backend & Data Engineering  |  Member 1: AI/Agent Integration

Endpoints:
  POST /api/v1/incidents/run               – trigger AI investigation
  GET  /api/v1/incidents                   – list incidents
  GET  /api/v1/incidents/{incident_id}     – full incident detail with report
  GET  /api/v1/incidents/{incident_id}/graph – relationship graph JSON
  POST /api/v1/incidents/{incident_id}/feedback – analyst feedback
"""
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.models.incident import Incident, IncidentStatus
from app.models.alert import Alert
from app.schemas.incident import IncidentRunRequest, IncidentResponse, FeedbackRequest

router = APIRouter()


def _run_investigation(incident_id: str, alert_ids: List[str], db_url: str):
    """Background task that runs the LangGraph agent workflow."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.rag.agent import run_investigation_workflow

    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        incident = session.query(Incident).filter(Incident.incident_id == incident_id).first()
        if not incident:
            return
        incident.status = IncidentStatus.INVESTIGATING
        session.commit()
        try:
            result = run_investigation_workflow(alert_ids=alert_ids, db_session=session)
            incident.status        = IncidentStatus.COMPLETED
            incident.confidence    = result.get("confidence", 0.5)
            incident.summary       = result.get("summary", "")
            incident.report_markdown = result.get("report", "")
            incident.graph_data    = result.get("graph", {})
            incident.timeline      = result.get("timeline", [])
            incident.mitre_techniques = result.get("mitre_techniques", [])
            incident.recommendations  = result.get("recommendations", [])
            session.commit()
        except Exception as exc:
            incident.status = IncidentStatus.PENDING
            incident.summary = f"Investigation failed: {exc}"
            session.commit()


@router.post("/run", response_model=IncidentResponse, status_code=202)
def run_investigation(
    body: IncidentRunRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Trigger an AI investigation for the given alert IDs (async)."""
    # Validate alerts exist
    for aid in body.alert_ids:
        if not db.query(Alert).filter(Alert.alert_id == aid).first():
            raise HTTPException(status_code=404, detail=f"Alert not found: {aid}")

    incident_id = str(uuid.uuid4())
    title = body.title or f"Investigation: {', '.join(body.alert_ids[:2])}"
    incident = Incident(
        incident_id=incident_id,
        title=title,
        alert_ids=body.alert_ids,
        status=IncidentStatus.PENDING,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    from app.core.config import settings
    background_tasks.add_task(
        _run_investigation,
        incident_id=incident_id,
        alert_ids=body.alert_ids,
        db_url=settings.DB_URL,
    )
    return incident


@router.get("", response_model=List[IncidentResponse])
def list_incidents(
    status: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status)
    return q.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    obj = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Incident not found")
    return obj


@router.get("/{incident_id}/graph")
def get_incident_graph(
    incident_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    obj = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Incident not found")
    return obj.graph_data or {"nodes": [], "edges": []}


@router.post("/{incident_id}/feedback", response_model=IncidentResponse)
def add_feedback(
    incident_id: str,
    body: FeedbackRequest,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    obj = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Incident not found")
    obj.analyst_feedback = body.analyst_feedback
    db.commit()
    db.refresh(obj)
    return obj
