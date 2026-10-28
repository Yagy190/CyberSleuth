"""
CyberSleuth AI – Alerts Router
Member 2: Backend & Data Engineering

Endpoints:
  GET  /api/v1/alerts               – list alerts (with filters)
  GET  /api/v1/alerts/{alert_id}    – get alert detail
  PATCH /api/v1/alerts/{alert_id}   – update alert status
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.models.alert import Alert, AlertStatus
from app.schemas.event import AlertResponse, AlertStatusUpdate

router = APIRouter()


@router.get("", response_model=List[AlertResponse])
def list_alerts(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = db.query(Alert)
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    if username:
        q = q.filter(Alert.username == username)
    return q.order_by(Alert.triggered_at.desc()).offset(offset).limit(limit).all()


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    obj = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Alert not found")
    return obj


@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert_status(
    alert_id: str,
    body: AlertStatusUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    obj = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Alert not found")
    if body.status not in [s.value for s in AlertStatus]:
        raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")
    obj.status = body.status
    db.commit()
    db.refresh(obj)
    return obj
