"""
CyberSleuth AI – RAG & Agent Unit Tests
Member 1: AI/ML & Agent Architecture Lead
"""
from datetime import datetime, timezone
from app.rag.knowledge_base import get_knowledge_base
from app.rag.retriever import retrieve, retrieve_for_techniques
from app.rag.agent import run_investigation_workflow
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.event import Event, EventType


def test_knowledge_base_loading():
    kb = get_knowledge_base()
    assert len(kb.chunks) > 0
    technique_ids = [c.technique_id for c in kb.chunks if c.technique_id]
    assert "T1110" in technique_ids
    assert "T1548" in technique_ids


def test_rag_retrieval():
    results = retrieve("password guessing brute force attempts", top_k=3)
    assert len(results) > 0
    top_chunk, score = results[0]
    assert score > 0
    assert "Brute Force" in top_chunk.title or "Password" in top_chunk.title


def test_retrieval_by_technique_id():
    chunks = retrieve_for_techniques(["T1110"])
    assert len(chunks) > 0
    assert all("T1110" in c.technique_id for c in chunks)


def test_multi_agent_investigation_workflow(db_session):
    now = datetime.now(timezone.utc)

    # 1. Add supporting event
    evt = Event(
        event_id="EVT_AGENT_001",
        timestamp=now,
        event_type=EventType.LOGIN_FAILURE,
        username="compromised_user",
        host="host-dc01",
        source_ip="192.168.1.99",
    )
    db_session.add(evt)

    # 2. Add alert
    alert = Alert(
        alert_id="ALERT_AGENT_001",
        rule_name="BruteForce",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.OPEN,
        username="compromised_user",
        host="host-dc01",
        source_ip="192.168.1.99",
        description="Repeated failed logins observed",
        evidence_events=["EVT_AGENT_001"],
    )
    db_session.add(alert)
    db_session.commit()

    # 3. Run investigation
    result = run_investigation_workflow([alert.alert_id], db_session)

    assert "report" in result
    assert "summary" in result
    assert "confidence" in result
    assert "timeline" in result
    assert "graph" in result
    assert len(result["recommendations"]) > 0
    assert result["confidence"] > 0
