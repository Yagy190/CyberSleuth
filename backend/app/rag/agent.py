"""
CyberSleuth AI – LangGraph Multi-Agent Investigation Workflow
Member 1: AI/ML & Agent Architecture Lead

Agent graph:
  triage → investigate → threat_intel → timeline → verification → report

Each node receives a shared state dict and may:
  - Read events via the /api/v1/events/search read-only tool
  - Retrieve MITRE knowledge via the RAG retriever
  - Append findings to state (never write to DB directly)

When MOCK_LLM=true, all LLM calls use deterministic template-based responses
so the project works without a Gemini API key.
"""
from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TypedDict

try:
    from langgraph.graph import StateGraph, END
except ImportError:
    # Graceful fallback state runner if langgraph is not installed on host
    END = "__END__"

    class StateGraph:
        def __init__(self, state_schema=None):
            self.nodes = {}
            self.edges = {}
            self.entry_point = None

        def add_node(self, name, fn):
            self.nodes[name] = fn

        def add_edge(self, start, end):
            self.edges[start] = end

        def set_entry_point(self, name):
            self.entry_point = name

        def compile(self):
            parent = self

            class CompiledGraph:
                def invoke(self, state):
                    current = parent.entry_point
                    while current and current != END:
                        fn = parent.nodes[current]
                        state = fn(state)
                        current = parent.edges.get(current, END)
                    return state

            return CompiledGraph()
from sqlalchemy.orm import Session

from app.core.config import settings
from app.rag.retriever import retrieve
from app.models.alert import Alert
from app.models.event import Event


# ── Shared state ──────────────────────────────────────────────────────────────

class InvestigationState(TypedDict, total=False):
    alert_ids: List[str]
    alerts: List[Dict[str, Any]]
    related_events: List[Dict[str, Any]]
    mitre_chunks: List[Dict[str, Any]]     # retrieved RAG results
    timeline: List[Dict[str, Any]]
    findings: List[str]                    # bullet-point findings
    verified_findings: List[str]           # findings with evidence support
    unsupported_claims: List[str]          # claims without evidence
    mitre_techniques: List[str]
    recommendations: List[str]
    confidence: float
    summary: str
    report: str
    graph: Dict[str, Any]                  # {nodes, edges}
    error: Optional[str]


# ── LLM abstraction ────────────────────────────────────────────────────────────

def _llm_call(prompt: str, system: str = "") -> str:
    """Call Gemini or return a structured mock response."""
    if settings.MOCK_LLM or not settings.GEMINI_API_KEY:
        return _mock_llm(prompt)

    from langchain_google_genai import ChatGoogleGenerativeAI
    from langchain_core.messages import HumanMessage, SystemMessage
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash",
        google_api_key=settings.GEMINI_API_KEY,
        temperature=0.1,
    )
    messages = []
    if system:
        messages.append(SystemMessage(content=system))
    messages.append(HumanMessage(content=prompt))
    response = llm.invoke(messages)
    return response.content


def _mock_llm(prompt: str) -> str:
    """Deterministic mock LLM – parses the prompt keywords for structured output."""
    p = prompt.lower()
    if "triage" in p or "severity" in p:
        return json.dumps({"severity": "high", "requires_investigation": True,
                           "reason": "Multiple suspicious events detected"})
    if "timeline" in p or "chronolog" in p:
        return "Events are ordered chronologically in the timeline."
    if "verify" in p or "evidence" in p:
        return json.dumps({"verified": True, "confidence": 0.85,
                           "unsupported": [], "supported": ["Brute force detected"]})
    if "report" in p or "incident" in p:
        return (
            "## Incident Report\n\n"
            "**Summary:** Suspicious credential access activity detected.\n\n"
            "**Findings:**\n"
            "- Multiple failed login attempts observed.\n"
            "- Successful login from unusual IP followed.\n"
            "- Privilege escalation event detected post-login.\n\n"
            "**Confidence:** 85%\n\n"
            "**Recommendations:**\n"
            "1. Reset compromised credentials immediately.\n"
            "2. Enable MFA on affected accounts.\n"
            "3. Review privilege change audit logs.\n\n"
            "*Note: Conclusions are evidence-backed. Unverified hypotheses are marked [UNCERTAIN].*"
        )
    return "Analysis complete."


# ── Tool: search logs (read-only) ─────────────────────────────────────────────

def _search_events_tool(
    db_session: Session,
    username: str | None = None,
    host: str | None = None,
    source_ip: str | None = None,
    event_type: str | None = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Read-only tool – agents may ONLY call this to access events."""
    q = db_session.query(Event)
    if username:
        q = q.filter(Event.username == username)
    if host:
        q = q.filter(Event.host == host)
    if source_ip:
        q = q.filter(Event.source_ip == source_ip)
    if event_type:
        q = q.filter(Event.event_type == event_type)
    rows = q.order_by(Event.timestamp.asc()).limit(limit).all()
    return [
        {
            "event_id": r.event_id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "event_type": r.event_type,
            "username": r.username,
            "host": r.host,
            "source_ip": r.source_ip,
            "dest_ip": r.dest_ip,
            "dest_port": r.dest_port,
        }
        for r in rows
    ]


# ── Nodes ──────────────────────────────────────────────────────────────────────

def triage_node(state: InvestigationState) -> InvestigationState:
    """Assess alert severity and decide investigation priority."""
    alerts_summary = "\n".join(
        f"- {a.get('rule_name', '?')} | {a.get('severity', '?')} | {a.get('description', '')}"
        for a in state.get("alerts", [])
    )
    prompt = (
        f"TRIAGE TASK:\nYou are a security triage analyst.\n"
        f"Alerts:\n{alerts_summary}\n\n"
        f"Return JSON: {{\"severity\": \"low|medium|high|critical\", "
        f"\"requires_investigation\": true|false, \"reason\": \"...\"}}"
    )
    resp = _llm_call(prompt, system="You are a cybersecurity triage analyst. Respond only in JSON.")
    try:
        parsed = json.loads(resp)
        state["summary"] = f"Triage: {parsed.get('reason', 'Investigation required.')}"
    except (json.JSONDecodeError, ValueError):
        state["summary"] = "Triage: Investigation required."
    return state


def investigate_node(state: InvestigationState, db_session: Session) -> InvestigationState:
    """Search for events related to each alert – core investigation step."""
    all_events: List[Dict[str, Any]] = []
    for alert in state.get("alerts", []):
        # Search by each available entity
        for search_kwargs in [
            {"username": alert.get("username"), "limit": 30},
            {"source_ip": alert.get("source_ip"), "limit": 20},
            {"host": alert.get("host"), "limit": 20},
        ]:
            if any(v for v in search_kwargs.values() if v and v != 30 and v != 20):
                events = _search_events_tool(db_session, **search_kwargs)
                all_events.extend(events)

    # De-duplicate by event_id
    seen = set()
    unique_events = []
    for e in all_events:
        if e["event_id"] not in seen:
            seen.add(e["event_id"])
            unique_events.append(e)

    state["related_events"] = unique_events
    return state


def threat_intel_node(state: InvestigationState) -> InvestigationState:
    """Retrieve relevant MITRE ATT&CK techniques from the RAG knowledge base."""
    queries = []
    for alert in state.get("alerts", []):
        rule = alert.get("rule_name", "")
        desc = alert.get("description", "")
        queries.append(f"{rule} {desc}")

    all_chunks = []
    seen_ids = set()
    for q in queries:
        results = retrieve(q, top_k=settings.RAG_TOP_K)
        for chunk, score in results:
            if chunk.chunk_id not in seen_ids and score > 0.1:
                seen_ids.add(chunk.chunk_id)
                all_chunks.append({
                    "chunk_id": chunk.chunk_id,
                    "title": chunk.title,
                    "text": chunk.text,
                    "technique_id": chunk.technique_id,
                    "tactic": chunk.tactic,
                    "score": round(score, 3),
                })

    state["mitre_chunks"] = all_chunks
    state["mitre_techniques"] = list({c["technique_id"] for c in all_chunks if c.get("technique_id")})
    return state


def timeline_node(state: InvestigationState) -> InvestigationState:
    """Sort all related events into a chronological timeline."""
    events = state.get("related_events", [])
    sorted_events = sorted(
        events,
        key=lambda e: e.get("timestamp") or "",
    )
    state["timeline"] = sorted_events

    # Build relationship graph
    nodes = []
    edges = []
    node_ids = set()

    for e in sorted_events:
        for field_name, field_type in [
            ("username", "user"),
            ("host", "host"),
            ("source_ip", "ip"),
        ]:
            val = e.get(field_name)
            if val and val not in node_ids:
                node_ids.add(val)
                nodes.append({"id": val, "type": field_type, "label": val})

        # Edges: user → host, user → ip
        if e.get("username") and e.get("host"):
            edges.append({"source": e["username"], "target": e["host"],
                          "label": e.get("event_type", ""), "event_id": e["event_id"]})
        if e.get("username") and e.get("source_ip"):
            edges.append({"source": e["username"], "target": e["source_ip"],
                          "label": "login_from", "event_id": e["event_id"]})

    state["graph"] = {"nodes": nodes, "edges": edges}
    return state


def verification_node(state: InvestigationState) -> InvestigationState:
    """
    Check whether findings are supported by actual events.
    Flags unsupported claims to ensure the report is evidence-grounded.
    """
    events = state.get("related_events", [])
    alerts = state.get("alerts", [])

    findings = []
    verified = []
    unsupported = []

    event_types_seen = {e.get("event_type") for e in events}

    for alert in alerts:
        rule = alert.get("rule_name", "")
        evidence = alert.get("evidence_events", []) or []
        desc = alert.get("description", "")

        # Evidence-grounded: the alert has event IDs supporting it
        if evidence and any(e["event_id"] in evidence for e in events):
            verified.append(f"[VERIFIED] {rule}: {desc} (Evidence: {', '.join(evidence[:3])})")
        elif rule in ("BruteForce", "BruteForceSuccess") and "login_failure" in event_types_seen:
            verified.append(f"[LIKELY] {rule}: Supported by login failure events in dataset.")
        else:
            unsupported.append(f"[UNCERTAIN] {rule}: {desc} — insufficient direct evidence in log window.")

    state["verified_findings"] = verified
    state["unsupported_claims"] = unsupported
    state["findings"] = findings

    # Confidence = ratio of verified to total
    total = len(verified) + len(unsupported)
    state["confidence"] = round(len(verified) / total, 2) if total else 0.5

    return state


def report_node(state: InvestigationState) -> InvestigationState:
    """Generate the final markdown incident report."""
    verified = "\n".join(f"- {f}" for f in state.get("verified_findings", []))
    uncertain = "\n".join(f"- {f}" for f in state.get("unsupported_claims", []))
    techniques = ", ".join(state.get("mitre_techniques", []) or ["None identified"])
    confidence = state.get("confidence", 0.0)

    # Build citations block from RAG chunks
    citations = "\n".join(
        f"[{i+1}] {c['title']} (score: {c.get('score', 0):.2f}) — {c['technique_id'] or 'N/A'}"
        for i, c in enumerate(state.get("mitre_chunks", []))
    )

    prompt = (
        f"INCIDENT REPORT TASK:\n"
        f"Verified findings:\n{verified or 'None'}\n\n"
        f"Uncertain findings:\n{uncertain or 'None'}\n\n"
        f"MITRE techniques: {techniques}\n"
        f"Confidence: {confidence:.0%}\n"
        f"Citations:\n{citations or 'None'}\n\n"
        f"Write a professional security incident report in markdown with sections: "
        f"Executive Summary, Verified Findings, Uncertain Areas, MITRE ATT&CK Mapping, "
        f"Recommendations, and Citations. "
        f"Never claim an attack is confirmed without evidence."
    )

    report_text = _llm_call(prompt, system="You are a senior security analyst. Write a concise, factual incident report.")

    # Build recommendations
    recs = [
        "Reset credentials for all affected accounts.",
        "Enable multi-factor authentication.",
        "Review and audit privilege change logs.",
        "Isolate affected hosts for forensic analysis.",
        "Update detection rules to reduce future false negatives.",
    ]
    state["recommendations"] = recs
    state["report"] = report_text
    state["summary"] = state.get("summary", "") + f" Confidence: {confidence:.0%}."
    return state


# ── Graph assembly ─────────────────────────────────────────────────────────────

def _build_graph(db_session: Session) -> StateGraph:
    graph = StateGraph(InvestigationState)

    graph.add_node("triage",       triage_node)
    graph.add_node("investigate",  lambda s: investigate_node(s, db_session))
    graph.add_node("threat_intel", threat_intel_node)
    graph.add_node("timeline",     timeline_node)
    graph.add_node("verification", verification_node)
    graph.add_node("report",       report_node)

    graph.set_entry_point("triage")
    graph.add_edge("triage",       "investigate")
    graph.add_edge("investigate",  "threat_intel")
    graph.add_edge("threat_intel", "timeline")
    graph.add_edge("timeline",     "verification")
    graph.add_edge("verification", "report")
    graph.add_edge("report",       END)

    return graph.compile()


# ── Public entry point ────────────────────────────────────────────────────────

def run_investigation_workflow(
    alert_ids: List[str],
    db_session: Session,
) -> Dict[str, Any]:
    """
    Run the full LangGraph investigation for the given alert IDs.
    Returns a dict with: summary, report, graph, timeline, mitre_techniques,
    recommendations, confidence.
    """
    # Load alerts from DB
    alerts_data = []
    for aid in alert_ids:
        alert = db_session.query(Alert).filter(Alert.alert_id == aid).first()
        if alert:
            alerts_data.append({
                "alert_id": alert.alert_id,
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "description": alert.description,
                "username": alert.username,
                "host": alert.host,
                "source_ip": alert.source_ip,
                "evidence_events": alert.evidence_events or [],
            })

    initial_state: InvestigationState = {
        "alert_ids": alert_ids,
        "alerts": alerts_data,
        "related_events": [],
        "mitre_chunks": [],
        "timeline": [],
        "findings": [],
        "verified_findings": [],
        "unsupported_claims": [],
        "mitre_techniques": [],
        "recommendations": [],
        "confidence": 0.0,
        "summary": "",
        "report": "",
        "graph": {"nodes": [], "edges": []},
        "error": None,
    }

    workflow = _build_graph(db_session)
    final_state = workflow.invoke(initial_state)
    return final_state
