# CyberSleuth AI — System Architecture & Design Specification

CyberSleuth AI is an autonomous, evidence-grounded cybersecurity investigation platform. It automates security event triage, multi-event attack chain correlation, relevant knowledge retrieval via RAG, and LangGraph-coordinated AI investigation.

---

## 1. High-Level Architecture Overview

The platform is structured into six decoupled modules communicating via typed API interfaces and a relational database backing.

```mermaid
flowchart TD
    subgraph DataSources["1. Log Ingestion Sources"]
        OS["OS & Auth Logs (Syslog, Windows Event)"]
        FW["Network & Firewall Egress Logs"]
        APP["Application & Cloud Audit Trails"]
    end

    subgraph Module1["Module 1 — Ingestion & Normalization"]
        PARSE["Parser & Normalizer"]
        VAL["Pydantic Schema Validator & Quarantiner"]
        DEDUP["Deduplication Engine"]
    end

    subgraph Storage["Persistence Layer"]
        PG[("PostgreSQL 15")]
        PGV[("pgvector Embeddings Index")]
    end

    subgraph Module2["Module 2 — Threat Detection Engine"]
        RULES["Deterministic Rule Engine\n(Brute Force, Sequence, Priv Change)"]
        ANOMALY["Isolation Forest Anomaly Model\n(Volume & Behavior Outliers)"]
        CORR["Temporal Correlation Engine"]
    end

    subgraph Module3["Module 3 — Cybersecurity RAG"]
        KB["MITRE ATT&CK & NIST Playbooks"]
        EMBED["Sentence Transformers (all-MiniLM-L6-v2)"]
        HYBRID["Hybrid Vector + Keyword Retriever"]
        RERANK["Cross-Encoder Reranker"]
    end

    subgraph Module4["Module 4 — LangGraph Multi-Agent Investigation"]
        TRIAGE["Triage Agent"]
        INVESTIGATE["Investigation Agent"]
        THREAT_INTEL["Threat Intel Agent"]
        TIMELINE["Timeline Agent"]
        VERIFY["Verification Agent"]
        REPORT["Reporting Agent"]
    end

    subgraph Module5["Module 5 — Threat Relationship Graph"]
        REL["Entity Extractor (IP, User, Host, Alert)"]
        GRAPH["React Flow Graph Layout Engine"]
    end

    subgraph Module6["Module 6 — Security Analyst Dashboard"]
        UI["React + TypeScript Dashboard"]
        TIMELINE_UI["Interactive Incident Timeline"]
        EVIDENCE_UI["Verifiable Evidence Inspector"]
        REPORT_UI["Calibrated AI Report Viewer"]
    end

    DataSources --> Module1
    Module1 --> Storage
    Storage --> Module2
    Module2 -->|"Alerts & Incidents"| Module4
    Module3 <-->|"Context & Citations"| Module4
    Module4 -->|"Structured Findings"| Storage
    Storage --> Module5
    Storage --> Module6
    Module5 --> Module6
```

---

## 2. End-to-End Investigation Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Security Analyst
    participant Dashboard as React Dashboard (Member 3)
    participant API as FastAPI Backend (Member 2)
    participant Detect as Detection Engine (Member 2)
    participant DB as PostgreSQL + pgvector
    participant LangGraph as LangGraph Agent Workflow (Member 1)
    participant RAG as Cybersecurity RAG (Member 1)

    Analyst->>Dashboard: Upload / stream security event batch
    Dashboard->>API: POST /api/v1/events/ingest
    API->>API: Validate schema & quarantine malformed records
    API->>DB: Store normalized events (events table)
    API->>Detect: Evaluate rules & anomaly models
    Detect->>DB: Insert correlated alert & incident
    API-->>Dashboard: 201 Created (Alerts generated)

    Analyst->>Dashboard: Click "Investigate Incident"
    Dashboard->>API: POST /api/v1/incidents/{id}/investigate
    API->>LangGraph: Initialize investigation graph state

    LangGraph->>DB: Query related entity logs (read-only tool)
    LangGraph->>RAG: Retrieve MITRE techniques & playbooks
    RAG-->>LangGraph: Relevant document chunks & citations
    LangGraph->>LangGraph: Timeline alignment & evidence verification
    LangGraph->>DB: Persist investigation report & graph links
    LangGraph-->>API: Investigation completed

    API-->>Dashboard: Push report, timeline, and relationship graph
    Dashboard->>Analyst: Render evidence-grounded findings with uncertainty caveats
```

---

## 3. Module Breakdown

### Module 1 — Security Log Ingestion Pipeline
- **Purpose**: Ingests, normalizes, and validates heterogeneous security records.
- **Key Responsibilities**:
  - Parse structured formats (JSON, CSV, Syslog).
  - Normalize timestamp formats to ISO 8601 UTC.
  - Standardize schema: `event_id`, `timestamp`, `username`, `source_ip`, `host`, `event_type`, `severity_hint`, `details`.
  - Quarantine invalid records without breaking batch processing.
  - Deduplicate re-transmitted records.

### Module 2 — Threat Detection Engine
- **Purpose**: Identify suspicious activity using both deterministic signatures and statistical anomalies.
- **Rule Engine**:
  - Repeated failed logins (threshold $\ge 5$ within 5 minutes $\rightarrow$ T1110).
  - Failed logins followed by success from identical source IP $\rightarrow$ T1110.001.
  - Unauthorized privilege changes (approved=False or missing change ticket $\rightarrow$ T1548).
  - Outbound connection bursts and heavy data egress $\rightarrow$ T1041.
  - Temporal multi-stage attack correlation linking authentication, elevation, and egress.
- **Machine Learning Engine**:
  - Scikit-learn `IsolationForest` for detecting volume and out-of-schedule behavior outliers.

### Module 3 — Cybersecurity RAG (Retrieval-Augmented Generation)
- **Purpose**: Retrieve authoritative defensive knowledge from MITRE ATT&CK Enterprise Matrix and NIST SP 800-61 playbooks.
- **Architecture**:
  - Document chunking with semantic boundaries.
  - Dense embeddings via `sentence-transformers/all-MiniLM-L6-v2`.
  - Vector similarity search in PostgreSQL via `pgvector`.
  - Re-ranking using a cross-encoder to select top relevant context chunks.
  - Source attribution with verifiable citation links.

### Module 4 — Multi-Agent Investigation (LangGraph)
- **Purpose**: Coordinate autonomous, specialized AI agents in a controlled, non-hallucinatory DAG.
- **Specialized Roles**:
  - **Triage Agent**: Assesses initial severity and scopes the investigation boundary.
  - **Investigation Agent**: Calls safe, read-only tools to search logs for related IP and host activity.
  - **Threat Intelligence Agent**: Queries RAG for matching MITRE techniques and response playbooks.
  - **Timeline Agent**: Chronologically sorts and aligns all contributing evidence events.
  - **Verification Agent**: Validates that all draft assertions are backed by concrete event IDs; strikes out unverified assumptions.
  - **Reporting Agent**: Compiles the final structured incident report with explicit uncertainty caveats.

### Module 5 — Threat Relationship Graph
- **Purpose**: Connect disparate entities (Users, Workstations, IPs, Alerts, MITRE Techniques) into an interactive topological graph.
- **Technology**: React Flow with hierarchical force-directed node layout.
- **Design Principle**: Clearly distinguishes observed facts (solid links to event IDs) from inferred attack hypotheses (dashed links).

### Module 6 — Security Analyst Dashboard
- **Purpose**: Professional Web UI for Security Operations Center (SOC) analysts.
- **Features**:
  - Incident queue with priority filters.
  - Chronological event timeline.
  - Interactive React Flow entity relationship viewer.
  - Evidence viewer linking findings directly to raw event JSON.
  - Markdown investigation report display with citation references.

---

## 4. Relational Database Schema

```mermaid
erDiagram
    USERS ||--o{ AUDIT_LOG : generates
    USERS ||--o{ INCIDENTS : assigned_to
    INCIDENTS ||--|{ ALERTS : contains
    ALERTS ||--|{ EVENTS : evidence_links
    INCIDENTS ||--o| INVESTIGATIONS : produces
    INVESTIGATIONS ||--o{ INVESTIGATION_CITATIONS : references

    EVENTS {
        string event_id PK
        timestamp timestamp
        string username
        string source_ip
        string host
        string event_type
        string severity_hint
        jsonb details
        timestamp created_at
    }

    ALERTS {
        string alert_id PK
        string rule_name
        string severity
        string target_user
        string source_ip
        text[] event_ids
        float confidence
        timestamp created_at
    }

    INCIDENTS {
        string incident_id PK
        text[] alert_ids
        string title
        string status
        string severity
        string assigned_to
        timestamp created_at
        timestamp updated_at
    }

    INVESTIGATIONS {
        string investigation_id PK
        string incident_id FK
        string status
        text summary
        jsonb timeline
        text[] evidence_event_ids
        string[] mitre_techniques
        text[] uncertainty_caveats
        text[] recommendations
        float confidence
        timestamp completed_at
    }

    INVESTIGATION_CITATIONS {
        int citation_id PK
        string investigation_id FK
        string technique_id
        string source_title
        text chunk_text
    }

    USERS {
        int user_id PK
        string username UK
        string email
        string password_hash
        string role
        boolean is_active
    }

    AUDIT_LOG {
        int log_id PK
        int user_id FK
        string action
        string resource_type
        jsonb details
        string ip_address
        timestamp timestamp
    }
```

---

## 5. Security & Isolation Controls

1. **Agent Tool Sandboxing**: AI agents are provided exclusively read-only tools (`search_logs`, `query_mitre_rag`, `get_timeline`). No write, alter, or delete database capabilities exist within the agent runtime.
2. **Untrusted Data Isolation**: All log fields (such as messages or file paths) are treated as passive string data and encapsulated inside strictly delimited data blocks, neutralising direct and indirect prompt injection attempts.
3. **Role-Based Access Control (RBAC)**: Backend endpoints verify JWT bearer tokens; analyst operations are recorded in the tamper-evident `audit_log` table.
4. **Input Sanitization**: Pydantic schemas enforce type safety and reject SQL injection, XSS, and path traversal sequences.
