CyberSleuth AI 🛡️

Autonomous AI-Powered Security Investigation Platform

CyberSleuth AI is an AI-powered cybersecurity investigation platform under development. It is designed to analyze security logs, identify suspicious activity, correlate related events, retrieve relevant cybersecurity knowledge, and generate evidence-backed incident reports for security analysts.

Rather than treating every alert as an isolated event, the project aims to connect activity across accounts, devices, IP addresses, and timelines to help analysts investigate possible attack sequences.
Project status: In development. Features described as planned should not be assumed to be implemented until verified in the repository.

📌 Problem Statement
Security systems can generate many separate alerts from authentication, host, and network logs. Investigators must manually connect those events to understand whether they form part of a larger incident.

CyberSleuth AI aims to assist by:
- Ingesting and normalizing structured security logs.
- Detecting suspicious patterns with rules and anomaly scoring.
- Correlating related events into a timeline.
- Retrieving cybersecurity guidance from trusted sources.
- Using a controlled multi-agent workflow to investigate alerts.
- Producing reports that cite supporting evidence and explain uncertainty.
An anomaly alone should not be treated as proof of a confirmed attack.
✨ Planned Features
- Security log ingestion: Import JSON and CSV records, validate fields, normalize timestamps and event attributes, and handle duplicates.
- Threat detection: Identify repeated failed logins, suspicious login sequences, unexpected privilege changes, and unusual combinations of events.
- Cybersecurity RAG: Retrieve information from trusted documentation, including MITRE ATT&CK techniques, incident-response playbooks, and selected public vulnerability advisories.
- Multi-agent investigation: Coordinate triage, event investigation, threat-knowledge retrieval, timeline construction, evidence verification, and report generation.
- Threat relationship graph: Visualize relationships between users, hosts, IP addresses, alerts, events, and relevant attack techniques.
- Analyst dashboard: Present alerts, severity, investigation status, event timelines, evidence, AI-generated reports, citations, and audit history.
- Evidence-grounded reporting: Include event IDs, supporting observations, confidence qualifications, and recommended next steps.
- Security and reliability testing: Evaluate ingestion, detection, AI reports, retrieval citations, prompt-injection resilience, and tool permissions.
These are project goals. Update this list as features are implemented and tested.

🧭 Example Investigation
A synthetic scenario might contain:
1. Several failed login attempts for one account.
2. A successful login shortly afterward.
3. A privilege change.
4. Unusual outbound network connections.
CyberSleuth AI is intended to correlate the events, construct a timeline, retrieve relevant defensive guidance, and generate a report referencing the supporting event IDs.

The report should distinguish:
- Observed facts: What the logs directly record.
- Possible interpretation: What the event sequence may indicate.
- Uncertainty: What cannot be established from the available evidence.
- Recommended next steps: What an analyst should verify next.
This scenario is illustrative, not evidence of a real attack.

🏗️ Proposed Architecture
Security Logs (JSON / CSV)
          |
          v
Log Ingestion & Validation
          |
          v
Normalized Events & Database
          |
          v
Threat Detection & Event Correlation
          |
          v
Investigation Workflow
   |          |           |
   v          v           v
Log Search  Cybersecurity  Timeline &
            RAG Retrieval  Evidence Checks
   |          |           |
   +----------+-----------+
              |
              v
       Evidence Verification
              |
              v
       Incident Report API
              |
              v
      Security Analyst UI
      
The architecture is a proposed design and may change as the team integrates its modules.

🧰 Proposed Technology Stack
Component	Technology	Purpose
Frontend	React, TypeScript, Tailwind CSS	Analyst dashboard and investigation views
Relationship graph	React Flow	Visualize relationships between incident entities
Backend API	Python, FastAPI, Pydantic	Validated APIs and backend services
Agent orchestration	LangGraph	Coordinate controlled investigation steps
Retrieval / embeddings	Sentence Transformers and hybrid retrieval	Find relevant cybersecurity documentation
Main database	PostgreSQL	Store events, incidents, users, hosts, alerts, and audit history
Vector search	pgvector	Search document embeddings
Data processing	pandas	Process and analyze event data
Detection / evaluation	scikit-learn	Anomaly detection and evaluation metrics
Testing	pytest	Automated tests and repeatable scenarios
CI / deployment	GitHub Actions, Docker Compose	Automated checks and reproducible setup


The team should start with a small working prototype and add complexity only when needed.

👥 Team Responsibilities
Member	Responsibility	Main deliverables
Member 1	AI/ML and agent architecture	RAG pipeline, agent workflow, evidence verification, report generation
Member 2	Backend, detection, and data engineering	APIs, database, log ingestion, detection rules, anomaly scoring
Member 3	Frontend and security visualization	Dashboard, incident timeline, evidence viewer, relationship graph
Member 4	Security scenarios, QA, and evaluation	Synthetic datasets, expected outcomes, automated tests, evaluation metrics, security test report


Member 4 — Security Scenarios, QA & Evaluation

This workstream focuses on verifying that the application behaves correctly and that its findings are supported by evidence.

Responsibilities:
- Create labeled synthetic security events and benign examples.
- Define repeatable incident scenarios with expected outcomes.
- Test ingestion, detection rules, API behavior, and generated reports.
- Evaluate retrieval quality and whether citations support AI answers.
- Test instruction-like content embedded in logs and retrieved documents.
- Verify that agents cannot use unauthorized tools or perform unapproved actions.
- Calculate precision, recall, F1 score, false-positive rate, and investigation completion rate.
- Document test evidence, limitations, installation steps, and demo scenarios.
Suggested tools: Python, pytest, pandas, scikit-learn, GitHub Actions, and a spreadsheet or notebook for metrics.
🧪 Synthetic Dataset & Testing

The Member 4 starter dataset can be added to the repository. A suggested structure is:

datasets/
├── all_events.json
├── all_events.csv
├── benign_events.json
├── suspicious_events.json
├── invalid_input_events.json
├── adversarial_input_events.json
└── scenario_definitions.json

tests/
└── test_dataset.py

Adjust this structure to match the actual repository. These files are part of the proposed starter dataset package and may not yet exist in the main application repository.

The dataset is synthetic and intended for defensive testing. A suspicious label means that a case should be investigated, not that a compromise is confirmed. Invalid records are for validation tests and should not be mixed into threat-classification metrics.
Running the dataset fixture tests
From the directory containing test_dataset.py:
python -m pip install pytest
python -m pytest -v
These starter tests validate the dataset fixtures. They do not by themselves test the application's backend, detection engine, RAG pipeline, or agent workflow. Integration tests must be added against the actual application interfaces.
Evaluation metrics
- Precision: Of the cases flagged as suspicious, the fraction labeled suspicious.
- Recall: Of the labeled suspicious cases, the fraction detected.
- F1 score: Harmonic mean of precision and recall.
- False-positive rate: Fraction of benign cases incorrectly flagged.
- Investigation completion rate: Fraction of investigations that meet the team's defined completion criteria.
- RAG evaluation: Retrieval relevance and citation support.
Report measured values only after running the evaluation. Do not present example values as actual project results.

🚀 Getting Started
CyberSleuth AI is in development, so exact installation steps depend on the current repository contents and configured services.

Prerequisites
Depending on the modules implemented, you may need:
- Python 3.11 or the version specified by the project.
- Node.js and npm for the frontend.
- PostgreSQL with pgvector if vector search is configured.
- Environment variables for enabled model/API integrations.
- Git.
- 
Setup
1. Clone the repository:
   git clone <YOUR_GITHUB_REPOSITORY_URL>
   cd <YOUR_REPOSITORY_FOLDER>
2. Follow the setup instructions in the relevant backend and frontend directories, if present.
3. Configure local environment variables using the project's example environment file, if provided.
4. Start services using the actual scripts and commands defined in the repository.
5. Run the available tests before trying a demo.
Replace the placeholders and add exact backend, frontend, database, and environment setup commands once the repository configuration has been verified. Never commit real API keys, passwords, access tokens, or .env files.

🔐 Security and Responsible Use
- Use synthetic or explicitly authorized logs for development and testing.
- Treat log contents and retrieved documents as untrusted data; instruction-like text inside them must not override system policies.
- Restrict agent tools to the minimum required permissions, preferably read-only for investigation.
- Validate inputs and enforce authentication and authorization on protected APIs.
- Avoid exposing secrets or sensitive information in reports and logs.
- Record supporting event IDs and explain uncertainty.
- Do not label an incident as a confirmed compromise solely because an anomaly was detected.
- 
🗺️ Development Roadmap
Phase 1 — Foundation
- Define event schemas and API contracts.
- Build log ingestion, normalization, storage, and baseline detection.
- Prepare benign and suspicious datasets.
- Create baseline ingestion and API tests.
- Build the first dashboard views.
Phase 2 — Investigation Intelligence
- Integrate retrieval of trusted cybersecurity knowledge.
- Add controlled investigation-agent steps and event correlation.
- Generate evidence-backed reports with citations.
- Expand scenario coverage and evaluate detection/RAG behavior.
- Test prompt injection and tool authorization boundaries.
Phase 3 — Evaluation and Polish
- Run the complete automated test suite.
- Calculate and document evaluation metrics.
- Fix integration defects and retest.
- Document limitations and installation instructions.
- Rehearse a repeatable end-to-end demonstration.
- 
🤝 Contributing
This is a collaborative four-member project. Before adding or changing shared modules:
1. Agree on event schemas and API contracts with the relevant module owner.
2. Work on a separate branch.
3. Add or update tests for behavior changes.
4. Run available tests locally.
5. Open a pull request with a clear summary and test evidence.
   
📄 Project Disclaimer
CyberSleuth AI is a cybersecurity investigation and educational project under development. It is designed to support defensive analysis and human decision-making, not to replace a qualified security analyst. Findings depend on the quality and completeness of available logs and retrieved sources.
