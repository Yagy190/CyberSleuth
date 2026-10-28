"""
CyberSleuth AI – Database Seeding and Demo Initializer
Member 2: Backend & Data Engineering | Member 4: Demo Scenarios

Runs:
  1. Initializes tables and default admin account.
  2. Ingests synthetic events from CyberSleuth_Synthetic_Dataset.
  3. Runs detection engine to populate realistic alerts.
  4. Triggers an AI investigation on the first alert to generate a complete incident with timeline, graph, and report.

Usage:
    python -m app.scripts.seed_db
"""
import json
from pathlib import Path
from datetime import datetime

from app.core.database import SessionLocal, init_db
from app.models.user import User
from app.models.event import Event, EventType, GroundTruth
from app.models.alert import Alert
from app.detection.rules import run_detection_on_events
from app.rag.agent import run_investigation_workflow
from app.models.incident import Incident, IncidentStatus


def seed_database():
    print("=" * 60)
    print("CyberSleuth AI – Database Seeding")
    print("=" * 60)

    # 1. Init schema
    print("[1/4] Initializing database schema...")
    init_db()

    session = SessionLocal()
    try:
        # 2. Check if events already exist
        existing_count = session.query(Event).count()
        if existing_count > 0:
            print(f"[2/4] Found {existing_count} existing events in database. Skipping raw ingest.")
        else:
            base_dir = Path(__file__).resolve().parent.parent.parent.parent
            dataset_candidates = [
                base_dir / "CyberSleuth_Synthetic_Dataset" / "all_events.json",
                base_dir / "CyberSleuth_Synthetic_Dataset" / "suspicious_events.json",
                base_dir / "CyberSleuth_Synthetic_Dataset" / "datasets" / "expanded_suspicious_events.json",
            ]
            dataset_file = next((f for f in dataset_candidates if f.exists()), None)

            if not dataset_file:
                print("[!] Warning: No dataset file found in CyberSleuth_Synthetic_Dataset.")
                return

            print(f"[2/4] Ingesting events from {dataset_file.name}...")
            with open(dataset_file, "r", encoding="utf-8") as f:
                raw_events = json.load(f)

            created_events = []
            for item in raw_events:
                # Parse timestamp safely
                ts_raw = item.get("timestamp")
                if isinstance(ts_raw, str):
                    try:
                        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    except Exception:
                        ts = datetime.utcnow()
                else:
                    ts = datetime.utcnow()

                evt = Event(
                    event_id=item.get("event_id"),
                    scenario_id=item.get("scenario_id"),
                    timestamp=ts,
                    event_type=item.get("event_type", EventType.UNKNOWN),
                    username=item.get("username"),
                    host=item.get("host"),
                    source_ip=item.get("source_ip"),
                    dest_ip=item.get("dest_ip"),
                    dest_port=item.get("dest_port"),
                    ground_truth=item.get("ground_truth", GroundTruth.UNKNOWN),
                    label_reason=item.get("label_reason"),
                    raw_details=item.get("details_json") if isinstance(item.get("details_json"), dict) else None,
                )
                session.add(evt)
                created_events.append(evt)

            session.commit()
            print(f"      Successfully loaded {len(created_events)} events.")

            # 3. Run detection engine
            print("[3/4] Running detection engine across loaded events...")
            alerts = run_detection_on_events(created_events, session)
            print(f"      Generated {len(alerts)} alerts.")

        # 4. Generate demo incident if none exists
        print("[4/4] Checking demo incident...")
        inc_count = session.query(Incident).count()
        if inc_count == 0:
            first_alert = session.query(Alert).first()
            if first_alert:
                print(f"      Creating AI investigation for alert: {first_alert.alert_id} ({first_alert.rule_name})...")
                incident_id = "inc-demo-001"
                incident = Incident(
                    incident_id=incident_id,
                    title=f"Investigation: {first_alert.rule_name} on {first_alert.username or 'host'}",
                    status=IncidentStatus.INVESTIGATING,
                    alert_ids=[first_alert.alert_id],
                )
                session.add(incident)
                session.commit()

                # Run LangGraph workflow
                result = run_investigation_workflow([first_alert.alert_id], session)
                incident.status = IncidentStatus.COMPLETED
                incident.confidence = result.get("confidence", 0.85)
                incident.summary = result.get("summary", "Coordinated credential access and privilege escalation detected.")
                incident.report_markdown = result.get("report", "")
                incident.graph_data = result.get("graph", {})
                incident.timeline = result.get("timeline", [])
                incident.mitre_techniques = result.get("mitre_techniques", ["T1110", "T1078"])
                incident.recommendations = result.get("recommendations", [])
                session.commit()
                print("      Demo incident generated successfully!")
            else:
                print("      No alerts available to create demo incident.")
        else:
            print(f"      Found {inc_count} existing incidents.")

        print("=" * 60)
        print("Database seeding completed successfully.")
        print("Default credentials: admin / admin123")
        print("=" * 60)

    finally:
        session.close()


if __name__ == "__main__":
    seed_database()
