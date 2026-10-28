"""
CyberSleuth AI – Dataset Ingest Script
Member 2: Backend & Data Engineering

Usage:
    python -m app.scripts.ingest_dataset [--file path/to/events.json] [--token JWT_TOKEN]

Loads a JSON array of events into the backend via the /api/v1/events/ingest endpoint.
"""
import argparse
import json
import sys
import httpx
from pathlib import Path


def ingest(base_url: str, token: str, file_path: str, batch_size: int = 100):
    path = Path(file_path)
    if not path.exists():
        print(f"[ERROR] File not found: {file_path}")
        sys.exit(1)

    with open(path) as f:
        events = json.load(f)

    print(f"[INFO] Loaded {len(events)} events from {file_path}")

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    total_ingested = 0
    total_skipped = 0

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        try:
            resp = httpx.post(
                f"{base_url}/api/v1/events/ingest",
                json=batch,
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            total_ingested += data.get("ingested", 0)
            total_skipped += data.get("skipped", 0)
            print(f"  Batch {i//batch_size + 1}: +{data.get('ingested', 0)} ingested, {data.get('skipped', 0)} skipped")
        except httpx.HTTPError as e:
            print(f"  [ERROR] Batch failed: {e}")

    print(f"\n[DONE] Ingested: {total_ingested} | Skipped: {total_skipped}")


def main():
    parser = argparse.ArgumentParser(description="Ingest CyberSleuth dataset into backend")
    parser.add_argument("--url",   default="http://localhost:8000", help="Backend base URL")
    parser.add_argument("--token", required=True,                   help="JWT access token")
    parser.add_argument("--file",  required=True,                   help="Path to JSON events file")
    parser.add_argument("--batch", type=int, default=100,           help="Batch size (default: 100)")
    args = parser.parse_args()
    ingest(args.url, args.token, args.file, args.batch)


if __name__ == "__main__":
    main()
