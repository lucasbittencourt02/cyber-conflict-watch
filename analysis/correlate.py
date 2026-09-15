import json
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONNECTIVITY_DIR = BASE_DIR / "data" / "connectivity"
EVENTS_DIR = BASE_DIR / "data" / "events"
OUTPUT_DIR = BASE_DIR / "data" / "analysis"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def latest_json(directory: Path):
    files = sorted(directory.glob("*.json")) if directory.exists() else []
    return files[-1] if files else None


def load_events():
    events = []
    if not EVENTS_DIR.exists():
        return events
    for path in sorted(EVENTS_DIR.glob("*.json")):
        try:
            event = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(event, dict) and event.get("event_id"):
                events.append(event)
        except Exception:
            continue
    return events


def main():
    now = datetime.now(timezone.utc)
    result = {
        "generated_at": now.isoformat(),
        "engine_version": "0.1",
        "status": "ok",
        "connectivity": {"available": False, "regional_events": []},
        "tracked_events": [],
        "correlations": [],
        "methodology_notice": (
            "Temporal or geographic correlation is supporting evidence only. "
            "It does not establish causality or actor attribution."
        ),
    }

    connectivity_file = latest_json(CONNECTIVITY_DIR)
    if connectivity_file:
        try:
            connectivity = json.loads(connectivity_file.read_text(encoding="utf-8"))
            result["connectivity"] = {
                "available": connectivity.get("status") == "ok",
                "source_file": connectivity_file.name,
                "source_status": connectivity.get("status"),
                "regional_events": connectivity.get("events", []),
            }
        except Exception as exc:
            result["connectivity"]["error"] = str(exc)

    events = load_events()
    for event in events:
        summary = {
            "event_id": event.get("event_id"),
            "title": event.get("title"),
            "status": event.get("status"),
            "confidence": event.get("confidence"),
            "event_type": event.get("event_type"),
            "geography": event.get("geography", []),
        }
        result["tracked_events"].append(summary)

        geo = {str(x).upper() for x in event.get("geography", [])}
        for outage in result["connectivity"].get("regional_events", []):
            locations = {str(x).upper() for x in outage.get("locations", [])}
            if geo.intersection(locations):
                result["correlations"].append({
                    "event_id": event.get("event_id"),
                    "signal": "same_geography_connectivity_event",
                    "strength": "supporting_only",
                    "connectivity_event_id": outage.get("id"),
                    "note": "Geographic overlap requires analyst review; no causal relationship is inferred.",
                })

    output = OUTPUT_DIR / "correlations.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] Correlation output generated: {output}")
    print(f"[+] Tracked events: {len(result['tracked_events'])} | correlations: {len(result['correlations'])}")


if __name__ == "__main__":
    main()
