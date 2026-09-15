import json
import os
from datetime import datetime, timezone
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "data" / "connectivity"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

API_URL = "https://api.cloudflare.com/client/v4/radar/annotations/outages"
REGIONS = {"IL": "Israel", "PS": "Palestinian Territories"}


def main() -> None:
    now = datetime.now(timezone.utc)
    token = os.getenv("CLOUDFLARE_RADAR_TOKEN", "").strip()
    payload = {
        "collected_at": now.isoformat(),
        "source": "cloudflare_radar",
        "regions": REGIONS,
        "status": "unavailable",
        "events": [],
        "methodology_notice": (
            "Connectivity outages can have physical, operational, political or cyber causes. "
            "An outage is not by itself evidence of a cyberattack."
        ),
    }

    if not token:
        payload["reason"] = "CLOUDFLARE_RADAR_TOKEN secret is not configured"
    else:
        try:
            response = requests.get(
                API_URL,
                headers={"Authorization": f"Bearer {token}"},
                params={"dateRange": "7d", "limit": 100, "format": "json"},
                timeout=45,
            )
            response.raise_for_status()
            body = response.json()
            annotations = body.get("result", {}).get("annotations", [])
            regional = []
            for item in annotations:
                locations = set(item.get("locations") or [])
                matches = sorted(locations.intersection(REGIONS))
                if not matches:
                    continue
                regional.append({
                    "id": item.get("id"),
                    "locations": matches,
                    "event_type": item.get("eventType"),
                    "start": item.get("startDate"),
                    "end": item.get("endDate"),
                    "scope": item.get("scope"),
                    "description": item.get("description"),
                    "outage": item.get("outage"),
                    "asns": item.get("asns", []),
                    "linked_url": item.get("linkedUrl"),
                    "data_source": item.get("dataSource"),
                })
            payload["status"] = "ok"
            payload["events"] = regional
            payload["event_count"] = len(regional)
        except Exception as exc:
            payload["status"] = "error"
            payload["reason"] = str(exc)

    output = OUTPUT_DIR / now.strftime("%Y-%m-%d_%H-%M-%S.json")
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] Connectivity collection saved: {output}")
    print(f"[+] Cloudflare Radar: {payload['status']} | regional events={len(payload['events'])}")


if __name__ == "__main__":
    main()
