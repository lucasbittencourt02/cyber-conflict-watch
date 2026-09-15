import json
from datetime import datetime, timezone
from pathlib import Path

import requests


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "daily"
DATA_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = "CyberConflictWatch/0.1 (+https://github.com/lucasbittencourt02/cyber-conflict-watch)"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})


def fetch_text(url: str) -> dict:
    try:
        response = SESSION.get(url, timeout=45)
        response.raise_for_status()
        return {
            "status": "ok",
            "http_status": response.status_code,
            "data": response.text,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def fetch_json(url: str, params: dict) -> dict:
    try:
        response = SESSION.get(url, params=params, timeout=60)
        response.raise_for_status()
        return {
            "status": "ok",
            "http_status": response.status_code,
            "data": response.json(),
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def collect_dshield() -> dict:
    feeds = {
        "top_ports": "https://feeds.dshield.org/feeds/topports.txt",
        "top_ips": "https://feeds.dshield.org/feeds/topips.txt",
        "top_networks": "https://feeds.dshield.org/feeds/block.txt",
    }

    return {name: fetch_text(url) for name, url in feeds.items()}


def collect_gdelt() -> dict:
    endpoint = "https://api.gdeltproject.org/api/v2/doc/doc"

    queries = {
        "palestine_cyber": '(Gaza OR Palestine) (cyberattack OR hacking OR DDoS OR malware OR phishing)',
        "israel_cyber": 'Israel (cyberattack OR hacking OR DDoS OR malware OR phishing)',
        "connectivity": '(Gaza OR Palestine OR Israel) ("internet outage" OR telecommunications OR blackout)',
        "hacktivism": '(Israel OR Palestine OR Gaza) (hacktivist OR hacktivism OR "claimed responsibility")',
    }

    results = {}

    for name, query in queries.items():
        params = {
            "query": query,
            "mode": "ArtList",
            "format": "json",
            "maxrecords": 25,
            "timespan": "1d",
            "sort": "HybridRel",
        }
        results[name] = fetch_json(endpoint, params)

    return results


def main() -> None:
    now = datetime.now(timezone.utc)

    payload = {
        "project": "Cyber Conflict Watch",
        "version": "0.1.0",
        "collected_at": now.isoformat(),
        "methodology_notice": (
            "Observed infrastructure, news reports and network telemetry do not by themselves "
            "establish attribution to a state, group or individual."
        ),
        "sources": {
            "dshield": collect_dshield(),
            "gdelt": collect_gdelt(),
        },
    }

    output = DATA_DIR / now.strftime("%Y-%m-%d_%H-%M-%S.json")
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"[+] Collection saved: {output}")


if __name__ == "__main__":
    main()
