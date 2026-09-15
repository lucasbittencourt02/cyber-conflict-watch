import json
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "daily"
DATA_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = "CyberConflictWatch/0.2 (+https://github.com/lucasbittencourt02/cyber-conflict-watch)"

retry_policy = Retry(
    total=3,
    connect=3,
    read=3,
    status=3,
    backoff_factor=3,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["GET"]),
    respect_retry_after_header=True,
    raise_on_status=False,
)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})
SESSION.mount("https://", HTTPAdapter(max_retries=retry_policy))


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
        response = SESSION.get(url, params=params, timeout=90)
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


def classify_gdelt_articles(response: dict) -> dict:
    if response.get("status") != "ok":
        return {
            "status": response.get("status", "error"),
            "error": response.get("error", "GDELT request failed"),
            "articles": [],
            "topics": {},
        }

    articles = response.get("data", {}).get("articles", [])

    topics = {
        "cyber": [],
        "connectivity": [],
        "hacktivism": [],
    }

    keywords = {
        "cyber": [
            "cyber", "hack", "ddos", "malware", "phishing", "ransomware",
            "breach", "exploit", "wiper", "botnet",
        ],
        "connectivity": [
            "internet", "outage", "blackout", "telecom", "telecommunication",
            "connectivity", "network disruption",
        ],
        "hacktivism": [
            "hacktivist", "hacktivism", "claimed responsibility", "claim",
            "defacement", "leak",
        ],
    }

    for article in articles:
        searchable = " ".join(
            str(article.get(field, ""))
            for field in ("title", "url", "domain")
        ).lower()

        for topic, terms in keywords.items():
            if any(term in searchable for term in terms):
                topics[topic].append(article)

    return {
        "status": "ok",
        "http_status": response.get("http_status"),
        "article_count": len(articles),
        "articles": articles,
        "topics": topics,
    }


def collect_gdelt() -> dict:
    endpoint = "https://api.gdeltproject.org/api/v2/doc/doc"

    # One broad request per collection run. This is intentionally kept to a
    # single GDELT request to be friendly to the public API and reduce HTTP 429s.
    query = (
        '(Israel OR Palestine OR Gaza) '
        '(cyber OR cyberattack OR hacking OR DDoS OR malware OR phishing OR '
        'hacktivist OR hacktivism OR "internet outage" OR telecommunications OR blackout)'
    )

    params = {
        "query": query,
        "mode": "ArtList",
        "format": "json",
        "maxrecords": 75,
        "timespan": "1d",
        "sort": "HybridRel",
    }

    response = fetch_json(endpoint, params)
    return classify_gdelt_articles(response)


def determine_health(dshield: dict, gdelt: dict) -> dict:
    checks = {
        "dshield_top_ports": dshield.get("top_ports", {}).get("status") == "ok",
        "dshield_top_ips": dshield.get("top_ips", {}).get("status") == "ok",
        "dshield_top_networks": dshield.get("top_networks", {}).get("status") == "ok",
        "gdelt": gdelt.get("status") == "ok",
    }

    successful = sum(checks.values())
    total = len(checks)

    if successful == total:
        state = "healthy"
    elif successful == 0:
        state = "failed"
    else:
        state = "partial"

    return {
        "state": state,
        "successful_checks": successful,
        "total_checks": total,
        "checks": checks,
    }


def main() -> None:
    now = datetime.now(timezone.utc)

    dshield = collect_dshield()
    gdelt = collect_gdelt()
    health = determine_health(dshield, gdelt)

    payload = {
        "project": "Cyber Conflict Watch",
        "version": "0.2.0",
        "collected_at": now.isoformat(),
        "collection_health": health,
        "methodology_notice": (
            "Observed infrastructure, news reports and network telemetry do not by themselves "
            "establish attribution to a state, group or individual."
        ),
        "sources": {
            "dshield": dshield,
            "gdelt": gdelt,
        },
    }

    output = DATA_DIR / now.strftime("%Y-%m-%d_%H-%M-%S.json")
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"[+] Collection saved: {output}")
    print(
        "[+] Collection health: "
        f"{health['state']} ({health['successful_checks']}/{health['total_checks']})"
    )

    if health["state"] != "healthy":
        print("[!] One or more sources were unavailable; partial data was preserved.")


if __name__ == "__main__":
    main()
