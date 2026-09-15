import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "daily"
DATA_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = "CyberConflictWatch/0.3 (+https://github.com/lucasbittencourt02/cyber-conflict-watch)"

retry_policy = Retry(
    total=2,
    connect=2,
    read=2,
    status=2,
    backoff_factor=2,
    status_forcelist=[500, 502, 503, 504],
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
        response = SESSION.get(url, params=params, timeout=60)
        if response.status_code == 429:
            return {
                "status": "error",
                "http_status": 429,
                "error": "GDELT rate limit (HTTP 429)",
                "retry_after": response.headers.get("Retry-After"),
            }
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
            "status": "error",
            "http_status": response.get("http_status"),
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
        "fresh": True,
        "http_status": response.get("http_status"),
        "article_count": len(articles),
        "articles": articles,
        "topics": topics,
    }


def latest_gdelt_cache(now: datetime, max_age_hours: float = 36.0) -> dict | None:
    for path in sorted(DATA_DIR.glob("*.json"), reverse=True):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            collected_at = datetime.fromisoformat(payload["collected_at"])
            age_hours = (now - collected_at).total_seconds() / 3600
            if age_hours > max_age_hours:
                continue

            gdelt = payload.get("sources", {}).get("gdelt", {})
            if gdelt.get("status") == "ok":
                cached = dict(gdelt)
                cached["status"] = "cached"
                cached["fresh"] = False
                cached["cached_from"] = path.name
                cached["cached_collected_at"] = payload.get("collected_at")
                cached["cache_age_hours"] = round(age_hours, 2)
                return cached
        except Exception:
            continue
    return None


def collect_gdelt(now: datetime, skip: bool = False) -> dict:
    cache = latest_gdelt_cache(now)

    if skip:
        if cache:
            cache["cache_reason"] = "scheduled reuse; fresh GDELT collection is limited to once daily"
            return cache
        return {
            "status": "unavailable",
            "fresh": False,
            "error": "GDELT refresh skipped and no valid cache is available",
            "articles": [],
            "topics": {},
        }

    endpoint = "https://api.gdeltproject.org/api/v2/doc/doc"
    query = (
        '(Israel OR Palestine OR Gaza) '
        '(cyber OR cyberattack OR hacking OR DDoS OR malware OR phishing OR '
        'hacktivist OR hacktivism OR "internet outage" OR telecommunications OR blackout)'
    )
    params = {
        "query": query,
        "mode": "ArtList",
        "format": "json",
        "maxrecords": 50,
        "timespan": "1d",
        "sort": "HybridRel",
    }

    result = classify_gdelt_articles(fetch_json(endpoint, params))
    if result.get("status") == "ok":
        return result

    if cache:
        cache["cache_reason"] = "fresh GDELT request failed; using last valid result"
        cache["upstream_error"] = result.get("error")
        cache["upstream_http_status"] = result.get("http_status")
        return cache

    return result


def determine_health(dshield: dict, gdelt: dict) -> dict:
    dshield_checks = {
        "dshield_top_ports": dshield.get("top_ports", {}).get("status") == "ok",
        "dshield_top_ips": dshield.get("top_ips", {}).get("status") == "ok",
        "dshield_top_networks": dshield.get("top_networks", {}).get("status") == "ok",
    }

    gdelt_status = gdelt.get("status")
    checks = {
        **dshield_checks,
        "gdelt_available": gdelt_status in {"ok", "cached"},
    }

    successful = sum(checks.values())
    total = len(checks)

    if not any(dshield_checks.values()) and not checks["gdelt_available"]:
        state = "failed"
    elif all(dshield_checks.values()) and gdelt_status == "ok":
        state = "healthy"
    elif all(dshield_checks.values()) and gdelt_status == "cached":
        state = "degraded"
    else:
        state = "partial"

    return {
        "state": state,
        "successful_checks": successful,
        "total_checks": total,
        "checks": checks,
        "gdelt_fresh": gdelt_status == "ok",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--skip-gdelt",
        action="store_true",
        help="Reuse the most recent valid GDELT result instead of querying the API.",
    )
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    dshield = collect_dshield()
    gdelt = collect_gdelt(now, skip=args.skip_gdelt)
    health = determine_health(dshield, gdelt)

    payload = {
        "project": "Cyber Conflict Watch",
        "version": "0.3.0",
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
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[+] Collection saved: {output}")
    print(
        "[+] Collection health: "
        f"{health['state']} ({health['successful_checks']}/{health['total_checks']})"
    )
    print(f"[+] GDELT status: {gdelt.get('status')} | fresh={gdelt.get('fresh', False)}")


if __name__ == "__main__":
    main()
