import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "daily"
OUTPUT_DIR = BASE_DIR / "data" / "analysis"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def rows(raw: str):
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line.split("\t")


def main():
    files = sorted(DATA_DIR.glob("*.json"))
    port_presence = Counter()
    ip_presence = Counter()
    network_presence = Counter()
    usable = 0

    for path in files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            dshield = payload.get("sources", {}).get("dshield", {})
            if not all(dshield.get(k, {}).get("status") == "ok" for k in ("top_ports", "top_ips", "top_networks")):
                continue
            usable += 1
            port_presence.update({r[0] for r in rows(dshield["top_ports"].get("data", "")) if r})
            ip_presence.update({r[0] for r in rows(dshield["top_ips"].get("data", "")) if r})
            network_presence.update({f"{r[0]}/{r[2]}" for r in rows(dshield["top_networks"].get("data", "")) if len(r) > 2})
        except Exception:
            continue

    def top(counter, n=20):
        return [
            {"value": value, "collections_present": count, "presence_ratio": round(count / usable, 3) if usable else 0}
            for value, count in counter.most_common(n)
        ]

    maturity = "building"
    if usable >= 28:
        maturity = "minimum_7_day_baseline"

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "usable_collections": usable,
        "baseline_maturity": maturity,
        "note": "Presence frequency is a baseline feature, not a maliciousness or attribution score.",
        "top_port_presence": top(port_presence),
        "top_ip_presence": top(ip_presence),
        "top_network_presence": top(network_presence),
    }
    output = OUTPUT_DIR / "dshield_baseline.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] Baseline updated: {output} | usable={usable} | maturity={maturity}")


if __name__ == "__main__":
    main()
