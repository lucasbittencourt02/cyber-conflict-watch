import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "daily"
REPORT_DIR = BASE_DIR / "reports" / "daily"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

SAO_PAULO = ZoneInfo("America/Sao_Paulo")


def latest_collection() -> Path:
    files = sorted(DATA_DIR.glob("*.json"))
    if not files:
        raise FileNotFoundError("No collection JSON files found in data/daily")
    return files[-1]


def parse_tsv(raw: str, columns: int | None = None) -> list[list[str]]:
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("\t")]
        if columns is None or len(parts) >= columns:
            rows.append(parts)
    return rows


def markdown_escape(value: object) -> str:
    return str(value or "-").replace("|", "\\|").replace("\n", " ").strip()


def render_ports(dshield: dict) -> str:
    source = dshield.get("top_ports", {})
    if source.get("status") != "ok":
        return "Dados de portas indisponíveis nesta coleta.\n"
    rows = parse_tsv(source.get("data", ""), 2)[:10]
    if not rows:
        return "Nenhuma porta retornada pelo feed.\n"
    lines = ["| # | Porta | Serviço | Descrição |", "|---:|---:|---|---|"]
    for idx, row in enumerate(rows, 1):
        port = markdown_escape(row[0])
        service = markdown_escape(row[1] if len(row) > 1 else "-")
        description = markdown_escape(row[2] if len(row) > 2 else "-")
        lines.append(f"| {idx} | {port} | {service} | {description} |")
    return "\n".join(lines) + "\n"


def render_ips(dshield: dict) -> str:
    source = dshield.get("top_ips", {})
    if source.get("status") != "ok":
        return "Dados de IPs indisponíveis nesta coleta.\n"
    rows = parse_tsv(source.get("data", ""), 1)[:10]
    if not rows:
        return "Nenhum IP retornado pelo feed.\n"
    lines = ["| # | IP | Reverse DNS / identificação retornada |", "|---:|---|---|"]
    for idx, row in enumerate(rows, 1):
        ip = markdown_escape(row[0])
        rdns = markdown_escape(row[1] if len(row) > 1 else "-")
        lines.append(f"| {idx} | `{ip}` | {rdns} |")
    return "\n".join(lines) + "\n"


def render_networks(dshield: dict) -> str:
    source = dshield.get("top_networks", {})
    if source.get("status") != "ok":
        return "Dados de redes indisponíveis nesta coleta.\n"
    rows = parse_tsv(source.get("data", ""), 4)[:10]
    if not rows:
        return "Nenhuma rede retornada pelo feed.\n"
    lines = [
        "| # | Rede | Prefixo | Alvos reportando scans | Rede/ASN | País |",
        "|---:|---|---:|---:|---|---|",
    ]
    for idx, row in enumerate(rows, 1):
        network = f"{row[0]}/{row[2]}" if len(row) > 2 else row[0]
        targets = row[3] if len(row) > 3 else "-"
        org = row[4] if len(row) > 4 else "-"
        country = row[5] if len(row) > 5 else "-"
        lines.append(
            f"| {idx} | `{markdown_escape(network)}` | {markdown_escape(row[2] if len(row) > 2 else '-')} "
            f"| {markdown_escape(targets)} | {markdown_escape(org)} | {markdown_escape(country)} |"
        )
    return "\n".join(lines) + "\n"


def article_line(article: dict) -> str:
    title = markdown_escape(article.get("title") or "Sem título")
    domain = markdown_escape(article.get("domain") or "fonte não informada")
    url = article.get("url") or ""
    seen = markdown_escape(article.get("seendate") or article.get("date") or "-")
    if url:
        return f"- [{title}]({url}) — **{domain}** — `{seen}`"
    return f"- {title} — **{domain}** — `{seen}`"


def render_gdelt(gdelt: dict) -> str:
    status = gdelt.get("status")
    if status not in {"ok", "cached"}:
        error = markdown_escape(gdelt.get("error", "erro não informado"))
        return f"A fonte GDELT não respondeu corretamente nesta coleta. Erro registrado: `{error}`.\n"

    count = gdelt.get("article_count", 0)
    topics = gdelt.get("topics", {})
    lines = []

    if status == "cached":
        age = markdown_escape(gdelt.get("cache_age_hours", "?"))
        cached_from = markdown_escape(gdelt.get("cached_from", "coleta anterior"))
        upstream = markdown_escape(gdelt.get("upstream_error", "refresh não executado"))
        lines.extend([
            f"> ⚠️ **GDELT em cache.** Dados reutilizados de `{cached_from}` (idade aproximada: **{age} h**).",
            f"> Motivo do refresh não fresco: `{upstream}`.",
            "",
        ])

    lines.extend([
        f"A consulta disponível contém **{count} artigo(s)** na janela configurada.",
        "",
        "> **Importante:** zero resultados significa apenas que esta consulta não encontrou correspondências; não significa ausência de eventos no conflito.",
        "",
    ])

    labels = {
        "cyber": "Cyber / exploração / malware",
        "connectivity": "Conectividade / outages / telecom",
        "hacktivism": "Hacktivismo / claims / leaks",
    }
    for key, label in labels.items():
        articles = topics.get(key, [])
        lines.extend([f"### {label}", ""])
        if not articles:
            lines.append("Nenhum item classificado automaticamente nesta categoria.")
        else:
            seen_urls = set()
            emitted = 0
            for article in articles:
                url = article.get("url", "")
                if url and url in seen_urls:
                    continue
                if url:
                    seen_urls.add(url)
                lines.append(article_line(article))
                emitted += 1
                if emitted >= 8:
                    break
        lines.append("")
    return "\n".join(lines)


def source_health_table(health: dict) -> str:
    checks = health.get("checks", {})
    lines = ["| Fonte / verificação | Estado |", "|---|---|"]
    for name, ok in checks.items():
        label = name.replace("_", " ").title()
        lines.append(f"| {label} | {'✅ OK' if ok else '⚠️ Falha'} |")
    if "gdelt_fresh" in health:
        lines.append(f"| GDELT Fresh | {'✅ Sim' if health['gdelt_fresh'] else '⚠️ Não — cache'} |")
    return "\n".join(lines)


def build_report(payload: dict, source_file: Path) -> str:
    collected_at = datetime.fromisoformat(payload["collected_at"])
    local_time = collected_at.astimezone(SAO_PAULO)
    date_label = local_time.strftime("%d/%m/%Y")
    health = payload.get("collection_health", {})
    health_state = health.get("state", "unknown").upper()
    dshield = payload.get("sources", {}).get("dshield", {})
    gdelt = payload.get("sources", {}).get("gdelt", {})

    return f"""# Cyber Conflict Watch — Daily Brief — {date_label}

> **Resumo automatizado preliminar.** Este documento organiza telemetria e mídia aberta para apoiar estudo de CTI. Ele **não atribui ataques** a Estados, grupos ou indivíduos e não deve ser tratado como intelligence assessment final sem validação humana.

## Status da coleta

- **Estado:** `{health_state}`
- **Última coleta (São Paulo):** `{local_time.strftime('%Y-%m-%d %H:%M:%S %Z')}`
- **Última coleta (UTC):** `{collected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}`
- **Arquivo bruto:** `data/daily/{source_file.name}`

{source_health_table(health)}

## [OBSERVAÇÃO] Baseline global de atividade da Internet — DShield

> Os dados abaixo são **globais** e servem como baseline de scanning/atividade observada pelo DShield. Eles **não representam automaticamente atividade contra Israel, Gaza, Cisjordânia ou Palestina**.

### Top portas observadas

{render_ports(dshield)}

### Top IPs observados

{render_ips(dshield)}

> A presença de um IP nesta lista não identifica o operador real nem comprova intenção maliciosa específica contra o conflito monitorado.

### Top redes /24 observadas

{render_networks(dshield)}

## [OBSERVAÇÃO] Mídia e contexto relacionado ao conflito — GDELT

{render_gdelt(gdelt)}

## [ASSESSMENT BOUNDARY] O que este relatório ainda não pode afirmar

- Não há atribuição automática de atividade a Israel, Palestina, Irã, grupos hacktivistas ou qualquer outro ator.
- Coincidência temporal entre notícia, scanning e indisponibilidade **não demonstra causalidade**.
- País de origem de IP ou ASN **não equivale à nacionalidade do operador**.
- Os Top Ports e Top IPs do DShield são baseline global; para falar em targeting regional será necessária telemetria específica de destino.
- Claims publicados por hacktivistas devem permanecer como **CLAIMED** até haver corroboradores independentes.

## Próximos pivôs para análise humana

1. Se surgir notícia de outage, comparar com Cloudflare Radar, IODA, RIPE Atlas/BGP e fontes locais.
2. Se houver claim hacktivista, registrar horário, alvo, evidência publicada e procurar confirmação independente.
3. Se uma porta/CVE chamar atenção, verificar se o comportamento é global ou regional antes de associá-lo ao conflito.
4. Usar GreyNoise Community pontualmente para enriquecer IPs selecionados, não como prova de atribuição.
5. Mapear TTPs no MITRE ATT&CK somente depois de existir comportamento técnico observável.

## Estado analítico

**Confidence:** `UNASSESSED`

Ainda não há baseline histórica suficiente no projeto para classificar atividade como normal, elevada ou anômala. O primeiro objetivo é acumular dados consistentes durante pelo menos 7 dias.

---

_Gerado automaticamente pelo Cyber Conflict Watch v0.3. Revisão humana recomendada antes de publicação._
"""


def main() -> None:
    source_file = latest_collection()
    payload = json.loads(source_file.read_text(encoding="utf-8"))
    collected_at = datetime.fromisoformat(payload["collected_at"])
    local_date = collected_at.astimezone(SAO_PAULO).strftime("%Y-%m-%d")
    output = REPORT_DIR / f"{local_date}.md"
    output.write_text(build_report(payload, source_file), encoding="utf-8")
    print(f"[+] Daily report generated: {output}")


if __name__ == "__main__":
    main()
