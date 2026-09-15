# Cyber Conflict Watch

Community CTI observatory for monitoring cyber activity related to geopolitical conflicts using public data sources.

## Current scope — v0.1

The first version collects public information four times per day using GitHub Actions.

### Sources

- DShield / SANS ISC: top ports, source IPs and networks.
- GDELT: cyber-related reporting, connectivity disruptions and hacktivism references involving Israel, Palestine and Gaza.

### Schedule

The collector runs at approximately 06:10, 12:10, 18:10 and 23:10 in `America/Sao_Paulo`.

### Output

Each execution writes a timestamped JSON file under:

```text
data/daily/
```

The repository stores the raw collection so later versions can build baselines, detect anomalies, correlate claims and generate weekly public-facing reports.

## Methodology note

Observed IP geolocation, infrastructure, news reports and network telemetry do **not** by themselves prove attribution to a state, organization, hacktivist group or individual.

The project will distinguish observations, claims, corroborated events, assessments and hypotheses.

## Roadmap

- v0.1 — automated public-data collection
- v0.2 — normalization and daily summaries
- v0.3 — hacktivist/cyber-persona tracking
- v0.4 — weekly CTI report
- v0.5 — simplified public dashboard and Instagram-ready summaries
