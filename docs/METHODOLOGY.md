# Cyber Conflict Watch — Methodology

## Purpose

Cyber Conflict Watch is a community CTI research project. It correlates public telemetry, Internet measurements, official advisories, open reporting and public cyber claims without treating temporal correlation as attribution.

## Evidence layers

1. **Observation** — telemetry, routing/connectivity measurement or directly observable technical fact.
2. **Claim** — an actor, persona, organization or third party states that an event occurred.
3. **Corroboration** — an independent source or measurement supports part of the claim.
4. **Confirmation** — sufficiently strong primary/official/technical evidence supports the event.
5. **Assessment** — analyst interpretation built from the evidence above.
6. **Hypothesis** — plausible explanation requiring more evidence.

## Event states

- `OBSERVED`: directly observed signal without a public actor claim.
- `CLAIMED`: event currently rests mainly on a claim.
- `CORROBORATED`: independent evidence supports the event, but important uncertainty remains.
- `CONFIRMED`: strong technical, primary or official evidence confirms the material event.
- `DISPUTED`: credible evidence conflicts with the original claim.

A confirmed event does not automatically mean the claimed attribution is confirmed.

## Confidence

- `LOW`: weak, single-source or ambiguous evidence.
- `MEDIUM`: multiple useful indicators or independent corroboration, with material gaps.
- `HIGH`: strong technical/primary evidence and consistent independent corroboration.
- `UNASSESSED`: insufficient analyst review.

## Attribution boundary

IP geolocation, ASN ownership, language, claimed alignment, malware overlap and timing can support investigation but do not independently establish attribution to a state, organization, group or person.

## Source roles

- Official cyber authorities and affected organizations: primary/confirmation candidates.
- Cloudflare Radar, RIPE, IODA and similar measurement platforms: connectivity/routing corroboration.
- DShield: global Internet scanning baseline, not regional targeting proof.
- GDELT/open media: discovery/context, not automatic confirmation.
- Hacktivist/social claims: leads that remain `CLAIMED` until corroborated.

## Publication rule

Automated reports are preliminary. Claims involving attribution, destructive impact, critical infrastructure compromise or sensitive geopolitical conclusions require human review before public publication.
