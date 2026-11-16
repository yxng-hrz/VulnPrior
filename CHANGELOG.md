# Changelog

## 2.0.0 — Vulnerability risk governance

### Added
- Threat-intelligence enrichment: FIRST EPSS API and CISA KEV feed (online), KEV JSON upload and EPSS payload (offline), ransomware-use flag, KEV dates.
- Ransomware factor and configurable scoring weights; `/dashboard/methodology`.
- Remediation lifecycle with allowed transitions, compensating-control and false-positive justifications.
- Four-eyes, time-bound risk acceptance (30-day cap for KEV) with automatic return to the queue on expiry.
- SLA deadlines anchored on detection, overdue tracking, SLA compliance rate, MTTR, % remediated within SLA.
- Business-service exposure, Pareto remediation impact, remediation plan by owner (JSON/CSV), ticket references.
- Findings CSV import with regression re-opening.
- Risk snapshots and trend, executive report, hash-chained audit log, API-key RBAC, security headers.
- Redesigned dashboard with Pareto curve, trend, plan by owner and what-if simulator.

### Changed
- `due_date` kept for compatibility, now derived from `sla_due_at`.

### Tests
- 6 → 19 tests.
