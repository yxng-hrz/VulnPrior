"""Threat-intelligence enrichment from public feeds.

- FIRST EPSS API: probability that a CVE will be exploited in the next 30 days.
- CISA Known Exploited Vulnerabilities (KEV) catalogue, including ransomware use.

Network access is optional: every function also works from a payload you supply
(e.g. a KEV JSON file downloaded on an internet-connected workstation).
"""
from datetime import datetime, timezone

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Vulnerability
from app.services.audit import log_event
from app.services.finding_service import rescore_all

EPSS_BATCH = 100


def fetch_epss(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    scores: dict[str, tuple[float, float]] = {}
    with httpx.Client(timeout=settings.feed_timeout_seconds) as client:
        for start in range(0, len(cve_ids), EPSS_BATCH):
            batch = cve_ids[start:start + EPSS_BATCH]
            response = client.get(settings.epss_api_url, params={"cve": ",".join(batch)})
            response.raise_for_status()
            for row in response.json().get("data", []):
                scores[row["cve"].upper()] = (float(row["epss"]), float(row.get("percentile", 0) or 0))
    return scores


def fetch_kev_catalog() -> dict:
    with httpx.Client(timeout=settings.feed_timeout_seconds) as client:
        response = client.get(settings.kev_feed_url)
        response.raise_for_status()
        return response.json()


def apply_epss(db: Session, scores: dict[str, tuple[float, float]], actor: str) -> dict:
    now = datetime.now(timezone.utc)
    updated = 0
    for vuln in db.query(Vulnerability).all():
        if vuln.cve_id in scores:
            vuln.epss, vuln.epss_percentile = scores[vuln.cve_id]
            vuln.enriched_at = now
            updated += 1
    db.flush()
    rescored = rescore_all(db)
    log_event(db, "enrichment_epss", actor=actor, details=f"updated={updated}; rescored={rescored}")
    db.commit()
    return {"source": "FIRST EPSS", "vulnerabilities_updated": updated, "findings_rescored": rescored}


def apply_kev(db: Session, catalog: dict, actor: str) -> dict:
    entries = {item["cveID"].upper(): item for item in catalog.get("vulnerabilities", []) if "cveID" in item}
    now = datetime.now(timezone.utc)
    newly_kev = 0
    matched = 0
    for vuln in db.query(Vulnerability).all():
        entry = entries.get(vuln.cve_id)
        if not entry:
            continue
        matched += 1
        if not vuln.kev:
            newly_kev += 1
        vuln.kev = True
        vuln.ransomware_use = str(entry.get("knownRansomwareCampaignUse", "")).lower() == "known"
        vuln.kev_date_added = entry.get("dateAdded")
        vuln.kev_due_date = entry.get("dueDate")
        vuln.enriched_at = now
    db.flush()
    rescored = rescore_all(db)
    log_event(db, "enrichment_kev", actor=actor,
              details=f"catalog_version={catalog.get('catalogVersion', 'n/a')}; matched={matched}; newly_kev={newly_kev}")
    db.commit()
    return {
        "source": "CISA KEV",
        "catalog_version": catalog.get("catalogVersion"),
        "catalog_entries": len(entries),
        "vulnerabilities_matched": matched,
        "newly_flagged_kev": newly_kev,
        "findings_rescored": rescored,
    }
