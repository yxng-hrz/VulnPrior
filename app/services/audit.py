"""Tamper-evident audit trail.

Every event stores the SHA-256 hash of its own content concatenated with the
hash of the previous event. Modifying or deleting a past event breaks the
chain, which ``verify_chain`` detects. This is not a substitute for WORM
storage, but it demonstrates evidence integrity, a core audit expectation.
"""
import hashlib
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent

GENESIS = "0" * 64


def _normalize(value: datetime) -> str:
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat(timespec="seconds")


def compute_hash(prev_hash: str, event_type: str, actor: str, entity_type: str, entity_id: str, details: str, created_at: datetime) -> str:
    payload = "|".join([prev_hash, event_type, actor, entity_type, entity_id, details, _normalize(created_at)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_event(
    db: Session,
    event_type: str,
    actor: str = "system",
    entity_type: str = "",
    entity_id: str = "",
    details: str = "",
) -> AuditEvent:
    last = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
    prev_hash = last.hash if last is not None and last.hash else GENESIS
    created_at = datetime.now(timezone.utc).replace(microsecond=0)
    event = AuditEvent(
        event_type=event_type,
        actor=actor,
        entity_type=entity_type,
        entity_id=str(entity_id),
        details=details,
        created_at=created_at,
        prev_hash=prev_hash,
        hash=compute_hash(prev_hash, event_type, actor, entity_type, str(entity_id), details, created_at),
    )
    db.add(event)
    db.flush()  # make the event visible to the next log_event in the same transaction
    return event


def verify_chain(db: Session) -> dict:
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
    expected_prev = GENESIS
    for event in events:
        recomputed = compute_hash(
            event.prev_hash, event.event_type, event.actor, event.entity_type,
            event.entity_id, event.details, event.created_at,
        )
        if event.prev_hash != expected_prev or recomputed != event.hash:
            return {
                "valid": False,
                "events_checked": len(events),
                "first_broken_event_id": event.id,
                "head_hash": events[-1].hash if events else GENESIS,
            }
        expected_prev = event.hash
    return {
        "valid": True,
        "events_checked": len(events),
        "first_broken_event_id": None,
        "head_hash": expected_prev,
    }
