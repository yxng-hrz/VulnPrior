"""Lightweight API-key RBAC.

Roles:
- admin    : full access (inventory, imports, enrichment, scoring)
- reviewer : read access + remediation status changes and risk acceptance
- auditor  : read-only access to posture, reports and audit trail

When ``API_KEYS`` is empty the API runs in demo mode and every caller is
treated as ``admin``. This keeps the portfolio demo frictionless while showing
how authorization is enforced once keys are configured.
"""
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException

from app.config import settings

ROLES = {"admin", "reviewer", "auditor"}


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    authenticated: bool


def _load_keys() -> dict[str, str]:
    keys: dict[str, str] = {}
    for item in filter(None, (part.strip() for part in settings.api_keys.split(","))):
        key, _, role = item.partition(":")
        role = role.strip().lower()
        if key and role in ROLES:
            keys[key.strip()] = role
    return keys


def current_principal(x_api_key: str | None = Header(default=None)) -> Principal:
    keys = _load_keys()
    if not keys:
        return Principal(name="demo-mode", role="admin", authenticated=False)
    if not x_api_key or x_api_key not in keys:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")
    role = keys[x_api_key]
    return Principal(name=f"{role}-key", role=role, authenticated=True)


def require_role(*allowed: str):
    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.role not in allowed:
            raise HTTPException(status_code=403, detail=f"Role '{principal.role}' is not allowed for this action")
        return principal

    return dependency


ANY_ROLE = require_role("admin", "reviewer", "auditor")
ADMIN = require_role("admin")
REVIEWER = require_role("admin", "reviewer")
AUDITOR = require_role("admin", "auditor")
