import csv
import io

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditEvent
from app.schemas import AuditEventRead
from app.security import ANY_ROLE
from app.services.audit import verify_chain
from app.services.finding_service import expire_acceptances, remediation_plan
from app.services.report_service import executive_report

router = APIRouter(tags=["reports & audit"], dependencies=[Depends(ANY_ROLE)])


@router.get("/reports/executive", response_class=PlainTextResponse)
def get_executive_report(db: Session = Depends(get_db)):
    """COMEX-ready Markdown: headline, trend, business services at risk, accepted risks, decisions requested."""
    expire_acceptances(db)
    return PlainTextResponse(executive_report(db), media_type="text/markdown; charset=utf-8")


@router.get("/reports/remediation-plan")
def get_remediation_plan(format: str = Query(default="json", pattern="^(json|csv)$"), db: Session = Depends(get_db)):
    """Open work grouped by owner and ordered by deadline (CSV ready for Jira / ServiceNow import)."""
    plan = remediation_plan(db)
    if format == "json":
        return plan
    buffer = io.StringIO()
    fields = ["owner", "finding_id", "cve_id", "asset", "business_service", "risk_level", "risk_score",
              "decision", "sla_due_at", "overdue", "ticket_ref"]
    writer = csv.DictWriter(buffer, fieldnames=fields)
    writer.writeheader()
    for group in plan:
        for item in group["items"]:
            writer.writerow({"owner": group["owner"], **item})
    return Response(buffer.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="remediation-plan.csv"'})


@router.get("/audit", response_model=list[AuditEventRead])
def list_audit(limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)):
    return db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit).all()


@router.get("/audit/verify")
def verify_audit(db: Session = Depends(get_db)):
    return verify_chain(db)
