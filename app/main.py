from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import Base, engine
from app.routers import assets, dashboard, enrichment, findings, imports, reports, vulnerabilities
from app.security import _load_keys


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Business-oriented vulnerability prioritization: CVSS + EPSS + CISA KEV/ransomware intelligence + asset "
        "criticality, SLA tracking, four-eyes risk acceptance, remediation workflow, Pareto impact analysis "
        "and executive reporting."
    ),
    lifespan=lifespan,
)

origins = ["*"] if settings.cors_origins == "*" else settings.cors_origins.split(",")
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if not request.url.path.startswith(("/docs", "/redoc")):
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response


for router in [assets.router, vulnerabilities.router, findings.router, dashboard.router, imports.router,
               enrichment.router, reports.router]:
    app.include_router(router, prefix="/api/v1")

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/health")
def health():
    return {"status": "ok", "service": settings.app_name, "version": settings.app_version,
            "auth_mode": "api-key" if _load_keys() else "demo"}


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(static_dir / "index.html")
