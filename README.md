# VulnPrior

**Business-oriented vulnerability prioritization for CISO / security governance portfolios.**

VulnPrior turns vulnerability data into a remediation queue that includes technical severity, exploitation likelihood and business context.

Instead of asking only:

> Which CVEs have the highest CVSS score?

VulnPrior asks:

> Which vulnerabilities should the organization remediate first, on which business assets, and why?

## What it demonstrates

- Vulnerability management
- Business risk prioritization
- CISO-oriented decision support
- Asset criticality
- CVSS / EPSS / known exploitation concepts
- Remediation SLAs
- FastAPI / SQLAlchemy / REST APIs
- Docker and PostgreSQL
- Automated tests and GitHub Actions
- Executive explanations rather than raw technical output

## Screenshot-ready dashboard

After seeding demo data, open:

- Dashboard: `http://127.0.0.1:8000`
- Swagger/OpenAPI: `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/health`

The built-in dashboard intentionally uses synthetic CVEs so the repository works offline and does not claim live vulnerability intelligence.

## Architecture

```text
Browser
   |
   v
FastAPI
   |
   +---- Assets
   +---- Vulnerabilities
   +---- Findings
   +---- Risk Preview
   +---- CSV Imports
   |
   v
Risk Engine
   |
   +---- CVSS
   +---- EPSS
   +---- Known Exploited flag
   +---- Asset criticality
   +---- Internet exposure
   +---- Sensitive data
   +---- Environment
   +---- Compensating controls
   |
   v
SQLite (local) / PostgreSQL (Docker)
```

## Risk model

VulnPrior uses an educational weighted model:

| Factor | Max impact |
|---|---:|
| CVSS | 24 |
| EPSS | 24 |
| Known exploited | 18 |
| Asset criticality | 16 |
| Internet exposure | 8 |
| Sensitive data | 5 |
| Production environment | 3 |
| Patch available | 2 |
| Compensating control | -12 |

The score is clamped between 0 and 100.

Default bands:

- `80-100` -> CRITICAL
- `60-79.9` -> HIGH
- `35-59.9` -> MEDIUM
- `<35` -> LOW

**Important:** this model is intentionally transparent and explainable. It is a portfolio/learning implementation, not an enterprise risk standard and not a substitute for professional vulnerability management processes.

## Quick start

### Requirements

- Python 3.11+
- `pip`

### Linux / macOS

```bash
git clone https://github.com/YOUR_USERNAME/vulnprior.git
cd vulnprior

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt

python scripts/seed_demo.py
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`.

### Windows PowerShell

```powershell
git clone https://github.com/YOUR_USERNAME/vulnprior.git
cd vulnprior

py -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt

python scripts/seed_demo.py
uvicorn app.main:app --reload
```

## Run tests

```bash
pytest -q
```

Expected result:

```text
6 passed
```

## Docker

```bash
docker compose up --build
```

This starts:

- FastAPI on port `8000`
- PostgreSQL on the internal Compose network

Seed data in Docker:

```bash
docker compose exec api python scripts/seed_demo.py
```

Then open `http://127.0.0.1:8000`.

Stop:

```bash
docker compose down
```

Delete the PostgreSQL volume too:

```bash
docker compose down -v
```

## API examples

### Create an asset

```bash
curl -X POST http://127.0.0.1:8000/api/v1/assets \
  -H "Content-Type: application/json" \
  -d '{
    "name": "customer-api-prod",
    "owner": "Platform",
    "environment": "production",
    "criticality": 5,
    "internet_exposed": true,
    "contains_sensitive_data": true,
    "business_service": "Customer API"
  }'
```

### Preview a risk score without storing data

```bash
curl -X POST http://127.0.0.1:8000/api/v1/dashboard/risk-preview \
  -H "Content-Type: application/json" \
  -d '{
    "cvss": 9.8,
    "epss": 0.91,
    "kev": true,
    "patch_available": true,
    "asset_criticality": 5,
    "internet_exposed": true,
    "contains_sensitive_data": true,
    "environment": "production",
    "compensating_control": false
  }'
```

### List findings by priority

```bash
curl "http://127.0.0.1:8000/api/v1/findings?limit=20"
```

### Only critical findings

```bash
curl "http://127.0.0.1:8000/api/v1/findings?level=CRITICAL"
```

### Only known-exploited findings

```bash
curl "http://127.0.0.1:8000/api/v1/findings?kev_only=true"
```

## CSV imports

Example files are included in `data/`.

Import assets:

```bash
curl -X POST \
  -F "file=@data/assets.csv" \
  http://127.0.0.1:8000/api/v1/imports/assets-csv
```

Import vulnerabilities:

```bash
curl -X POST \
  -F "file=@data/vulnerabilities.csv" \
  http://127.0.0.1:8000/api/v1/imports/vulnerabilities-csv
```

## Repository structure

```text
vulnprior/
├── app/
│   ├── routers/
│   │   ├── assets.py
│   │   ├── dashboard.py
│   │   ├── findings.py
│   │   ├── imports.py
│   │   └── vulnerabilities.py
│   ├── services/
│   │   ├── finding_service.py
│   │   └── risk_engine.py
│   ├── static/
│   │   ├── app.js
│   │   ├── index.html
│   │   └── style.css
│   ├── config.py
│   ├── database.py
│   ├── main.py
│   ├── models.py
│   └── schemas.py
├── data/
├── scripts/
│   └── seed_demo.py
├── tests/
├── .github/workflows/ci.yml
├── docker-compose.yml
├── Dockerfile
├── Makefile
└── requirements.txt
```

## Suggested roadmap

### v1.1
- Connect to FIRST EPSS data
- Import CISA Known Exploited Vulnerabilities
- Add CVE enrichment
- Add asset tags and business impact dimensions

### v1.2
- Add authentication and RBAC
- Risk acceptance workflow
- Due-date tracking and SLA breaches
- Remediation owner notifications
- Audit log

### v2
- SBOM ingestion
- Multi-tenant organizations
- Executive PDF reporting
- Trend charts
- Jira / ServiceNow integrations
- Risk treatment plans and exception workflow

## Portfolio talking points

In an interview, do not present this as "another vulnerability scanner."

Present the design problem:

1. Security teams can have thousands of findings.
2. CVSS alone does not express business priority.
3. Exploitation context changes urgency.
4. Asset criticality changes business impact.
5. Decision-makers need an explainable remediation queue.
6. VulnPrior makes the prioritization logic visible and auditable.

That framing is closer to a CISO / security governance responsibility than pure scanning.

## Security notes

- Demo CVEs are synthetic.
- No offensive scanning is performed.
- Do not store production secrets in `.env`.
- Replace the sample scoring model with an organization-approved methodology before real-world use.
- Add authentication and authorization before exposing this service outside a local development environment.

## License

MIT.
