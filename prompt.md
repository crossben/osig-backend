The backend must be built with:

Python 3.10+

FastAPI

PostgreSQL

SQLAlchemy or SQLModel

Alembic for migrations

Redis for cache + queue

Celery or RQ for background jobs

Pydantic

JWT authentication

Docker + docker-compose

🚨 CRITICAL ARCHITECTURE RULES

This backend is the ONLY backend for OSIG

The Next.js frontend must ONLY consume this API

Enable CORS

All long-running scans MUST run in background workers

Use environment variables for secrets and config

Never scrape private content or bypass logins

🎯 CORE FEATURES TO IMPLEMENT

1. Authentication & Users

Register

Login

JWT access tokens

Get current user

User plans (free, pro, enterprise)

Daily scan limits per plan

Password hashing (bcrypt or argon2)

1. Scan Management

Endpoints:

POST /scans → create new scan

GET /scans → list user scans (pagination, filters)

GET /scans/{id} → get scan details

GET /scans/{id}/results → get scan results

GET /scans/{id}/sources → get sources used

Scan fields:

target_type: email | username | domain | phone

target_value: string

scan_type: quick | deep

status: pending | running | completed | failed

progress: 0–100

When a scan is created:

Validate user limits

Create DB record

Enqueue background job

1. OSINT Modules (v1, FREE TOOLS ONLY)

Implement modular OSINT services using ONLY these free, public tools:

✅ EmailIntelService

Holehe (email account existence on public services)

Gravatar (public avatar/profile via email hash)

Output:

Found services list

Public profile URLs (if any)

Risk flags (basic)

✅ UsernameIntelService

Sherlock (public username search across platforms)

WhatsMyName dataset checks

Output:

Platform name

Profile URL

Found: true/false

✅ DomainIntelService

Amass (subdomains, footprint)

TheHarvester (emails, hosts from public sources)

python-whois (WHOIS info)

dnspython (DNS records)

Output:

Subdomains

Emails found

WHOIS summary

DNS records

✅ PhoneIntelService (LIGHT, METADATA ONLY)

phonenumbers (country, type, possible carrier)

Output:

Country

Number type (mobile, fixed, etc.)

Carrier (if available)

1. Background Workers

Use Celery or RQ with Redis

One job = one scan

Workflow:

Mark scan as running

Run relevant modules based on target_type

After each module:

Save results (JSON)

Save sources used

Update scan progress

Mark scan completed or failed

1. Results & Sources Storage

Store results in JSONB

Store sources separately

Endpoints to fetch:

Normalized results

Raw JSON

Sources list

1. Reports

Endpoints:

POST /reports/{scan_id} → generate report (pdf or json)

GET /reports → list user reports

GET /reports/{id}/download → download file

Use ReportLab or WeasyPrint for PDF generation

PDF must include:

Scan summary

Findings

Sources

Legal disclaimer (“Public info only”)

1. Audit Logs & Safety

Log:

scan_created

report_generated

login

Store:

user_id

action

target

ip_address

timestamp

Enforce:

Rate limiting

Daily scan limits

Disclaimer acceptance on scan creation

1. Database Schema

Implement tables:

users

scans

scan_modules

results

sources

reports

audit_logs

Use Alembic migrations.

1. Project Structure
backend/
  app/
    main.py
    core/
    api/
    models/
    schemas/
    services/
    workers/
    osint/
      email_intel.py
      username_intel.py
      domain_intel.py
      phone_intel.py
    db/
  alembic/
  Dockerfile
  docker-compose.yml

2. API Quality

OpenAPI docs enabled

Proper HTTP status codes

Pagination

Input validation with Pydantic

Structured error responses

🛡️ PRODUCT POSITIONING

Never mention “hacking”

Always say “publicly available information”

Include legal disclaimer in relevant responses

📦 PYTHON DEPENDENCIES TO USE

Backend:

fastapi

uvicorn

sqlalchemy or sqlmodel

alembic

psycopg2 or asyncpg

redis

celery or rq

passlib[bcrypt] or argon2-cffi

python-jose or pyjwt

httpx or requests

reportlab or weasyprint

OSINT:

sherlock (as submodule or subprocess)

holehe

whatsmyname dataset

amass (CLI)

theHarvester (CLI or lib)

python-whois

dnspython

phonenumbers

✅ DELIVERABLES

Fully working FastAPI backend

Background workers executing OSINT scans

PostgreSQL schema + migrations

Modular OSINT services using ONLY free tools

Secure JWT auth

Ready for Next.js frontend consumption

Build this as a real, production-ready, legal OSINT SaaS backend.
