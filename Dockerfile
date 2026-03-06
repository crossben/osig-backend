# ============================================================
# OSIG Backend — Production Dockerfile
# Python 3.11 slim, multi-stage build
# ============================================================

# ── Stage 1: dependency builder ──────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps needed to compile psycopg2, Pillow, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps into a local prefix so we can copy them
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --prefix=/install --no-cache-dir -r requirements.txt \
    && pip install --prefix=/install --no-cache-dir ddgs


# ── Stage 2: runtime image ───────────────────────────────────
FROM python:3.11-slim AS runtime

# Runtime system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Create app user (no root in production)
RUN useradd -m -u 1001 appuser

USER appuser

WORKDIR /app

# Copy application code
COPY --chown=appuser:appuser . .

# Create directories for reports / storage
RUN mkdir -p /app/storage/reports && chown -R appuser:appuser /app/storage

# Ensure the appuser owns the app directories
USER root
RUN chown -R appuser:appuser /app
USER appuser

# Expose FastAPI port
EXPOSE 8000

# Health check — polls the health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health >/dev/null 2>&1 || exit 1

# Entrypoint: run migrations then start uvicorn
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2"]
