"""
OSIG Backend - Celery Application Configuration

Defines the Celery app instance and its settings.
"""
import os
from celery import Celery

# Get Redis URL from environment or use default
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Create Celery app
celery_app = Celery(
    "osig_workers",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.workers.scan_tasks"]
)

# Optional configuration settings
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)
