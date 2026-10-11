"""
OSIG Backend - Celery Application Configuration

Defines the Celery app instance and its settings.
"""
from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

# Same .env-backed settings as the API, so worker and API share one broker
REDIS_URL = settings.REDIS_URL

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
    # A scan is long and not safely re-entrant mid-way: ack only when done,
    # take one at a time, and requeue if the worker dies under it
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=900,
    task_time_limit=960,
    broker_connection_retry_on_startup=True,
)

# Scheduled re-scans (run `celery beat`, or the worker with -B in dev)
celery_app.conf.beat_schedule = {
    "run-due-watches": {"task": "osig.run_due_watches", "schedule": 300.0},
    "purge-expired-data": {"task": "osig.purge_expired_data", "schedule": 6 * 3600.0},
    "expire-plans": {"task": "osig.expire_plans", "schedule": 3600.0},
    "reconcile-payments": {"task": "osig.reconcile_payments", "schedule": 300.0},  # old one-off payments still pending
    "reconcile-subscriptions": {"task": "osig.reconcile_subscriptions", "schedule": 6 * 3600.0},
    "billing-reminders": {"task": "osig.billing_reminders", "schedule": 24 * 3600.0},
    "weekly-digest": {"task": "osig.weekly_digest", "schedule": crontab(minute=0, hour=8, day_of_week="mon")},
}
