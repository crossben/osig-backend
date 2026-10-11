"""
What each plan allows, in one place. Limits come from the plans table (editable
in the admin console); DEFAULT_PLANS is the seed and the fallback when a row
is missing (e.g. in tests).

Callers raise PlanLimitReached, which the API turns into 402 with a message
that tells the user what to upgrade to.
"""
from typing import Any, Dict, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.user import User

UNLIMITED = 1_000_000

# Prices are minor units per currency and period (XOF has no minor unit; USD in cents).
DEFAULT_PLANS: Dict[str, Dict[str, Any]] = {
    "free": {
        "name": "Free", "rank": 0, "self_serve": False, "prices": {},
        "limits": {"daily_scans": 10, "deep_scans": False, "watches": 2, "min_watch_interval_hours": 24,
                   "bulk_max": 0, "exports": False, "sharing": False, "api_keys": 0, "max_retention_days": None,
                   "identities": 3, "household": 0},
    },
    "pro": {
        "name": "Pro", "rank": 1, "self_serve": True,
        "prices": {"XOF": {"month": 5000, "quarter": 14000, "half": 27000, "year": 50000},
                   "USD": {"month": 900, "quarter": 2500, "half": 4800, "year": 9000}},
        "limits": {"daily_scans": 200, "deep_scans": True, "watches": 20, "min_watch_interval_hours": 6,
                   "bulk_max": 50, "exports": True, "sharing": True, "api_keys": 3, "max_retention_days": None,
                   "identities": 10, "household": 5},
    },
    "enterprise": {
        # Not sold online ("contact us"): the prices exist so Yoon can grant it (comp) and rank it
        "name": "Enterprise", "rank": 2, "self_serve": False,
        "prices": {"XOF": {"month": 25000, "year": 250000}, "USD": {"month": 4900, "year": 49000}},
        "limits": {"daily_scans": UNLIMITED, "deep_scans": True, "watches": 100, "min_watch_interval_hours": 6,
                   "bulk_max": 50, "exports": True, "sharing": True, "api_keys": 10, "max_retention_days": None,
                   "identities": 25, "household": 10},
    },
}

PERIODS = {  # period -> (days, months it is priced as when no explicit price exists)
    "month": (30, 1),
    "quarter": (90, 3),
    "half": (180, 6),
    "year": (365, 10),  # a year costs ten months
}


def plan_row(db: Session, slug: str):
    from app.models.billing import Plan
    return db.query(Plan).filter(Plan.slug == slug).first()


def plan_info(db: Session, slug: str) -> Dict[str, Any]:
    row = plan_row(db, slug)
    base = DEFAULT_PLANS.get(slug, DEFAULT_PLANS["free"])
    if not row:
        return {"slug": slug, "is_active": True, **base}
    return {"slug": row.slug, "name": row.name, "rank": row.rank, "self_serve": row.self_serve,
            "is_active": row.is_active, "prices": row.prices or {},
            "limits": {**base["limits"], **(row.limits or {})}}


def price_for(info: Dict[str, Any], currency: str, period: str) -> Optional[int]:
    by_period = (info.get("prices") or {}).get(currency) or {}
    if period in by_period:
        return int(by_period[period])
    if "month" in by_period and period in PERIODS:
        return int(by_period["month"]) * PERIODS[period][1]
    return None


def limits(db: Session, user: User) -> Dict[str, Any]:
    plan = user.plan.value if hasattr(user.plan, "value") else str(user.plan)
    return plan_info(db, plan)["limits"]


def limit(db: Session, user: User, key: str):
    return limits(db, user).get(key)


class PlanLimitReached(HTTPException):
    def __init__(self, message: str):
        super().__init__(status_code=status.HTTP_402_PAYMENT_REQUIRED,
                         detail=f"{message} Upgrade your plan under Billing.")


def require(db: Session, user: User, feature: str, message: str) -> None:
    """For on/off features: deep_scans, exports, sharing."""
    if not limit(db, user, feature):
        raise PlanLimitReached(message)


def require_below(db: Session, user: User, key: str, current: int, message: str) -> None:
    """For counted limits: watches, api_keys, bulk_max..."""
    allowed = limit(db, user, key) or 0
    if current >= allowed:
        raise PlanLimitReached(message.format(limit=allowed))
