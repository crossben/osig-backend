"""
Billing plumbing shared by the subscription code (app/services/subscription_service.py).

Plans are prepaid Yoon 0.3.0 subscriptions: Yoon owns invoices, renewals, grace,
reminders and expiry; OSIG grants access only from Yoon's signed subscription
events. The old one-off payments (the `payments` table) are history only.
"""
from app.core.config import settings

# Countries Yoon's providers collect in; anything else pays by card (Stripe) in USD
XOF_COUNTRIES = {"SN", "CI", "BJ", "BF", "ML", "TG", "NE", "GW"}


def enabled() -> bool:
    return bool(settings.YOON_API_URL and settings.YOON_API_KEY and settings.YOON_WEBHOOK_SECRET)


def yoon_client():
    from yoonpay import Yoon
    return Yoon(settings.YOON_API_URL, settings.YOON_API_KEY)


def currency_for(country: str) -> str:
    return "XOF" if (country or "").upper() in XOF_COUNTRIES else "USD"
