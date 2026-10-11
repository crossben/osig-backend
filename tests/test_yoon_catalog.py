"""OSIG plans -> Yoon catalog: pure planning, idempotent keys, and the script's dry run."""
from types import SimpleNamespace

import pytest

from app.models.billing import Plan
from app.services import yoon_catalog
from app.services.yoon_catalog import PlanSpec, PriceSpec, plan_operations


@pytest.fixture(autouse=True)
def default_plans(db):
    """Other tests edit plans through the admin API: start from the seeded defaults."""
    db.query(Plan).delete()
    db.commit()


def _desired():
    return [PlanSpec("pro", "Pro", {"daily_scans": 200}, [
        PriceSpec("XOF", 5000, "month", 1), PriceSpec("XOF", 14000, "month", 3), PriceSpec("XOF", 50000, "year", 1)])]


def _yoon_plan(prices, features=None, name="Pro", active=True):
    return {"id": "plan_1", "slug": "pro", "name": name, "active": active,
            "features": features if features is not None else {"daily_scans": 200},
            "prices": [{"id": f"price_{i}", "currency": c, "amount": a, "interval": iv, "interval_count": n,
                        "active": act} for i, (c, a, iv, n, act) in enumerate(prices)]}


def test_desired_catalog_uses_calendar_periods_and_skips_free(db):
    plans = {p.slug: p for p in yoon_catalog.desired_catalog(db)}
    assert "free" not in plans and {"pro", "enterprise"} <= set(plans)
    slots = {(p.interval, p.interval_count) for p in plans["pro"].prices}
    assert slots == {("month", 1), ("month", 3), ("month", 6), ("year", 1)}
    assert plans["pro"].features["daily_scans"] == 200 and plans["pro"].features["deep_scans"] is True
    ent = {(p.currency, p.interval): p.amount for p in plans["enterprise"].prices}
    assert ent == {("XOF", "month"): 25000, ("XOF", "year"): 250000, ("USD", "month"): 4900, ("USD", "year"): 49000}


def test_enterprise_costs_more_per_day_than_any_pro_price(db):
    plans = {p.slug: p for p in yoon_catalog.desired_catalog(db)}
    days = {("month", 1): 30.44, ("month", 3): 91.31, ("month", 6): 182.62, ("year", 1): 365.25}
    for cur in ("XOF", "USD"):
        pro_max = max(p.amount / days[(p.interval, p.interval_count)] for p in plans["pro"].prices if p.currency == cur)
        ent_min = min(p.amount / days[(p.interval, p.interval_count)] for p in plans["enterprise"].prices if p.currency == cur)
        assert ent_min > pro_max, cur


def test_new_plan_is_created_with_all_prices():
    ops = plan_operations(_desired(), [])
    assert [o.kind for o in ops] == ["create_plan"]
    assert len(ops[0].payload["prices"]) == 3 and ops[0].idempotency_key() == "osig-plan-pro"


def test_matching_catalog_needs_nothing():
    existing = [_yoon_plan([("XOF", 5000, "month", 1, True), ("XOF", 14000, "month", 3, True),
                            ("XOF", 50000, "year", 1, True), ("XOF", 4000, "month", 1, False)])]
    assert plan_operations(_desired(), existing) == []


def test_changed_amount_adds_new_price_and_archives_old_one():
    existing = [_yoon_plan([("XOF", 4500, "month", 1, True), ("XOF", 14000, "month", 3, True),
                            ("XOF", 50000, "year", 1, True), ("USD", 900, "month", 1, True)])]
    ops = plan_operations(_desired(), existing)
    kinds = sorted((o.kind, o.price.amount if o.price else o.price_id) for o in ops)
    assert kinds == [("add_price", 5000), ("archive_price", "price_0"), ("archive_price", "price_3")]
    add = next(o for o in ops if o.kind == "add_price")
    assert add.idempotency_key() == "osig-price-pro-XOF-month1-5000"


def test_features_name_and_archived_plan_are_updated():
    existing = [_yoon_plan([("XOF", 5000, "month", 1, True), ("XOF", 14000, "month", 3, True),
                            ("XOF", 50000, "year", 1, True)], features={"daily_scans": 100}, name="Pro old",
                           active=False)]
    ops = plan_operations(_desired(), existing)
    assert [o.kind for o in ops] == ["update_plan"]
    assert set(ops[0].payload) == {"name", "features", "active"}
    assert ops[0].idempotency_key() == plan_operations(_desired(), existing)[0].idempotency_key()


def test_script_dry_run_prints_and_changes_nothing(monkeypatch, capsys):
    import scripts.yoon_sync_catalog as script
    from app.core.config import settings
    from app.services import billing_service
    monkeypatch.setattr(settings, "YOON_API_URL", "http://yoon.test")
    monkeypatch.setattr(settings, "YOON_API_KEY", "yk_test_secret")
    calls = []

    class FakePlans:
        def list_plans(self, **kw):
            return SimpleNamespace(data=[], next_cursor=None)

        def create_plan(self, *a, **k):
            calls.append("create")

    fake = SimpleNamespace(plans=lambda: FakePlans(), call=lambda f: f())
    monkeypatch.setattr(billing_service, "yoon_client", lambda: fake)
    assert script.main([]) == 0
    out = capsys.readouterr().out
    assert "Would do" in out and "create plan pro" in out and "create plan enterprise" in out
    assert "XOF 5000 / month" in out and "XOF 14000 / 3 x month" in out
    assert "yk_test_secret" not in out and calls == []
