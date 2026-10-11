"""
OSIG's plans table -> Yoon 0.3.0 catalog (plans + prices).

- Every OSIG plan with at least one price becomes a Yoon plan with the same slug;
  its `features` are OSIG's limits, so subscriptions carry them.
  Free has no price and stays "no subscription".
- Periods are calendar periods: month, quarter = month x 3, half = month x 6, year.
- Yoon prices are immutable: a changed amount is a new price, and the old one is
  archived (`active: false`); existing subscriptions keep their price.

plan_operations() is pure (tested with fakes); apply() performs the operations
with deterministic Idempotency-Keys, so re-running never duplicates anything.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

PERIODS: Dict[str, Tuple[str, int]] = {
    "month": ("month", 1),
    "quarter": ("month", 3),
    "half": ("month", 6),
    "year": ("year", 1),
}


@dataclass(frozen=True)
class PriceSpec:
    currency: str
    amount: int
    interval: str
    interval_count: int

    @property
    def slot(self) -> Tuple[str, str, int]:
        return self.currency, self.interval, self.interval_count

    def label(self) -> str:
        n = f"{self.interval_count} x " if self.interval_count != 1 else ""
        return f"{self.currency} {self.amount} / {n}{self.interval}"


@dataclass
class PlanSpec:
    slug: str
    name: str
    features: Dict[str, Any]
    prices: List[PriceSpec] = field(default_factory=list)


@dataclass
class Operation:
    kind: str  # create_plan | update_plan | add_price | archive_price
    slug: str
    detail: str
    plan_id: Optional[str] = None
    price: Optional[PriceSpec] = None
    price_id: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)

    def idempotency_key(self) -> str:
        if self.kind == "create_plan":
            return f"osig-plan-{self.slug}"
        if self.kind == "add_price":
            p = self.price
            return f"osig-price-{self.slug}-{p.currency}-{p.interval}{p.interval_count}-{p.amount}"
        if self.kind == "archive_price":
            return f"osig-archive-{self.price_id}"
        import hashlib
        import json
        digest = hashlib.sha256(json.dumps(self.payload, sort_keys=True, default=str).encode()).hexdigest()[:16]
        return f"osig-plan-update-{self.slug}-{digest}"


def desired_catalog(db: Session) -> List[PlanSpec]:
    """Read OSIG's plans (table, or defaults when a row is missing)."""
    from app.services.plan_limits import DEFAULT_PLANS, plan_info
    out = []
    for slug in sorted(DEFAULT_PLANS, key=lambda s: DEFAULT_PLANS[s]["rank"]):
        info = plan_info(db, slug)
        prices = [PriceSpec(cur.upper(), int(amount), *PERIODS[period])
                  for cur, by_period in sorted((info.get("prices") or {}).items())
                  for period, amount in sorted(by_period.items()) if period in PERIODS]
        if prices and info.get("is_active", True):
            out.append(PlanSpec(slug=slug, name=info["name"], features=info["limits"], prices=prices))
    return out


def _get(obj, key):
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key)


def _interval(value) -> str:
    return getattr(value, "value", value)


def plan_operations(desired: List[PlanSpec], existing: List[Any]) -> List[Operation]:
    """What to do so Yoon's catalog matches OSIG. `existing` = Yoon plans (models or dicts)."""
    by_slug = {_get(p, "slug"): p for p in existing}
    ops: List[Operation] = []
    for spec in desired:
        current = by_slug.get(spec.slug)
        if current is None:
            ops.append(Operation("create_plan", spec.slug,
                                 f"create plan {spec.slug} ({spec.name}) with {len(spec.prices)} prices: "
                                 + "; ".join(p.label() for p in spec.prices),
                                 payload={"slug": spec.slug, "name": spec.name, "features": spec.features,
                                          "prices": spec.prices}))
            continue
        plan_id = _get(current, "id")
        changes = {}
        if _get(current, "name") != spec.name:
            changes["name"] = spec.name
        if (_get(current, "features") or {}) != spec.features:
            changes["features"] = spec.features
        if not _get(current, "active"):
            changes["active"] = True
        if changes:
            ops.append(Operation("update_plan", spec.slug, f"update plan {spec.slug}: {', '.join(sorted(changes))}",
                                 plan_id=plan_id, payload=changes))
        active = {}
        for price in _get(current, "prices") or []:
            if _get(price, "active"):
                key = (_get(price, "currency"), _interval(_get(price, "interval")), _get(price, "interval_count"))
                active.setdefault(key, []).append(price)
        wanted = {p.slot: p for p in spec.prices}
        for slot, p in wanted.items():
            same = [x for x in active.get(slot, []) if _get(x, "amount") == p.amount]
            if not same:
                ops.append(Operation("add_price", spec.slug, f"add price {spec.slug}: {p.label()}",
                                     plan_id=plan_id, price=p))
        for slot, prices in active.items():
            for x in prices:
                if slot not in wanted or _get(x, "amount") != wanted[slot].amount:
                    ops.append(Operation("archive_price", spec.slug,
                                         f"archive price {_get(x, 'id')} ({slot[0]} {_get(x, 'amount')} / "
                                         f"{slot[2]} x {slot[1]})", plan_id=plan_id, price_id=_get(x, "id")))
    return ops


def fetch_existing(yoon) -> List[Any]:
    plans, cursor = [], None
    while True:
        page = yoon.call(lambda: yoon.plans().list_plans(starting_after=cursor, limit=100))
        plans.extend(page.data)
        cursor = getattr(page, "next_cursor", None)
        if not cursor:
            return plans


def apply(yoon, ops: List[Operation]) -> None:
    from yoonpay.generated import CreatePlanRequest, PriceInput, UpdatePlanRequest, UpdatePriceRequest

    def price_input(p: PriceSpec):
        return PriceInput(currency=p.currency, amount=p.amount, interval=p.interval, interval_count=p.interval_count)

    created: Dict[str, str] = {}
    for op in ops:
        key = op.idempotency_key()
        if op.kind == "create_plan":
            req = CreatePlanRequest(slug=op.slug, name=op.payload["name"], features=op.payload["features"],
                                    prices=[price_input(p) for p in op.payload["prices"]])
            plan = yoon.call(lambda: yoon.plans().create_plan(key, req))
            created[op.slug] = plan.id
        elif op.kind == "update_plan":
            req = UpdatePlanRequest(**op.payload)
            yoon.call(lambda: yoon.plans().update_plan(op.plan_id, key, req))
        elif op.kind == "add_price":
            yoon.call(lambda: yoon.plans().create_price(op.plan_id or created[op.slug], key, price_input(op.price)))
        elif op.kind == "archive_price":
            yoon.call(lambda: yoon.plans().update_price(op.price_id, key, UpdatePriceRequest(active=False)))
