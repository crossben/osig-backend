"""
Create / update OSIG's plans and prices in Yoon from the plans table.

    .venv/bin/python scripts/yoon_sync_catalog.py            # dry run: prints what it would do
    .venv/bin/python scripts/yoon_sync_catalog.py --apply    # does it (idempotent: safe to re-run)

Reads YOON_API_URL / YOON_API_KEY from settings (.env). Never prints the key.
"""
import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
logging.disable(logging.INFO)  # keep SQL echo out of the report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--apply", action="store_true", help="perform the operations (default: dry run)")
    args = parser.parse_args(argv)

    import app.models  # noqa: F401
    from app.core.config import settings
    from app.db.session import SessionLocal
    from app.services import billing_service, yoon_catalog

    if not (settings.YOON_API_URL and settings.YOON_API_KEY):
        print("YOON_API_URL / YOON_API_KEY are not set", file=sys.stderr)
        return 1
    db = SessionLocal()
    try:
        desired = yoon_catalog.desired_catalog(db)
    finally:
        db.close()
    yoon = billing_service.yoon_client()
    existing = yoon_catalog.fetch_existing(yoon)
    ops = yoon_catalog.plan_operations(desired, existing)

    print(f"Yoon at {settings.YOON_API_URL}: {len(existing)} plan(s) today")
    for spec in desired:
        print(f"  OSIG {spec.slug}: " + "; ".join(p.label() for p in spec.prices))
    if not ops:
        print("Nothing to do: Yoon's catalog matches OSIG.")
        return 0
    print(("Doing" if args.apply else "Would do") + f" {len(ops)} operation(s):")
    for op in ops:
        print(f"  - {op.detail}   [Idempotency-Key {op.idempotency_key()}]")
    if not args.apply:
        print("Dry run: nothing was changed. Re-run with --apply.")
        return 0
    yoon_catalog.apply(yoon, ops)
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
