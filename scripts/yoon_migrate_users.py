"""
Move users with a running paid plan onto Yoon subscriptions (operator comp until their
current end date, or open-ended). See app/services/yoon_migration.py.

    .venv/bin/python scripts/yoon_migrate_users.py            # dry run: lists every user, plan, price, end date
    .venv/bin/python scripts/yoon_migrate_users.py --apply    # does it (idempotent per user)

Needs YOON_API_URL, YOON_API_KEY, and for --apply YOON_ADMIN_TOKEN + YOON_APPLICATION_ID.
Never prints keys, tokens or full e-mail addresses.
"""
import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
logging.disable(logging.INFO)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Migrate paid OSIG users to Yoon subscriptions")
    parser.add_argument("--apply", action="store_true", help="perform it (default: dry run)")
    args = parser.parse_args(argv)

    import app.models  # noqa: F401
    from app.core.config import settings
    from app.db.session import SessionLocal
    from app.services import billing_service, yoon_catalog, yoon_migration

    if not (settings.YOON_API_URL and settings.YOON_API_KEY):
        print("YOON_API_URL / YOON_API_KEY are not set", file=sys.stderr)
        return 1
    yoon = billing_service.yoon_client()
    catalog = yoon_catalog.fetch_existing(yoon)
    db = SessionLocal()
    try:
        rows = yoon_migration.plan_migration(db, catalog)
        todo = [r for r in rows if r.action == "migrate"]
        print(f"{len(rows)} user(s) on a paid plan; {len(todo)} to migrate")
        for r in rows:
            line = (f"  {r.action:<7} {r.email:<28} {r.plan:<10} until {r.until_text:<21} "
                    f"{r.currency} {r.period:<7} price {r.price_id or '-'}  country {r.country}")
            print(line + (f"  ({r.reason})" if r.reason else ""))
        if not args.apply:
            print("Dry run: nothing was changed. Re-run with --apply.")
            return 0
        if not (settings.YOON_ADMIN_TOKEN and settings.YOON_APPLICATION_ID):
            print("--apply needs YOON_ADMIN_TOKEN and YOON_APPLICATION_ID", file=sys.stderr)
            return 1
        admin = yoon_migration.YoonAdmin(settings.YOON_API_URL, settings.YOON_API_KEY,
                                         settings.YOON_ADMIN_TOKEN, settings.YOON_APPLICATION_ID)
        failed = 0
        for r in todo:
            try:
                sub_id = yoon_migration.migrate(db, admin, r)
                print(f"  migrated {r.email} -> {sub_id}")
            except Exception as e:
                db.rollback()
                failed += 1
                print(f"  FAILED {r.email}: {e}", file=sys.stderr)
        return 1 if failed else 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
