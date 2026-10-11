"""Grant (or with --revoke, remove) admin rights: python scripts/make_admin.py you@example.com"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.session import SessionLocal  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.user import User  # noqa: E402


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        sys.exit(__doc__)
    db = SessionLocal()
    user = db.query(User).filter(User.email == args[0].strip().lower()).first()
    if not user:
        sys.exit(f"No user with email {args[0]}")
    user.is_superuser = "--revoke" not in sys.argv
    db.commit()
    print(f"{user.email}: admin={user.is_superuser}")


if __name__ == "__main__":
    main()
