"""
OSIG Backend - Database Base

Import all models for Alembic to detect them.
"""
from app.db.session import Base
from app.models import *  # noqa
