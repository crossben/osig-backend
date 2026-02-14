"""
OSIG Backend - API v1 Router

Main router that combines all API v1 endpoints.
"""
from fastapi import APIRouter
from app.api.v1 import auth, scans

# Create main API router
api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router)
api_router.include_router(scans.router)

# Add more routers as we build them
# api_router.include_router(reports.router)
