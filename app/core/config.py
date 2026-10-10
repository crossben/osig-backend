"""
OSIG Backend - Configuration Settings

Loads environment variables and provides app-wide configuration.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Project
    PROJECT_NAME: str = "OSIG - Open Source Intelligence Gathering"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = True
    
    # Database
    DATABASE_URL: str
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Security
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14

    # Scan execution: "celery" (worker; survives API restarts) or "thread" (dev only)
    SCAN_EXECUTOR: str = "celery"
    # Active port scanning of the target's hosts on deep domain scans (opt-in)
    ENABLE_PORT_SCAN: bool = False

    # Sign in with Google (OAuth 2.0). Off unless both are set.
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    # Must match an "Authorized redirect URI" in Google Cloud. Goes through the
    # Next.js proxy so the OAuth cookie stays on the frontend's origin.
    GOOGLE_REDIRECT_URI: str = "http://localhost:3000/api/v1/auth/google/callback"
    FRONTEND_URL: str = "http://localhost:3000"

    # Optional source API keys
    HIBP_API_KEY: str = ""
    EMAILREP_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    URLSCAN_API_KEY: str = ""
    GITHUB_TOKEN: str = ""
    ABUSEIPDB_API_KEY: str = ""
    OPENCORPORATES_API_TOKEN: str = ""
    NUMVERIFY_API_KEY: str = ""

    # Rate limiting (per client IP) for auth and scan creation
    RATE_LIMIT_AUTH: str = "10/minute"
    RATE_LIMIT_SCANS: str = "20/hour"
    
    # CORS
    CORS_ORIGINS: str = "http://localhost:3000"
    
    # User Plan Limits
    FREE_DAILY_SCANS: int = 150
    PRO_DAILY_SCANS: int = 50
    ENTERPRISE_DAILY_SCANS: int = 999999
    
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True
    )
    
    @property
    def cors_origins_list(self) -> List[str]:
        """Convert CORS_ORIGINS string to list."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]


# Global settings instance
settings = Settings()
