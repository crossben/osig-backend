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

    # Outgoing email (verification, password reset, watch alerts).
    # Without SMTP_HOST, emails are only recorded in the mail_outbox table.
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "OSIG <no-reply@localhost>"
    SMTP_STARTTLS: bool = True

    # Delete scans older than this for everyone (0 = keep; users can set shorter)
    DATA_RETENTION_DAYS: int = 0

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
    RATE_LIMIT_EMAIL: str = "5/hour"  # forgot-password and resend-verification

    # Billing through Yoon (self-hosted payment gateway). Plan limits live in the plans table.
    YOON_API_URL: str = ""
    YOON_API_KEY: str = ""
    YOON_WEBHOOK_SECRET: str = ""
    BILLING_GRACE_DAYS: int = 2
    BILLING_REMINDER_DAYS: int = 7
    
    # Web Push (VAPID). Empty = push notifications off
    VAPID_PUBLIC_KEY: str = ""
    VAPID_PRIVATE_KEY: str = ""
    VAPID_SUBJECT: str = "mailto:admin@localhost"
    # No SMS provider yet: phone identities stay unverified (and unwatched) while false
    SMS_ENABLED: bool = False
    RATE_LIMIT_FOOTPRINT_REFRESH: str = "3/hour"

    # CORS
    CORS_ORIGINS: str = "http://localhost:3000"
    
    
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
