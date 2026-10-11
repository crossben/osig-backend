"""
OSIG Backend - Meta

Which optional sources this deployment has enabled (keys never leave the server).
"""
from fastapi import APIRouter, Depends

from app.core.config import settings
from app.core.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/meta", tags=["Meta"])


@router.get("/sources")
def optional_sources(_: User = Depends(get_current_user)):
    return [
        {"name": "Have I Been Pwned", "enabled": bool(settings.HIBP_API_KEY), "env": "HIBP_API_KEY",
         "adds": "Breach search with full breach details (XposedOrNot is used without it)"},
        {"name": "EmailRep", "enabled": bool(settings.EMAILREP_API_KEY), "env": "EMAILREP_API_KEY",
         "adds": "Email reputation without the anonymous rate limit"},
        {"name": "VirusTotal", "enabled": bool(settings.VIRUSTOTAL_API_KEY), "env": "VIRUSTOTAL_API_KEY",
         "adds": "Security vendors' verdicts on a domain"},
        {"name": "URLScan", "enabled": bool(settings.URLSCAN_API_KEY), "env": "URLSCAN_API_KEY",
         "adds": "Scans of subdomains too, and a higher search limit"},
        {"name": "GitHub", "enabled": bool(settings.GITHUB_TOKEN), "env": "GITHUB_TOKEN",
         "adds": "Leaked-secret search in public code; higher rate limit for commit-author search"},
        {"name": "AbuseIPDB", "enabled": bool(settings.ABUSEIPDB_API_KEY), "env": "ABUSEIPDB_API_KEY",
         "adds": "Abuse reports and confidence score for IP targets"},
        {"name": "OpenCorporates", "enabled": bool(settings.OPENCORPORATES_API_TOKEN), "env": "OPENCORPORATES_API_TOKEN",
         "adds": "Company register search for organization targets (deep)"},
        {"name": "numverify", "enabled": bool(settings.NUMVERIFY_API_KEY), "env": "NUMVERIFY_API_KEY",
         "adds": "Live validity, carrier and line type for phone numbers"},
        {"name": "OpenSanctions", "enabled": bool(settings.OPENSANCTIONS_API_KEY), "env": "OPENSANCTIONS_API_KEY",
         "adds": "Sanctions, PEP and crime-list screening (commercial use needs their licence)"},
        {"name": "AlienVault OTX", "enabled": bool(settings.OTX_API_KEY), "env": "OTX_API_KEY",
         "adds": "Threat reports and malware linked to domains and IPs"},
        {"name": "GreyNoise", "enabled": bool(settings.GREYNOISE_API_KEY), "env": "GREYNOISE_API_KEY",
         "adds": "Licensed GreyNoise lookups (the keyless community API is for non-commercial use)"},
        {"name": "ransomware.live", "enabled": settings.ENABLE_RANSOMWARE_LIVE, "env": "ENABLE_RANSOMWARE_LIVE",
         "adds": "Ransomware leak-site claims naming a domain or organization"},
        {"name": "Active port scan", "enabled": settings.ENABLE_PORT_SCAN, "env": "ENABLE_PORT_SCAN",
         "adds": "Nmap scan of the target's hosts on deep scans (probes the target directly)"},
    ]
