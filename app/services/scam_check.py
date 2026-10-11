"""
"Is this a scam?" quick checker.

Takes whatever the user pasted (a link, a domain, an email address, a phone
number or a whole SMS/WhatsApp message), works out what it is, runs fast
checks concurrently under a hard time budget and returns plain-language
reasons with a severity each. The score is the sum of the reasons' weights
(capped at 100); the verdict follows from it.

Rules:
  - Target-controlled hosts are only ever fetched through app/osint/safe_http
    (non-public addresses are reported, never contacted).
  - Nothing slow: no WhatsMyName, no dorks, no DNS brute force, no dnstwist
    (lookalikes are computed offline against a brand list).
  - Reason codes are stable (the frontend translates them); texts are English.
"""
import concurrent.futures
import hashlib
import ipaddress
import logging
import re
import ssl
import time
import unicodedata
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
import tldextract

from app.osint.safe_http import UnsafeTargetError, public_addresses, safe_get, safe_tls_connect

logger = logging.getLogger(__name__)

BUDGET_SECONDS = 10.0       # hard budget for all network checks of one request
CHECK_TIMEOUT = 6.0         # per network call
MAX_INDICATORS = 5          # URLs/emails/phones checked from one message

SEVERITY_WEIGHT = {"info": 0, "low": 8, "medium": 15, "high": 30, "critical": 50}

# Offline public-suffix snapshot: never fetch the list at request time
_tld = tldextract.TLDExtract(suffix_list_urls=())

# ---------------------------------------------------------------------------
# Reference lists
# ---------------------------------------------------------------------------

# brand -> (official registrable domains, name tokens that identify it)
BRANDS: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...]]] = {
    "Wave": (("wave.com",), ("wave",)),
    "Orange": (("orange.sn", "orange.com", "orange.fr", "orange-money.com"), ("orange", "orangemoney")),
    "Free / Yas": (("free.sn", "yas.sn"), ("freesn", "yas")),
    "Expresso": (("expressotelecom.sn", "expresso.sn"), ("expresso",)),
    "MTN": (("mtn.com", "mtn.ci", "mtn.cm", "mtn.bj"), ("mtn", "momo")),
    "Moov": (("moov-africa.ci", "moov-africa.bj", "moov-africa.tg", "moov.africa"), ("moov",)),
    "Ecobank": (("ecobank.com",), ("ecobank",)),
    "SGBS": (("societegenerale.sn", "sgbs.sn", "societegenerale.com"), ("sgbs", "societegenerale")),
    "CBAO": (("cbao.sn",), ("cbao",)),
    "Banque Atlantique": (("banqueatlantique.net",), ("banqueatlantique", "atlantique")),
    "UBA": (("ubagroup.com",), ("uba",)),
    "PayPal": (("paypal.com", "paypal.me"), ("paypal",)),
    "Apple": (("apple.com", "icloud.com"), ("apple", "icloud", "appleid")),
    "Google": (("google.com", "gmail.com", "google.sn", "youtube.com"), ("google", "gmail")),
    "Microsoft": (("microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"),
                  ("microsoft", "office365", "outlook")),
    "Facebook": (("facebook.com", "fb.com", "meta.com"), ("facebook", "meta")),
    "WhatsApp": (("whatsapp.com", "whatsapp.net", "wa.me"), ("whatsapp",)),
    "Instagram": (("instagram.com",), ("instagram",)),
    "Amazon": (("amazon.com", "amazon.fr"), ("amazon",)),
    "Netflix": (("netflix.com",), ("netflix",)),
    "DHL": (("dhl.com", "dhl.sn"), ("dhl",)),
    "La Poste": (("laposte.fr", "laposte.sn"), ("laposte",)),
    "Gouvernement du Sénégal": (("gouv.sn", "sec.gouv.sn"), ("gouv", "gouvsn")),
    "Impôts (DGID)": (("impotsetdomaines.gouv.sn", "dgid.sn", "impots.gouv.fr"), ("impots", "dgid")),
    "Senelec": (("senelec.sn",), ("senelec",)),
    "SDE / Sen'Eau": (("seneau.sn", "sde.sn"), ("seneau", "sde")),
    "Jumia": (("jumia.sn", "jumia.com", "jumia.ci"), ("jumia",)),
    "Wari": (("wari.com",), ("wari",)),
    "Kpay": (("kpay.sn",), ("kpay",)),
    "Djamo": (("djamo.com", "djamo.ci"), ("djamo",)),
}
# Tokens this short only count as an exact hyphen/dot-separated word
_SHORT_TOKEN = 4

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "tiny.cc", "rb.gy", "s.id", "t.ly", "v.gd", "bl.ink", "lnkd.in", "shorte.st",
    "adf.ly", "bitly.com", "short.io", "urlz.fr", "kutt.it", "qrco.de",
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "link", "gq", "ml", "cf", "tk", "ga", "work", "support", "live", "icu",
    "buzz", "rest", "cam", "monster", "sbs", "cfd", "quest", "shop", "online", "site", "fun", "loan",
    "win", "bid", "review", "country", "kim", "date", "zip", "mov", "info", "vip", "lol",
}
FREE_MAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.fr", "hotmail.com", "hotmail.fr", "outlook.com",
    "outlook.fr", "live.com", "live.fr", "aol.com", "icloud.com", "proton.me", "protonmail.com",
    "gmx.com", "gmx.fr", "mail.com", "yandex.com", "yandex.ru", "zoho.com", "orange.fr",
}
DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwam.com", "sharklasers.com",
    "guerrillamailblock.com", "yopmail.com", "yopmail.fr", "trashmail.com", "dispostable.com",
    "mailnull.com", "fakeinbox.com", "maildrop.cc", "getairmail.com", "10minutemail.com",
    "discard.email", "temp-mail.org", "tempail.com", "emailondeck.com", "mohmal.com", "tempmailo.com",
}
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

# ---------------------------------------------------------------------------
# Message heuristics (EN + FR + common Wolof-French phrasing)
# ---------------------------------------------------------------------------
# (code, severity, text, patterns). Each group counts once, whatever the hits.
MESSAGE_RULES: List[Tuple[str, str, str, List[str]]] = [
    ("msg_code_request", "high",
     "The message asks you to share a code (OTP, PIN or withdrawal code). No real company ever asks for it.",
     [r"envo[iy]e[sz]?[- ]?(moi|nous)? ?(le|ce|votre|ton)? ?code", r"\botp\b", r"code (de )?(retrait|secret|pin|confirmation|validation|v[ée]rification)",
      r"\bpin\b", r"send (me |us )?(the |your )?(code|otp|pin)", r"share (the |your )?(code|otp|pin)",
      r"verification code", r"donne[rz]?[- ]?(moi|nous) (le|ton|votre) code", r"yonnee ma code", r"yonne code bi",
      r"mot de passe", r"password"]),
    ("msg_fee_request", "high",
     "The message asks you to pay a fee or send money before you receive something.",
     [r"frais (de )?(d[ée]blocage|dossier|livraison|activation|traitement|transfert|retrait)", r"transf[ée]r(er|ez|t)",
      r"envo[iy]e[sz]? (de l'|l')?argent", r"send (the )?money", r"processing fee", r"release fee", r"pay (a|the) fee",
      r"payer (les|des) frais", r"d[ée]p[ôo]t (de|initial)", r"recharge[sz]?", r"carte (cadeau|prépayée|prepayee)",
      r"gift ?card", r"yonnee ma xaalis", r"wave (moi|nous)", r"fais un d[ée]p[ôo]t"]),
    ("msg_prize", "high",
     "The message says you have won a prize or lottery you never entered.",
     [r"vous avez ([ée]t[ée] )?gagn[ée]", r"tu as gagn[ée]", r"you('ve| have)? won", r"winner", r"gagnant",
      r"lot(erie|tery)", r"tirage au sort", r"f[ée]licitations?", r"congratulations", r"r[ée]compense",
      r"bonus de", r"cadeau (gratuit|offert)", r"free gift", r"jackpot", r"promo(tion)? sp[ée]ciale"]),
    ("msg_urgency", "medium",
     "The message pressures you to act quickly or threatens a penalty.",
     [r"(sera|va [êe]tre|est) (bloqu[ée]|suspendu|d[ée]sactiv[ée]|ferm[ée]|supprim[ée])", r"dernier (avis|rappel|d[ée]lai)",
      r"(within|in|sous|dans les?) (24|48) ?h", r"urgent", r"imm[ée]diatement", r"immediately", r"aujourd'hui (seulement|m[êe]me)",
      r"will be (blocked|suspended|closed|deactivated|deleted)", r"final (notice|warning)", r"act now", r"expire",
      r"dernier d[ée]lai", r"sans d[ée]lai", r"faute de quoi", r"poursuites", r"account (is )?(locked|suspended)",
      r"compte (bloqu|suspendu|d[ée]sactiv)", r"leegi leegi", r"gaawal"]),
    ("msg_too_good_offer", "medium",
     "The message offers an unrealistic job, loan or investment return.",
     [r"(gagne[rz]?|earn|make) .{0,30}(par|per|a|/) ?(jour|day|semaine|week|heure|hour)",
      r"(investi(ssement|r|ssez)|invest(ment)?) .{0,40}(garanti|guaranteed|double|x2|x10|%)", r"double[rz]? (votre|ton|your) (argent|money)",
      r"travail (à|a) domicile", r"work from home", r"recrutement (imm[ée]diat|urgent)", r"sans (exp[ée]rience|dipl[ôo]me)",
      r"pr[êe]t (rapide|sans|imm[ée]diat)", r"(crypto|bitcoin|forex|trading).{0,40}(profit|gain|b[ée]n[ée]fice|rendement)",
      r"revenu passif", r"passive income", r"\b\d{2,3} ?% (de |of )?(profit|rendement|return|int[ée]r[êe]t)"]),
    ("msg_link_request", "low",
     "The message asks you to click a link or open a page.",
     [r"cliqu(e|ez|er)", r"click", r"tap (the|this) link", r"lien ci-dessous", r"suivez (ce|le) lien", r"visit(ez)?",
      r"connecte[rz]?[- ]vous", r"log ?in", r"mettre à jour vos", r"update your", r"confirm(ez|er)? (votre|vos|your)",
      r"v[ée]rifie[rz]? (votre|vos|your)"]),
    ("msg_call_request", "low",
     "The message asks you to call or message a number.",
     [r"appele[rz]", r"rappele[rz]", r"call (us|me|this|now)", r"contact(ez|e)? (le|ce|nous|moi)", r"whatsapp (au|moi|nous)",
      r"[ée]cri(s|vez)[- ]?(moi|nous)", r"woo ma", r"wotal ma"]),
]
_MESSAGE_RES = [(c, s, t, [re.compile(p, re.I) for p in pats]) for c, s, t, pats in MESSAGE_RULES]

URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+|\b(?:[a-z0-9-]+\.)+[a-z]{2,24}/[^\s<>\"']*", re.I)
BARE_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+(?:xn--[a-z0-9-]+|[a-z]{2,24})\b", re.I)
EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", re.I)
PHONE_RE = re.compile(r"(?<![\w.])(?:\+|00)?\d[\d \-.()]{6,18}\d(?!\w)")
DOMAIN_FULL_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+(?:xn--[a-z0-9-]+|[a-z]{2,24})\.?$", re.I)
PHONE_FULL_RE = re.compile(r"^(?:\+|00)?[\d \-.()]{6,24}$")


def reason(code: str, severity: str, text: str, evidence: Optional[str] = None) -> Dict[str, Any]:
    r = {"code": code, "severity": severity, "text": text}
    if evidence:
        r["evidence"] = evidence[:300]
    return r


# ---------------------------------------------------------------------------
# Network primitives (each one small, so tests can monkeypatch them)
# ---------------------------------------------------------------------------

def _resolve(host: str) -> List[str]:
    """Public addresses of host; raises UnsafeTargetError for private/unresolvable."""
    return public_addresses(host)


def _whois_created(domain: str) -> Optional[datetime]:
    import whois
    w = whois.whois(domain)
    created = w.creation_date
    if isinstance(created, list):
        created = min((c for c in created if isinstance(c, datetime)), default=None)
    if not isinstance(created, datetime):
        return None
    return created.replace(tzinfo=None) if created.tzinfo else created


def _fetch(url: str) -> Dict[str, Any]:
    """GET through the SSRF guard (redirects re-vetted, max 5 hops); returns the final URL only."""
    resp = safe_get(url, headers={"User-Agent": "Mozilla/5.0 OSIG-ScamCheck/1.0"}, timeout=CHECK_TIMEOUT)
    return {"final_url": str(resp.request.url), "status": resp.status_code}


def _tls_info(host: str) -> Optional[Dict[str, Any]]:
    sock = safe_tls_connect(host, 443, timeout=4)
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(sock, server_hostname=host) as tls:
        cert = tls.getpeercert()
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
    return {"issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "not_before": not_before.isoformat()}


def _mail_records(domain: str) -> Dict[str, bool]:
    import dns.resolver

    def has(name, rtype, prefix=None):
        try:
            answers = dns.resolver.resolve(name, rtype, lifetime=3)
        except Exception:
            return False
        if prefix is None:
            return True
        return any(b"".join(a.strings).decode(errors="replace").lower().startswith(prefix) for a in answers)

    return {"mx": has(domain, "MX"), "spf": has(domain, "TXT", "v=spf1"),
            "dmarc": has(f"_dmarc.{domain}", "TXT", "v=dmarc1")}


def _virustotal(domain: str) -> Optional[Dict[str, int]]:
    from app.core.config import settings
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    r = httpx.get(f"https://www.virustotal.com/api/v3/domains/{domain}", timeout=CHECK_TIMEOUT,
                  headers={"x-apikey": settings.VIRUSTOTAL_API_KEY})
    if r.status_code != 200:
        return None
    stats = ((r.json().get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
    return {"malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0))}


def _urlscan(domain: str) -> Optional[int]:
    """Number of URLScan scans of the domain flagged malicious (needs URLSCAN_API_KEY)."""
    from app.core.config import settings
    if not settings.URLSCAN_API_KEY:
        return None
    r = httpx.get("https://urlscan.io/api/v1/search/", timeout=CHECK_TIMEOUT,
                  headers={"API-Key": settings.URLSCAN_API_KEY},
                  params={"q": f"page.domain:{domain} AND verdicts.malicious:true", "size": 1})
    if r.status_code != 200:
        return None
    return int(r.json().get("total", 0))


WEB_RISK_THREATS = ("SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE")


def _web_risk(target: str) -> Optional[List[str]]:
    """Google Web Risk Lookup API: threat types the URL is listed for ([] = not listed)."""
    from app.core.config import settings
    if not settings.GOOGLE_WEB_RISK_API_KEY:
        return None
    params = [("uri", target), ("key", settings.GOOGLE_WEB_RISK_API_KEY)] + [("threatTypes", t) for t in WEB_RISK_THREATS]
    r = httpx.get("https://webrisk.googleapis.com/v1/uris:search", params=params, timeout=CHECK_TIMEOUT)
    if r.status_code != 200:
        return None
    return list(((r.json() or {}).get("threat") or {}).get("threatTypes") or [])


def _urlhaus(url: Optional[str], host: str) -> Optional[Dict[str, Any]]:
    """abuse.ch URLhaus: is this exact URL, or this host, listed as distributing malware?"""
    from app.core.config import settings
    if not settings.URLHAUS_AUTH_KEY:
        return None
    headers = {"Auth-Key": settings.URLHAUS_AUTH_KEY}
    if url:
        r = httpx.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers=headers, timeout=CHECK_TIMEOUT)
        if r.status_code == 200 and r.json().get("query_status") == "ok":
            d = r.json()
            return {"listed": "url", "status": d.get("url_status"), "threat": d.get("threat"),
                    "tags": (d.get("tags") or [])[:5]}
    r = httpx.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host}, headers=headers, timeout=CHECK_TIMEOUT)
    if r.status_code != 200:
        return None
    d = r.json()
    status = d.get("query_status") or d.get("query_staus")  # their docs' example misspells it
    if status != "ok" or not int(d.get("url_count") or 0):
        return {"listed": None}
    online = sum(1 for u in d.get("urls") or [] if u.get("url_status") == "online")
    return {"listed": "host", "url_count": int(d.get("url_count") or 0), "online": online}


# ---------------------------------------------------------------------------
# Offline analysis
# ---------------------------------------------------------------------------

def registrable(host: str) -> str:
    ext = _tld(host)
    return ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") \
        else ext.registered_domain or host


def _official_brand(reg: str, host: str) -> Optional[str]:
    for brand, (domains, _tokens) in BRANDS.items():
        for d in domains:
            if reg == d or host == d or host.endswith("." + d):
                return brand
    return None


def _edit_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _skeleton(label: str) -> str:
    s = unicodedata.normalize("NFKD", label)
    s = "".join(c for c in s if not unicodedata.combining(c)).lower().translate(_HOMOGLYPHS)
    return s.replace("rn", "m").replace("vv", "w")


def lookalike_reasons(host: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Brand lookalikes for a host. Returns (reasons, official brand if the host IS the brand)."""
    host = host.lower().rstrip(".")
    reg = registrable(host)
    official = _official_brand(reg, host)
    if official:
        return [], official
    out: List[Dict[str, Any]] = []
    ext = _tld(host)
    label = (ext.domain or "").lower()
    try:
        label_u = label.encode().decode("idna") if label.startswith("xn--") else label
    except Exception:
        label_u = label
    words = [w for w in re.split(r"[-_.\d]+", label_u) if w]
    skel = _skeleton(label_u)
    skel_flat = skel.replace("-", "")
    sub = (ext.subdomain or "").lower()

    for brand, (domains, tokens) in BRANDS.items():
        # 1. official brand domain used as a subdomain: wave.com.secure-login.xyz
        hit = next((d for d in domains if sub == d or sub.endswith("." + d) or sub.startswith(d + ".")
                    or f".{d}." in f".{sub}."), None)
        if hit:
            out.append(reason("brand_in_subdomain", "critical",
                              f"The address starts with {hit} but actually belongs to {reg}: a classic trick to impersonate {brand}.",
                              host))
            continue
        brand_labels = {_tld(d).domain for d in domains} | {t for t in tokens if len(t) > _SHORT_TOKEN}
        label_flat = label_u.replace("-", "")
        sub_words = [w for w in re.split(r"[-_.]+", sub) if w]
        if any((t in words or t in sub_words) if len(t) <= _SHORT_TOKEN
               else (t in label_flat or t in sub.replace("-", "").replace(".", "")) for t in tokens):
            out.append(reason("brand_lookalike", "high",
                              f"The address uses the name {brand} but is not an official {brand} site.", host))
            continue
        for bl in brand_labels:
            if len(bl) >= 4 and skel_flat == bl and label_flat != bl:
                out.append(reason("brand_homoglyph", "critical",
                                  f"The address swaps look-alike characters to imitate {brand}.", host))
                break
            if len(bl) >= 5 and 0 < _edit_distance(skel_flat, bl) <= (1 if len(bl) < 7 else 2):
                out.append(reason("brand_typosquat", "high", f"The address is a misspelling of {brand}'s domain.", host))
                break
    # one lookalike reason per code is enough
    seen, uniq = set(), []
    for r in out:
        if r["code"] not in seen:
            seen.add(r["code"])
            uniq.append(r)
    return uniq, None


def static_host_reasons(host: str, scheme: Optional[str] = None) -> List[Dict[str, Any]]:
    out = []
    host = host.lower().rstrip(".")
    if "xn--" in host or any(ord(c) > 127 for c in host):
        out.append(reason("idn_domain", "medium",
                          "The address uses international characters (punycode), which can imitate other letters.", host))
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        out.append(reason("suspicious_tld", "low", f"The .{tld} extension is cheap and often used for scam sites.", host))
    if host.count("-") >= 3 or len(host) > 50:
        out.append(reason("long_hostname", "low", "The address is unusually long or has many hyphens.", host))
    if scheme == "http":
        out.append(reason("no_https", "low", "The link does not use a secure (https) connection.", host))
    return out


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Runner with a time budget
# ---------------------------------------------------------------------------

class _Runner:
    def __init__(self):
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=16)
        self.deadline = time.monotonic() + BUDGET_SECONDS

    def submit(self, fn: Callable, *args) -> concurrent.futures.Future:
        return self.pool.submit(fn, *args)

    def result(self, fut: concurrent.futures.Future, default=None):
        remaining = max(0.05, self.deadline - time.monotonic())
        try:
            return fut.result(timeout=min(remaining, CHECK_TIMEOUT + 1))
        except Exception as e:
            logger.info(f"scam check step skipped: {type(e).__name__}: {e}")
            return default

    def close(self):
        self.pool.shutdown(wait=False, cancel_futures=True)


class _Err:
    def __init__(self, exc: Exception):
        self.exc = exc


def _wrap(fn: Callable, *args):
    try:
        return fn(*args)
    except Exception as e:  # keep the exception as a value (UnsafeTargetError matters)
        return _Err(e)


# ---------------------------------------------------------------------------
# Indicator checks
# ---------------------------------------------------------------------------

def check_host(runner: _Runner, host: str, *, url: Optional[str] = None, fetch: bool = False,
               follow_final: bool = True) -> Dict[str, Any]:
    """All checks for one hostname (and optionally the URL on it). Returns {reasons, facts, checked}."""
    host = host.lower().rstrip(".").strip("[]")
    scheme = urlparse(url).scheme if url else None
    reasons: List[Dict[str, Any]] = []
    facts: Dict[str, Any] = {"host": host}
    checked = 0

    if _is_ip(host):
        addr = ipaddress.ip_address(host)
        reasons.append(reason("ip_address_url", "high",
                              "The link points to a bare IP address instead of a named website.", host))
        if not addr.is_global:
            reasons.append(reason("private_address", "high",
                                  "The link points to a private or local network address; it was not opened.", host))
            facts["fetched"] = False
            return {"reasons": reasons, "facts": facts, "checked": 1}
        reasons += static_host_reasons(host, scheme)
        if fetch and url:
            res = runner.result(runner.submit(_wrap, _fetch, url))
            facts["fetched"] = not isinstance(res, _Err) and res is not None
        return {"reasons": reasons, "facts": facts, "checked": 1}

    reg = registrable(host)
    facts["registrable_domain"] = reg
    look, official = lookalike_reasons(host)
    facts["official_brand"] = official
    reasons += look
    if not official:
        reasons += static_host_reasons(host, scheme)
    elif scheme == "http":
        reasons += [r for r in static_host_reasons(host, scheme) if r["code"] == "no_https"]
    is_short = reg in SHORTENERS or host in SHORTENERS
    if is_short:
        reasons.append(reason("url_shortener", "low", "The link is shortened, which hides where it really goes.", host))

    f_dns = runner.submit(_wrap, _resolve, host)
    f_whois = runner.submit(_wrap, _whois_created, reg) if not official and not is_short else None
    f_vt = runner.submit(_wrap, _virustotal, reg)
    f_us = runner.submit(_wrap, _urlscan, reg)
    f_wr = runner.submit(_wrap, _web_risk, url or f"http://{host}/") if not official else None
    f_uh = runner.submit(_wrap, _urlhaus, url, host) if not official else None

    dns_res = runner.result(f_dns)
    safe_to_fetch = False
    if isinstance(dns_res, _Err):
        msg = str(dns_res.exc)
        if isinstance(dns_res.exc, UnsafeTargetError) and "non-public" in msg:
            reasons.append(reason("private_address", "high",
                                  "This name points to a private or local network address; it was not opened.", host))
            facts["fetched"] = False
            checked += 1
        elif isinstance(dns_res.exc, UnsafeTargetError):
            reasons.append(reason("no_dns", "medium", "This address does not exist (no DNS record): the site is gone or never existed.", host))
            checked += 1
    elif dns_res:
        facts["ips"] = dns_res[:4]
        safe_to_fetch = True
        checked += 1

    f_fetch = f_tls = None
    if safe_to_fetch and fetch and url:
        f_fetch = runner.submit(_wrap, _fetch, url)
    if safe_to_fetch and not official and (scheme in (None, "https")):
        f_tls = runner.submit(_wrap, _tls_info, host)

    if f_whois is not None:
        created = runner.result(f_whois)
        if isinstance(created, datetime):
            checked += 1
            age = (datetime.utcnow() - created).days
            facts["domain_created"] = created.date().isoformat()
            facts["domain_age_days"] = age
            if age < 30:
                reasons.append(reason("new_domain", "high", f"The website was registered only {max(age, 0)} days ago.", reg))
            elif age < 180:
                reasons.append(reason("young_domain", "medium", f"The website is less than 6 months old ({age} days).", reg))

    vt = runner.result(f_vt)
    if isinstance(vt, dict):
        checked += 1
        facts["virustotal"] = vt
        if vt["malicious"] >= 2:
            reasons.append(reason("virustotal_malicious", "critical",
                                  f"{vt['malicious']} security vendors flag this site as malicious (VirusTotal).", reg))
        elif vt["malicious"] == 1 or vt["suspicious"] >= 2:
            reasons.append(reason("virustotal_suspicious", "medium", "Security vendors flag this site as suspicious (VirusTotal).", reg))
    us = runner.result(f_us)
    if isinstance(us, int):
        checked += 1
        facts["urlscan_malicious"] = us
        if us > 0:
            reasons.append(reason("urlscan_malicious", "high", "URLScan.io has seen this site serving malicious pages.", reg))
    wr = runner.result(f_wr) if f_wr is not None else None
    if isinstance(wr, list):
        checked += 1
        facts["web_risk"] = wr
        if "SOCIAL_ENGINEERING" in wr:
            reasons.append(reason("web_risk_phishing", "critical",
                                  "Google lists this link as phishing (deceptive site).", host))
        elif wr:
            reasons.append(reason("web_risk_malware", "critical",
                                  "Google lists this link as dangerous (malware or unwanted software).", host))
    uh = runner.result(f_uh) if f_uh is not None else None
    if isinstance(uh, dict):
        checked += 1
        facts["urlhaus"] = uh
        if uh.get("listed") == "url":
            reasons.append(reason("urlhaus_listed", "critical" if uh.get("status") == "online" else "high",
                                  "This exact link is listed by URLhaus as spreading malware.", host))
        elif uh.get("listed") == "host":
            reasons.append(reason("urlhaus_host", "high" if uh.get("online") else "medium",
                                  f"URLhaus has listed {uh['url_count']} malware link(s) on this site.", host))

    if f_tls is not None:
        tls = runner.result(f_tls)
        if isinstance(tls, dict):
            facts["tls"] = tls
            try:
                cert_age = (datetime.utcnow() - datetime.fromisoformat(tls["not_before"])).days
                if cert_age < 7:
                    reasons.append(reason("new_certificate", "low",
                                          f"The site's security certificate was issued {cert_age} days ago.", host))
            except Exception:
                pass

    if f_fetch is not None:
        res = runner.result(f_fetch)
        if isinstance(res, _Err):
            facts["fetched"] = False
            if isinstance(res.exc, UnsafeTargetError) and "non-public" in str(res.exc):
                reasons.append(reason("private_address", "high",
                                      "The link redirects to a private or local network address; it was not followed.", host))
        elif isinstance(res, dict):
            facts["fetched"] = True
            facts["final_url"] = res["final_url"][:500]
            final_host = (urlparse(res["final_url"]).hostname or "").lower()
            if final_host and registrable(final_host) != reg:
                facts["final_host"] = final_host
                reasons.append(reason("redirects_elsewhere", "info" if not is_short else "low",
                                      f"The link leads to {final_host}.", final_host))
                if follow_final:
                    sub = check_host(runner, final_host, url=res["final_url"], fetch=False, follow_final=False)
                    reasons += sub["reasons"]
                    facts["final"] = sub["facts"]
                    checked += sub["checked"]
    return {"reasons": reasons, "facts": facts, "checked": checked or (1 if look else 0)}


def check_url(runner: _Runner, raw: str) -> Dict[str, Any]:
    url = raw if re.match(r"^https?://", raw, re.I) else "https://" + raw
    parts = urlparse(url)
    host = parts.hostname or ""
    if not host:
        return {"reasons": [], "facts": {"url": raw}, "checked": 0}
    out = check_host(runner, host, url=url, fetch=True)
    if parts.username or "@" in parts.netloc:
        out["reasons"].append(reason("userinfo_in_url", "high",
                                     "The link hides its real destination after an @ sign.", host))
    out["facts"]["url"] = url[:500]
    return out


def check_email(runner: _Runner, address: str) -> Dict[str, Any]:
    local, _, domain = address.lower().partition("@")
    reasons: List[Dict[str, Any]] = []
    facts: Dict[str, Any] = {"email": address.lower(), "domain": domain}
    checked = 0
    if domain in DISPOSABLE:
        reasons.append(reason("disposable_email", "medium", "The address uses a throwaway email service.", domain))
    if domain in FREE_MAIL:
        facts["free_mail"] = True
        local_words = [w for w in re.split(r"[._+\-\d]+", local) if w]
        local_flat = re.sub(r"[^a-z]", "", local)
        for brand, (_domains, tokens) in BRANDS.items():
            if brand in ("Google",) and domain in ("gmail.com", "googlemail.com"):
                continue
            if any((t in local_words) if len(t) <= _SHORT_TOKEN else (t in local_flat) for t in tokens):
                reasons.append(reason("freemail_brand", "high",
                                      f"The address claims to be {brand} but is a free {domain} mailbox; companies use their own domain.",
                                      address.lower()))
                break
        checked += 1
    else:
        host = check_host(runner, domain)
        reasons += host["reasons"]
        facts["domain_facts"] = host["facts"]
        checked += host["checked"]
        if domain not in DISPOSABLE:
            mail = runner.result(runner.submit(_wrap, _mail_records, domain))
            if isinstance(mail, dict):
                checked += 1
                facts["mail"] = mail
                if not mail["mx"]:
                    reasons.append(reason("no_mx", "medium", "This domain cannot receive email (no mail server).", domain))
                if not mail["spf"] and not mail["dmarc"]:
                    reasons.append(reason("no_spf_dmarc", "low",
                                          "This domain has no email anti-spoofing records (SPF/DMARC).", domain))
    return {"reasons": reasons, "facts": facts, "checked": checked}


def check_phone(raw: str, country: Optional[str], brand_country: Optional[str] = None) -> Dict[str, Any]:
    import phonenumbers
    from phonenumbers import PhoneNumberType as T
    reasons: List[Dict[str, Any]] = []
    facts: Dict[str, Any] = {"input": raw}
    region = (country or "SN").upper()
    cleaned = raw.strip()
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    try:
        num = phonenumbers.parse(cleaned, region)
    except phonenumbers.NumberParseException:
        reasons.append(reason("invalid_phone", "high", "This is not a valid phone number.", raw))
        return {"reasons": reasons, "facts": facts, "checked": 1}
    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    facts["e164"] = e164
    if not phonenumbers.is_possible_number(num) or not phonenumbers.is_valid_number(num):
        reasons.append(reason("invalid_phone", "high", "This phone number cannot exist (invalid for its country).", e164))
        return {"reasons": reasons, "facts": facts, "checked": 1}
    num_region = phonenumbers.region_code_for_number(num)
    facts["region"] = num_region
    ntype = phonenumbers.number_type(num)
    facts["line_type"] = {T.MOBILE: "mobile", T.FIXED_LINE: "fixed", T.FIXED_LINE_OR_MOBILE: "fixed_or_mobile",
                          T.PREMIUM_RATE: "premium_rate", T.VOIP: "voip", T.SHARED_COST: "shared_cost",
                          T.TOLL_FREE: "toll_free", T.PERSONAL_NUMBER: "personal"}.get(ntype, "unknown")
    if ntype == T.PREMIUM_RATE:
        reasons.append(reason("premium_rate_phone", "high", "Calling this number is charged at a premium rate.", e164))
    elif ntype == T.VOIP:
        reasons.append(reason("voip_phone", "medium", "This is an internet (VoIP) number, easy to get anonymously.", e164))
    elif ntype in (T.SHARED_COST, T.PERSONAL_NUMBER):
        reasons.append(reason("special_rate_phone", "low", "This is a special-rate or forwarding number.", e164))
    if brand_country and num_region and num_region != brand_country:
        reasons.append(reason("phone_country_mismatch", "medium",
                              f"The message mentions a local company but the number is from abroad ({num_region}).", e164))
    elif country and num_region and num_region != region and not brand_country:
        reasons.append(reason("foreign_phone", "low", f"This number is registered in another country ({num_region}).", e164))
    return {"reasons": reasons, "facts": facts, "checked": 1}


# ---------------------------------------------------------------------------
# Input detection and messages
# ---------------------------------------------------------------------------

def detect_kind(text: str) -> str:
    t = text.strip()
    if "\n" not in t and " " not in t:
        if EMAIL_RE.fullmatch(t):
            return "email"
        if re.match(r"^https?://", t, re.I):
            return "url"
        host = t.split("/", 1)[0]
        if DOMAIN_FULL_RE.match(host) or _is_ip(host.split(":")[0]):
            return "url" if "/" in t else "domain"
    if PHONE_FULL_RE.match(t) and sum(c.isdigit() for c in t) >= 6:
        return "phone"
    return "message"


def extract_indicators(text: str) -> Dict[str, List[str]]:
    urls: List[str] = []
    for m in URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;:!?)»\"'")
        if u not in urls:
            urls.append(u)
    emails = list(dict.fromkeys(m.group(0).rstrip(".") for m in EMAIL_RE.finditer(text)))
    # Bare domains not already in a URL or an email ("allez sur wave-pay.top")
    covered = " ".join(urls + emails).lower()
    for m in BARE_DOMAIN_RE.finditer(text):
        d = m.group(0).lower()
        tld = d.rsplit(".", 1)[-1]
        if d in covered or not (tld in SUSPICIOUS_TLDS or tld in {"com", "net", "org", "sn", "ci", "fr", "io", "co", "me", "app"}
                                or tld.startswith("xn--")):
            continue
        if re.fullmatch(r"[\d.]+", d):
            continue
        urls.append(d)
        covered += " " + d
    no_links = URL_RE.sub(" ", EMAIL_RE.sub(" ", text))
    phones = []
    for m in PHONE_RE.finditer(no_links):
        p = m.group(0).strip()
        if sum(c.isdigit() for c in p) >= 7 and p not in phones:
            phones.append(p)
    return {"urls": urls, "emails": emails, "phones": phones}


_SN_BRANDS = ("wave", "orange money", "orange", "free money", "yas", "expresso", "senelec", "sen'eau", "seneau", "sde",
              "cbao", "sgbs", "wari", "kpay", "impots", "dgid", "gouv.sn", "gouvernement")


def message_reasons(text: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    low = text.lower()
    out = []
    for code, sev, msg, pats in _MESSAGE_RES:
        hit = next((p for p in pats if p.search(low)), None)
        if hit:
            m = hit.search(low)
            out.append(reason(code, sev, msg, m.group(0) if m else None))
    mentioned = []
    for brand, (_domains, tokens) in BRANDS.items():
        if any(re.search(rf"\b{re.escape(t)}\b", low) for t in tokens) or brand.lower() in low:
            mentioned.append(brand)
    if mentioned:
        out.append(reason("msg_brand_mention", "low",
                          f"The message presents itself as coming from {', '.join(mentioned[:3])}.", ", ".join(mentioned[:3])))
        codes = {r["code"] for r in out}
        if codes & {"msg_code_request", "msg_fee_request"}:
            out.append(reason("msg_impersonation_request", "high",
                              f"It claims to be {mentioned[0]} and asks for a code or money: {mentioned[0]} never asks for that by message.",
                              mentioned[0]))
    brand_country = "SN" if any(re.search(rf"\b{re.escape(b)}\b", low) for b in _SN_BRANDS) else None
    return out, brand_country


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

def mask_email(address: str) -> str:
    local, _, domain = address.partition("@")
    return f"{local[:1]}***@{domain.lower()}"


def mask_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    plus = "+" if raw.strip().startswith(("+", "00")) else ""
    if raw.strip().startswith("00"):
        digits = digits[2:]
    if len(digits) <= 4:
        return plus + "*" * len(digits)
    keep_start = 3 if plus else 2
    return plus + digits[:keep_start] + "*" * (len(digits) - keep_start - 2) + digits[-2:]


def redact_url(raw: str) -> str:
    url = raw if re.match(r"^https?://", raw, re.I) else "https://" + raw
    p = urlparse(url)
    host = (p.hostname or "").lower()
    base = host if _is_ip(host) else registrable(host)
    path = p.path if p.path not in ("", "/") else ""
    return (base + path)[:300]


def subject_for(kind: str, text: str, indicators: Dict[str, List[str]]) -> str:
    if kind in ("url", "domain"):
        return redact_url(text)
    if kind == "email":
        return mask_email(text)
    if kind == "phone":
        return mask_phone(text)
    first = None
    if indicators.get("urls"):
        first = redact_url(indicators["urls"][0]).split("/", 1)[0]
    elif indicators.get("emails"):
        first = indicators["emails"][0].split("@", 1)[1].lower()
    return f"Message mentioning {first or 'no links'}"[:300]


def input_hash(text: str, country: Optional[str]) -> str:
    norm = re.sub(r"\s+", " ", text.strip()).lower()
    return hashlib.sha256(f"{(country or '').upper()}|{norm}".encode()).hexdigest()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# A trusted list confirming the link is bad settles it, whatever else looks fine
CONFIRMED = {"web_risk_phishing", "web_risk_malware", "urlhaus_listed", "virustotal_malicious"}


def verdict_for(reasons: List[Dict[str, Any]], checked: int) -> Tuple[str, int]:
    score = min(100, sum(SEVERITY_WEIGHT.get(r["severity"], 0) for r in reasons))
    if any(r["code"] in CONFIRMED for r in reasons):
        return "scam", max(score, 90)
    if score >= 60:
        return "scam", score
    if score >= 25:
        return "suspicious", score
    if checked == 0 and not reasons:
        return "unknown", score
    return "no_red_flags", score


def _dedupe(reasons: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen, out = set(), []
    for r in reasons:
        key = (r["code"], r.get("evidence"))
        if key not in seen:
            seen.add(key)
            out.append(r)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(out, key=lambda r: order.get(r["severity"], 5))


def run_check(text: str, country: Optional[str] = None) -> Dict[str, Any]:
    """Analyse one input. Returns {kind, subject, verdict, score, reasons, details}."""
    text = text.strip()
    kind = detect_kind(text)
    runner = _Runner()
    started = time.monotonic()
    reasons: List[Dict[str, Any]] = []
    checked = 0
    details: Dict[str, Any] = {"kind": kind}
    try:
        if kind in ("url", "domain"):
            indicators = {"urls": [text], "emails": [], "phones": []}
            res = check_url(runner, text) if kind == "url" else check_host(runner, text.rstrip("/"))
            reasons, checked = res["reasons"], res["checked"]
            details["checks"] = [res["facts"]]
        elif kind == "email":
            indicators = {"urls": [], "emails": [text.lower()], "phones": []}
            res = check_email(runner, text)
            reasons, checked = res["reasons"], res["checked"]
            details["checks"] = [res["facts"]]
        elif kind == "phone":
            indicators = {"urls": [], "emails": [], "phones": [text]}
            res = check_phone(text, country)
            reasons, checked = res["reasons"], res["checked"]
            details["checks"] = [res["facts"]]
        else:
            indicators = extract_indicators(text)
            msg_reasons, brand_country = message_reasons(text)
            reasons += msg_reasons
            checked += 1 if msg_reasons else 0
            budget = MAX_INDICATORS
            jobs: List[Tuple[str, str, concurrent.futures.Future]] = []
            # Indicators run concurrently with each other (each uses the shared runner inside)
            outer = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_INDICATORS)
            for u in indicators["urls"][:budget]:
                jobs.append(("url", u, outer.submit(check_url, runner, u)))
            budget -= len(jobs)
            for e in indicators["emails"][:max(budget, 0)]:
                jobs.append(("email", e, outer.submit(check_email, runner, e)))
            budget = MAX_INDICATORS - len(jobs)
            for p in indicators["phones"][:max(budget, 0)]:
                jobs.append(("phone", p, outer.submit(check_phone, p, country, brand_country)))
            details["checks"] = []
            for k, value, fut in jobs:
                res = runner.result(fut)
                if not res:
                    details["checks"].append({"kind": k, "value": value, "timed_out": True})
                    continue
                reasons += res["reasons"]
                checked += res["checked"]
                details["checks"].append({"kind": k, "value": value, **res["facts"]})
            outer.shutdown(wait=False, cancel_futures=True)
            if not jobs and not msg_reasons:
                checked += 1  # the text itself was analysed and nothing stood out
            if len(indicators["urls"]) + len(indicators["emails"]) + len(indicators["phones"]) > MAX_INDICATORS:
                details["truncated"] = True
        details["indicators"] = indicators
    finally:
        runner.close()
    reasons = _dedupe(reasons)
    verdict, score = verdict_for(reasons, checked)
    details["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return {"kind": kind, "subject": subject_for(kind, text, details.get("indicators", {})),
            "verdict": verdict, "score": score, "reasons": reasons, "details": details,
            "checked_at": datetime.now(timezone.utc).isoformat()}

