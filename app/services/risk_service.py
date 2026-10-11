"""
OSIG Backend - Risk Assessment

Turns raw results into flags a person can act on. Every flag says what was
found, why it matters, and the evidence behind it; the 0-100 score is just the
sum of flag weights, so it is always explainable by the flags shown.
"""
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List

WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3}
SENSITIVE_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 1433: "SQL Server", 3306: "MySQL", 3389: "Remote Desktop",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}
LEAK_WORDS = re.compile(r"\b(password|passwd|leak(ed)?|dump|breach|credentials?|\.env|api[_-]?key)\b", re.I)


def _third_party(exposure: Dict[str, Any], domain: str) -> bool:
    """True when none of the host's names belong to the target domain."""
    if "cdn" in (exposure.get("tags") or []):
        return True
    names = [str(h).lower() for h in exposure.get("hostnames") or []]
    domain = domain.lower()
    return bool(names) and not any(n == domain or n.endswith("." + domain) for n in names)


def _parse_date(value: Any):
    if not value:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.strptime(str(value)[:len(fmt) + 6].strip(), fmt)
        except ValueError:
            continue
    return None


class _Assessment:
    def __init__(self):
        self.flags: List[Dict[str, Any]] = []
        self.findings: List[str] = []

    def flag(self, key: str, severity: str, description: str, source: str, evidence: List[str] = None):
        self.flags.append({
            "id": key, "type": key.split(":")[0], "severity": severity,
            "description": description, "source": source, "evidence": (evidence or [])[:8],
        })


def assess(scan, results: List) -> Dict[str, Any]:
    a = _Assessment()
    by_type: Dict[str, List] = {}
    for r in results:
        by_type.setdefault(r.data_type, []).append(r)
    target_type = scan.target_type.value

    # ── breaches (email) ───────────────────────────────────
    breaches = by_type.get("breach", [])
    if breaches:
        with_pw = [b for b in breaches if any("password" in str(c).lower() for c in (b.data.get("data_classes") or []))]
        names = [f"{b.data.get('name')} ({b.data.get('breach_date') or 'date unknown'})" for b in breaches]
        if with_pw:
            a.flag("breach:passwords", "critical" if len(with_pw) >= 3 else "high",
                   f"Exposed in {len(with_pw)} breach{'es' if len(with_pw) != 1 else ''} that leaked passwords. "
                   "Change any reused password and turn on two-factor sign-in.",
                   "XposedOrNot", [b.data.get("name") for b in with_pw])
        other = len(breaches) - len(with_pw)
        if other:
            a.flag("breach:data", "medium",
                   f"Appears in {other} other breach{'es' if other != 1 else ''} (personal data, no passwords).",
                   "XposedOrNot", [n for n in names if n.split(" (")[0] not in {b.data.get("name") for b in with_pw}])
        a.findings.append(f"Found in {len(breaches)} known breach{'es' if len(breaches) != 1 else ''}"
                          + (f", {len(with_pw)} with passwords" if with_pw else ""))

    # ── email address checks ───────────────────────────────
    for r in by_type.get("email_validation", []):
        d = r.data
        if d.get("is_disposable"):
            a.flag("email:disposable", "medium", "This is a disposable (throwaway) email provider.", r.source, [d.get("domain")])
        if d.get("domain_valid") is False:
            a.flag("email:no_mx", "low", "The address's domain has no mail servers, so it can't receive email.", r.source, [d.get("domain")])
        if d.get("provider"):
            a.findings.append(f"Mail handled by {d['provider']}")
    accounts = [r for r in by_type.get("account_existence", [])]
    if accounts:
        a.findings.append(f"Registered on {len(accounts)} site{'s' if len(accounts) != 1 else ''}: "
                          + ", ".join(sorted({r.data.get('platform') for r in accounts})[:6]))
        if len(accounts) >= 10:
            a.flag("exposure:accounts", "low", f"Registered on {len(accounts)} services, a wide footprint for account takeover attempts.",
                   "Holehe", sorted({r.data.get("platform") for r in accounts}))
    for r in by_type.get("profile", []):
        linked = r.data.get("verified_accounts") or []
        if linked:
            a.findings.append(f"Public Gravatar profile linking {len(linked)} account{'s' if len(linked) != 1 else ''}")

    # ── usernames ──────────────────────────────────────────
    profiles = [r for r in by_type.get("social_profile", []) if r.data.get("exists")]
    if profiles:
        a.findings.append(f"Handle found on {len(profiles)} platform{'s' if len(profiles) != 1 else ''}: "
                          + ", ".join(sorted({r.data.get('platform') for r in profiles})[:6]))
        locs = sorted({(r.data.get("profile") or {}).get("location") for r in profiles} - {None})
        if len(locs) > 1:
            a.flag("identity:mixed", "low",
                   f"Profiles with this handle list different locations ({', '.join(locs[:4])}). "
                   "They may belong to different people.", "Username Check", locs)

    # ── domain: mail security ──────────────────────────────
    if target_type == "domain":
        dmarc = [r for r in by_type.get("email_address", []) if "dmarc" in str(r.data.get("type", "")).lower()]
        spf = by_type.get("email_infrastructure", [])
        if not dmarc:
            a.flag("mail:no_dmarc", "medium", "No DMARC policy: anyone can send email that claims to be from this domain.",
                   "DMARC Analysis", [f"_dmarc.{scan.target_value}"])
        else:
            m = re.search(r"\bp=(\w+)", str(dmarc[0].data.get("record", "")), re.I)
            policy = (dmarc[0].data.get("policy") or (m.group(1) if m else "")).lower()
            if policy == "none":
                a.flag("mail:dmarc_none", "low", "DMARC is in monitoring mode (p=none): spoofed mail is reported but still delivered.",
                       "DMARC Analysis", [str(dmarc[0].data.get("record"))[:120]])
        if not spf:
            a.flag("mail:no_spf", "low", "No SPF record, so receiving servers can't tell which servers may send this domain's mail.",
                   "DNS TXT Analysis", [scan.target_value])

        # TLS / web
        for r in by_type.get("web_server", []):
            d = r.data
            tls = d.get("tls") or {}
            exp = _parse_date(tls.get("expires"))
            if d.get("tls_error") and not tls:
                a.flag("web:tls_error", "medium", "HTTPS failed: " + str(d["tls_error"])[:120], r.source)
            elif exp and exp - datetime.utcnow() < timedelta(days=21):
                a.flag("web:tls_expiring", "medium", f"The TLS certificate expires on {exp:%Y-%m-%d}.", r.source, [tls.get("issuer")])
            if d.get("status") and not d.get("hsts"):
                a.flag("web:no_hsts", "low", "No HSTS header, so first visits can be downgraded to plain HTTP.", r.source, [d.get("final_url")])
            if d.get("title"):
                a.findings.append(f"Website: “{d['title']}” served by {d.get('server') or 'an unnamed server'}")

        for r in by_type.get("domain_registration", []):
            exp = _parse_date(r.data.get("expiration_date"))
            if exp and exp - datetime.utcnow() < timedelta(days=30):
                a.flag("domain:expiring", "medium", f"The domain registration expires on {exp:%Y-%m-%d}.", r.source)
            if r.data.get("registrar"):
                a.findings.append(f"Registered with {r.data['registrar']}")

        subs = [r for r in results if r.data_type == "subdomain"]
        live = [r for r in subs if r.data.get("live", True) and r.data.get("ip_addresses")]
        if subs:
            a.findings.append(f"{len(subs)} subdomains, {len(live)} live")
        if len(live) > 30:
            a.flag("surface:subdomains", "low", f"{len(live)} live subdomains: a large surface to keep patched.",
                   "Certificate Transparency", [r.data.get("full_domain") for r in live[:8]])

        for r in by_type.get("open_ports", []):
            risky = [p for p in (r.data.get("open_ports") or []) if isinstance(p, dict) and p.get("port") in SENSITIVE_PORTS]
            if risky:
                a.flag("ports:sensitive", "high",
                       "Sensitive services reachable from the internet: "
                       + ", ".join(f"{SENSITIVE_PORTS[p['port']]} ({p['port']})" for p in risky), r.source,
                       [f"{r.data.get('ip')}:{p['port']}" for p in risky])

        for r in by_type.get("webpage_info", []):
            ph = r.data.get("phishing_analysis") or {}
            if ph.get("potential_risk"):
                a.flag("web:impersonation", "high",
                       "The homepage names an organization that doesn't match the domain: possible impersonation.",
                       r.source, [ph.get("base_domain")])

        for r in by_type.get("web_hygiene", []):
            if "security_txt" not in r.data:
                a.flag("web:no_security_txt", "low",
                       "No security.txt, so security researchers have no published way to report vulnerabilities.",
                       r.source, [f"https://{scan.target_value}/.well-known/security.txt"])
        for r in by_type.get("web_server", []):
            techs = [t.get("name") for t in (r.data.get("technologies") or []) if isinstance(t, dict)]
            if techs:
                a.findings.append("Built with " + ", ".join(techs[:6]))

        history = by_type.get("web_history", [])
        if history and history[0].data.get("first_capture"):
            a.findings.append(f"First archived {history[0].data['first_capture']}")

    # ── phone ──────────────────────────────────────────────
    for r in by_type.get("phone_info", []):
        d = r.data
        if d.get("is_valid") is False:
            a.flag("phone:invalid", "low", "This isn't a valid number for its country.", r.source)
        if str(d.get("number_type", "")).lower() in ("voip",):
            a.flag("phone:voip", "low", "VoIP number: easy to obtain and often used for throwaway accounts.", r.source)
        bits = [d.get("carrier"), d.get("location"), d.get("number_type")]
        if any(bits):
            a.findings.append(" · ".join(str(b) for b in bits if b))

    # ── exposed hosts and reputation (domain / ip) ─────────
    third_party = []
    for r in by_type.get("host_exposure", []):
        d = r.data
        # Shared infrastructure (GitHub Pages, CDNs) isn't the target's to patch
        if target_type == "domain" and _third_party(d, scan.target_value):
            third_party.append(d["ip"])
            continue
        risky = [p for p in d.get("ports", []) if p in SENSITIVE_PORTS]
        if risky:
            a.flag(f"ports:{d['ip']}", "high",
                   f"{d['ip']} exposes " + ", ".join(f"{SENSITIVE_PORTS[p]} ({p})" for p in risky)
                   + " to the internet.", r.source, [f"{d['ip']}:{p}" for p in risky])
        if d.get("vulns"):
            names = ", ".join((d.get("hostnames") or [d["ip"]])[:2])
            a.flag(f"cves:{d['ip']}", "high",
                   f"{len(d['vulns'])} known vulnerabilities (CVEs) match the software on {names}: "
                   "it is likely running outdated versions.", r.source, d["vulns"][:8])
    exposed = by_type.get("host_exposure", [])
    if exposed:
        a.findings.append(f"{len(exposed)} host{'s' if len(exposed) != 1 else ''} seen by Shodan, "
                          f"{sum(len(x.data.get('ports', [])) for x in exposed)} open ports in total")
    if third_party:
        a.findings.append(f"{len(third_party)} host{'s' if len(third_party) != 1 else ''} on third-party "
                          "infrastructure (not counted in risk)")

    for r in by_type.get("reputation", []):
        if r.data.get("malicious"):
            a.flag("reputation:malicious", "high",
                   f"{r.data['malicious']} security vendors on VirusTotal flag this domain as malicious.",
                   r.source, r.data.get("categories") or [])

    if target_type == "ip":
        for r in by_type.get("ip_info", []):
            if r.data.get("reverse_hostname"):
                a.findings.append(f"Hostname {r.data['reverse_hostname']}"
                                  + (" (forward-confirmed)" if r.data.get("forward_confirmed") else ""))
            if r.data.get("domains"):
                a.findings.append(f"Hosts {r.data.get('count', len(r.data['domains']))} domains")
        for r in by_type.get("ip_intel", []):
            geo = r.data.get("geo") or {}
            place = ", ".join(x for x in (geo.get("city"), geo.get("country")) if x)
            owner = r.data.get("asn_description") or geo.get("isp")
            a.findings.append(" · ".join(x for x in (owner, place) if x))

    # ── infostealer exposure (email / username / domain) ───
    for r in by_type.get("infostealer", []):
        d = r.data
        n = d.get("infection_count") or len(d.get("infections") or [])
        caveat = (" Usernames aren't unique, so this may be someone else using the same handle."
                  if target_type == "username" else "")
        a.flag("infostealer:device", "critical" if target_type == "email" else "high",
               f"A device used by this {target_type} was infected by password-stealing malware"
               + (f" (latest {d['latest']})" if d.get("latest") else "")
               + ". Every password saved on it should be treated as stolen: change them and enable two-factor sign-in."
               + caveat,
               r.source, [f"{i.get('date_compromised')} · {i.get('operating_system') or 'unknown OS'}"
                          for i in (d.get("infections") or [])][:5])
        a.findings.append(f"Linked to {n} infostealer infection{'s' if n != 1 else ''}")
    for r in by_type.get("infostealer_domain", []):
        d = r.data
        emp = d.get("employee_infections") or 0
        users = d.get("user_infections") or 0
        if emp or users:
            a.flag("infostealer:domain", "high",
                   f"Infostealer logs hold {emp} employee and {users} customer logins for this domain's sites.",
                   r.source, (d.get("employee_login_urls") or [])[:6])

    # ── lookalike domains ──────────────────────────────────
    looks = by_type.get("lookalike_domain", [])
    if looks:
        mail_capable = [r for r in looks if r.data.get("can_receive_mail")]
        a.findings.append(f"{len(looks)} registered lookalike domains, {len(mail_capable)} with mail servers")
        if mail_capable:
            a.flag("lookalikes:mail", "high" if len(mail_capable) > 5 else "medium",
                   f"{len(mail_capable)} lookalike domain{'s' if len(mail_capable) != 1 else ''} can send and receive email, "
                   "the setup used for phishing that impersonates this domain.",
                   "dnstwist", [r.data["domain"] for r in mail_capable])

    # ── IP reputation ──────────────────────────────────────
    for r in by_type.get("ip_reputation", []):
        d = r.data
        if d.get("classification") == "malicious":
            a.flag("ip:malicious", "high", "GreyNoise classifies this IP as malicious: it is actively attacking or scanning hosts.",
                   r.source, [d.get("ip")])
        elif d.get("scanning_internet"):
            a.flag("ip:scanning", "medium", "This IP is mass-scanning the internet (seen by GreyNoise).", r.source, [d.get("ip")])
        if d.get("known_benign_service"):
            a.findings.append(f"Known service: {d.get('name')}")
        score_ = d.get("abuse_score")
        if score_ is not None and score_ >= 10:
            a.flag("ip:abuse", "high" if score_ >= 50 else "medium",
                   f"AbuseIPDB abuse confidence {score_}% from {d.get('reports')} reports in the last 90 days.",
                   r.source, [d.get("ip")])

    # ── PGP impersonation hint ─────────────────────────────
    keys = by_type.get("pgp_key", [])
    if keys and not any(k.data.get("verified") for k in keys) and len(keys) > 1:
        a.flag("pgp:unverified", "low",
               f"{len(keys)} PGP keys list this address but none is verified; some may be impersonations.",
               "Ubuntu keyserver", [str((k.data.get("key") or {}).get("fingerprint", ""))[-16:] for k in keys])
    if keys:
        a.findings.append(f"{len(keys)} published PGP key{'s' if len(keys) != 1 else ''}"
                          + (" (verified)" if any(k.data.get("verified") for k in keys) else ""))

    # ── organizations ──────────────────────────────────────
    for r in by_type.get("org_profile", []):
        d = r.data
        bits = [d.get("description"), d.get("founded") and f"founded {d['founded']}", d.get("headquarters")]
        a.findings.append(" · ".join(str(b) for b in bits if b))
    entities = by_type.get("legal_entity", [])
    if entities:
        active = [e for e in entities if str(e.data.get("status", "")).upper() == "ACTIVE"]
        a.findings.append(f"{len(entities)} legal entities found, {len(active)} active")

    # ── public mentions (any type) ─────────────────────────
    leaks = [r for r in by_type.get("dork_result", [])
             if LEAK_WORDS.search(f"{r.data.get('title', '')} {r.data.get('snippet', '')}")]
    if leaks:
        a.flag("mentions:leak_terms", "medium",
               f"{len(leaks)} public page{'s' if len(leaks) != 1 else ''} mention the target next to words like "
               "“password”, “leak” or “.env”. Check them.", "DuckDuckGo Dork", [r.data.get("url") for r in leaks])
    mentions = by_type.get("dork_result", [])
    if mentions:
        a.findings.append(f"{len(mentions)} public page{'s' if len(mentions) != 1 else ''} mention the target")

    # ── sanctions / PEP / offshore screening (possible matches only) ──
    screened = by_type.get("sanctions_match", [])
    for category, key, severity, what in (
            ("sanctions", "watchlist:sanctions", "critical", "a sanctions list"),
            ("crime", "watchlist:crime", "high", "a crime or wanted list"),
            ("pep", "watchlist:pep", "medium", "a politically exposed persons (PEP) list")):
        hits = [r for r in screened if r.data.get("category") == category]
        if hits:
            strong = max(float(r.data.get("score") or 0) for r in hits)
            a.flag(key, severity if category != "sanctions" or strong >= 0.9 else "high",
                   f"Possible match on {what} for {', '.join(sorted({str(r.data.get('name_queried')) for r in hits})[:3])}. "
                   "This is a name match only: confirm identity (date of birth, country, registration numbers) "
                   "before acting on it.", "OpenSanctions",
                   [f"{r.data.get('matched_name')} · {round(float(r.data.get('score') or 0) * 100)}% · "
                    + ", ".join((r.data.get("datasets") or [])[:2]) for r in hits])
    offshore = by_type.get("offshore_match", [])
    if offshore:
        a.flag("watchlist:offshore", "medium",
               f"{len(offshore)} possible match{'es' if len(offshore) != 1 else ''} in the ICIJ Offshore Leaks database. "
               "Appearing there does not imply wrongdoing, and names can match different people or companies.",
               "ICIJ Offshore Leaks", [f"{r.data.get('matched_name')} ({r.data.get('node_type') or 'entity'})" for r in offshore])

    # ── secrets in public code ─────────────────────────────
    leaks = by_type.get("code_leak", [])
    creds = [r for r in leaks if r.data.get("likely_credential")]
    if creds:
        a.flag("code:secrets", "high",
               f"{len(creds)} public code file{'s' if len(creds) != 1 else ''} on GitHub appear to contain credentials "
               "next to this target (passwords, API keys or private keys). Treat them as compromised: rotate them "
               "and remove them from the repository history.", "GitHub Code Search",
               [f"{r.data.get('repo')}/{r.data.get('path')} ({r.data.get('preview') or r.data.get('kind')})" for r in creds])
    rest = [r for r in leaks if not r.data.get("likely_credential")]
    if rest:
        a.flag("code:mentions", "medium",
               f"{len(rest)} public code file{'s' if len(rest) != 1 else ''} mention this target next to secret-related "
               "words or in configuration files. Check they don't expose anything sensitive.", "GitHub Code Search",
               [r.data.get("html_url") for r in rest])

    # ── document metadata ──────────────────────────────────
    for r in by_type.get("document_metadata_summary", []):
        people = r.data.get("people") or []
        if people:
            logins = [p for p in people if " " not in p.strip()]
            a.flag("docs:metadata", "medium" if logins else "low",
                   f"Metadata in {r.data.get('documents')} public document{'s' if r.data.get('documents') != 1 else ''} "
                   f"names {len(people)} author{'s' if len(people) != 1 else ''}"
                   + (", including what look like internal usernames" if logins else "")
                   + ". Attackers use these for phishing and password guessing: strip metadata before publishing.",
                   r.source, people)
        if r.data.get("software"):
            a.findings.append("Documents made with " + ", ".join(r.data["software"][:5]))

    # ── dark web (ransomware leak sites) ───────────────────
    claims = by_type.get("darkweb_mention", [])
    if claims:
        a.flag("darkweb:ransomware", "high",
               f"Named on {len(claims)} ransomware leak-site post{'s' if len(claims) != 1 else ''}: the group claims "
               "to have stolen data. Check whether the claim is genuine and prepare breach notification.",
               "ransomware.live", [f"{r.data.get('group')} · {r.data.get('attack_date') or 'date unknown'}" for r in claims])

    # ── threat-intel feeds (OTX) ───────────────────────────
    for r in by_type.get("threat_intel", []):
        d = r.data
        if d.get("allowlisted"):
            a.findings.append(f"OTX allow-lists {d.get('indicator')} ({', '.join(d['allowlisted'][:2])})")
            continue
        if d.get("pulse_count"):
            a.flag("intel:otx", "high" if d.get("malware_families") else "medium",
                   f"{d['pulse_count']} AlienVault OTX threat report{'s' if d['pulse_count'] != 1 else ''} mention "
                   f"{d.get('indicator')}"
                   + (f", linked to malware ({', '.join(d['malware_families'][:3])})" if d.get("malware_families") else "")
                   + ". Reports can be stale or about shared hosting: review them.", r.source,
                   (d.get("pulses") or [])[:5])

    # ── homepage snapshot ──────────────────────────────────
    for r in by_type.get("page_snapshot", []):
        if r.data.get("title"):
            a.findings.append(f"Homepage fingerprint #{str(r.data.get('fingerprint'))[:8]} (“{r.data['title'][:60]}”)")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    a.flags.sort(key=lambda f: order[f["severity"]])
    score = min(100, sum(WEIGHT[f["severity"]] for f in a.flags))
    level = "critical" if score >= 60 else "high" if score >= 35 else "medium" if score >= 10 else "low"
    return {"score": score, "level": level, "flags": a.flags, "findings": a.findings}
