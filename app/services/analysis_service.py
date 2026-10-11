"""
Derived views over stored results, shared by scans and investigations:

- map points: any result carrying lat/lon (IP geolocation, hosting of A records)
- timeline: every dated fact (domain registered, breach, infostealer infection,
  account created, PGP key made, company founded, TLS expiry, first archive...)
- STIX 2.1 bundle and MISP event exports of the entity graph

Results are walked generically, so a module that adds a dated field or a
location shows up here without changes.
"""
import uuid
from datetime import date, datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.services.graph_service import build_graph

# key -> (what happened, importance) ; keys are matched case-insensitively
DATE_KEYS = {
    "creation_date": ("Domain registered", "info"),
    "registered": ("Registered", "info"),
    "expiration_date": ("Domain registration expires", "info"),
    "updated_date": ("Registration updated", "info"),
    "breach_date": ("Appeared in a breach", "high"),
    "date_compromised": ("Infostealer infection", "critical"),
    "created": ("Created", "info"),
    "created_at": ("Created", "info"),
    "joined": ("Account created", "info"),
    "founded": ("Founded", "info"),
    "inception": ("Founded", "info"),
    "incorporated": ("Incorporated", "info"),
    "dissolved": ("Dissolved", "medium"),
    "not_before": ("Certificate issued", "info"),
    "not_after": ("Certificate expires", "info"),
    "valid_from": ("Certificate issued", "info"),
    "valid_until": ("Certificate expires", "info"),
    "first_seen": ("First seen", "info"),
    "last_seen": ("Last seen", "info"),
    "first_snapshot": ("First archived", "info"),
    "last_snapshot": ("Last archived", "info"),
    "first_archived": ("First archived", "info"),
    "last_archived": ("Last archived", "info"),
    "last_analysis_date": ("Last analysed by VirusTotal", "info"),
}
LABEL_KEYS = ("name", "title", "breach", "site", "platform", "domain", "email", "username", "company",
              "issuer", "subject", "host", "url")


def parse_date(value: Any) -> Optional[date]:
    """ISO strings, 'YYYYMMDDhhmmss' (Wayback), epoch seconds/ms, or WHOIS lists."""
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, list):
        return parse_date(value[0]) if value else None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, (int, float)):
        ts = value / 1000 if value > 1e11 else value
        if 3e8 < ts < 4.2e9:
            return datetime.fromtimestamp(ts, tz=timezone.utc).date()
        return None
    s = str(value).strip()
    if s.isdigit():
        if len(s) == 14 or len(s) == 8:  # wayback timestamp / YYYYMMDD
            try:
                return datetime.strptime(s[:8], "%Y%m%d").date()
            except ValueError:
                return None
        return parse_date(int(s))
    if s[:1] == "+":  # Wikidata '+1998-09-04T00:00:00Z'
        s = s[1:]
    try:
        from dateutil import parser
        d = parser.parse(s, default=datetime(2000, 1, 1)).date()
    except (ValueError, OverflowError, TypeError):
        return None
    return d if 1970 <= d.year <= 2100 else None


def _walk(obj: Any, path: Tuple[str, ...] = ()) -> Iterable[Tuple[Tuple[str, ...], dict]]:
    if isinstance(obj, dict):
        yield path, obj
        for k, v in obj.items():
            yield from _walk(v, path + (str(k),))
    elif isinstance(obj, list):
        for item in obj[:200]:
            yield from _walk(item, path)


def _context(d: dict) -> Optional[str]:
    for k in LABEL_KEYS:
        v = d.get(k)
        if isinstance(v, str) and v and len(v) < 120:
            return v
    return None


def _num(v: Any) -> Optional[float]:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f


def map_points(scans_with_results: List[tuple]) -> List[dict]:
    """One point per distinct location, with what is there."""
    points: Dict[Tuple[float, float], dict] = {}
    for scan, results in scans_with_results:
        for r in results:
            for _path, d in _walk(r.data):
                lat = _num(d.get("lat", d.get("latitude")))
                lon = _num(d.get("lon", d.get("lng", d.get("longitude"))))
                if lat is None or lon is None or not (-90 <= lat <= 90 and -180 <= lon <= 180) or (lat == 0 and lon == 0):
                    continue
                key = (round(lat, 3), round(lon, 3))
                p = points.setdefault(key, {
                    "lat": lat, "lon": lon, "labels": [], "sources": [], "scan_ids": [],
                    "place": ", ".join(str(x) for x in (d.get("city"), d.get("region") or d.get("regionName"),
                                                        d.get("country")) if x) or None,
                    "org": d.get("org") or d.get("isp") or d.get("as"),
                })
                label = d.get("query") or d.get("ip") or d.get("ip_address") or r.data.get("ip") or \
                    r.data.get("ip_address") or r.data.get("domain") or scan.target_value
                for lst, v in ((p["labels"], label), (p["sources"], r.source), (p["scan_ids"], str(scan.id))):
                    if v and v not in lst:
                        lst.append(v)
    return list(points.values())


def timeline(scans_with_results: List[tuple]) -> List[dict]:
    """Dated facts, oldest first, de-duplicated."""
    events: Dict[tuple, dict] = {}
    for scan, results in scans_with_results:
        for r in results:
            if r.data_type == "dork_result":
                continue
            for _path, d in _walk(r.data):
                for key, value in d.items():
                    meta = DATE_KEYS.get(str(key).lower())
                    if not meta or isinstance(value, (dict,)):
                        continue
                    when = parse_date(value)
                    if not when:
                        continue
                    what, severity = meta
                    ctx = _context(d) or (r.data.get("platform") if isinstance(r.data, dict) else None)
                    title = f"{what}: {ctx}" if ctx else what
                    k = (when.isoformat(), title.lower())
                    if k in events:
                        continue
                    events[k] = {
                        "date": when.isoformat(), "title": title, "severity": severity,
                        "source": r.source, "data_type": r.data_type, "source_url": r.source_url,
                        "scan_id": str(scan.id), "target": scan.target_value,
                        "future": when > date.today(),
                    }
    return sorted(events.values(), key=lambda e: e["date"])


# ── exports ──────────────────────────────────────────────────────
_NS = uuid.UUID("6f1c2a52-8d0e-4f4b-9c7a-2f0f0b0c0a51")


def _sid(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, kind + ':' + value)}"


STIX_SCO = {  # graph kind -> (STIX type, value property)
    "ip": None, "domain": ("domain-name", "value"), "subdomain": ("domain-name", "value"),
    "nameserver": ("domain-name", "value"), "mailserver": ("domain-name", "value"),
    "lookalike": ("domain-name", "value"), "email": ("email-addr", "value"),
    "url": ("url", "value"), "account": ("user-account", "account_login"),
    "network": ("autonomous-system", None),
}


def stix_bundle(scans_with_results: List[tuple], name: str) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    graph = build_graph(scans_with_results)
    identity = {"type": "identity", "spec_version": "2.1", "id": _sid("identity", "osig"),
                "created": now, "modified": now, "name": "OSIG", "identity_class": "system"}
    objects: List[dict] = [identity]
    refs: List[str] = []
    for n in graph["nodes"]:
        kind, label = n["kind"], str(n["label"])
        obj: Optional[dict] = None
        if kind == "ip":
            t = "ipv6-addr" if ":" in label else "ipv4-addr"
            obj = {"type": t, "value": label}
        elif kind == "network":
            digits = "".join(ch for ch in label.split()[0] if ch.isdigit())
            if digits:
                obj = {"type": "autonomous-system", "number": int(digits), "name": label}
        elif kind in STIX_SCO and STIX_SCO[kind]:
            t, prop = STIX_SCO[kind]
            if kind == "account" and "@" in label:
                user, _, platform = label.partition("@")
                obj = {"type": t, "account_login": user.strip(), "account_type": platform.strip() or None}
            else:
                obj = {"type": t, prop: label}
        elif kind == "breach":
            obj = {"type": "note", "spec_version": "2.1", "created": now, "modified": now,
                   "abstract": f"Breach: {label}", "content": f"Target appears in breach '{label}'",
                   "created_by_ref": identity["id"], "object_refs": []}
        if not obj:
            continue
        obj = {k: v for k, v in obj.items() if v is not None}
        obj.setdefault("spec_version", "2.1")
        obj["id"] = _sid(obj["type"], label)
        objects.append(obj)
        refs.append(obj["id"])
    # notes must reference something: attach to the observables
    observables = [r for r in refs if not r.startswith("note--")]
    for o in objects:
        if o["type"] == "note":
            o["object_refs"] = observables[:50] or [identity["id"]]
    report = {
        "type": "report", "spec_version": "2.1", "id": _sid("report", name + now), "created": now, "modified": now,
        "name": f"OSIG: {name}", "report_types": ["observed-data"],
        "published": now, "created_by_ref": identity["id"], "object_refs": refs or [identity["id"]],
        "description": "Open-source intelligence collected by OSIG from public sources.",
    }
    objects.append(report)
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


MISP_ATTR = {  # graph kind -> (MISP type, category)
    "ip": ("ip-dst", "Network activity"), "domain": ("domain", "Network activity"),
    "subdomain": ("hostname", "Network activity"), "nameserver": ("hostname", "Network activity"),
    "mailserver": ("hostname", "Network activity"), "lookalike": ("domain", "Network activity"),
    "email": ("email", "Social network"), "url": ("url", "External analysis"),
    "account": ("text", "Social network"), "phone": ("phone-number", "Person"),
    "network": ("AS", "Network activity"), "organization": ("text", "Attribution"),
    "breach": ("text", "External analysis"), "person": ("full-name", "Person"),
    "port": ("port", "Network activity"),
}


def misp_event(scans_with_results: List[tuple], name: str) -> dict:
    graph = build_graph(scans_with_results)
    attributes = []
    for n in graph["nodes"]:
        meta = MISP_ATTR.get(n["kind"])
        if not meta:
            continue
        mtype, category = meta
        value = str(n["label"])
        if mtype == "AS":
            digits = "".join(ch for ch in value.split()[0] if ch.isdigit())
            if not digits:
                continue
            value = f"AS{digits}"
        attributes.append({
            "type": mtype, "category": category, "value": value, "to_ids": False,
            "comment": f"{n['kind']} found by OSIG", "uuid": str(uuid.uuid5(_NS, f"{mtype}:{value}")),
        })
    return {"Event": {
        "info": f"OSIG: {name}", "date": date.today().isoformat(), "analysis": "2",
        "threat_level_id": "4", "distribution": "0", "published": False,
        "uuid": str(uuid.uuid5(_NS, "event:" + name + datetime.now().isoformat())),
        "Tag": [{"name": "osint:source-type=\"automatic-collection\""}, {"name": "tlp:amber"}],
        "Attribute": attributes,
    }}
