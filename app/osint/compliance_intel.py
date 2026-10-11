"""
Sanctions / PEP / offshore-leaks screening (background module).

Screens the organization target itself, plus person and organization names that
earlier modules found in this scan (Wikidata executives, GLEIF legal entities,
the WHOIS registrant organization, names on public profiles).

Sources and terms:
- OpenSanctions match API (https://api.opensanctions.org/match/default), needs
  OPENSANCTIONS_API_KEY. The data is CC BY-NC 4.0: free for non-commercial use;
  OSIG is a paid SaaS, so production use requires an OpenSanctions commercial
  licence. Skipped silently without a key.
- ICIJ Offshore Leaks reconciliation API (W3C Reconciliation,
  https://offshoreleaks.icij.org/api/v1/reconcile), no key. Database under ODbL,
  contents CC BY-SA: commercial use allowed with attribution ("ICIJ Offshore
  Leaks Database") - every result carries it. ICIJ notes that appearing in the
  database does not imply wrongdoing.

Names are not identities: everything here is reported as a *possible* match,
with the matched name and score so a person can judge it.
"""
import re
from typing import Any, List, Optional, Tuple

import httpx

from app.osint.base import BaseOSINTModule, OSINTResult, prior_results

UA = {"User-Agent": "OSIG/1.0 (open source intelligence research)"}
OPENSANCTIONS_URL = "https://api.opensanctions.org/match/default"
ICIJ_URL = "https://offshoreleaks.icij.org/api/v1/reconcile"
OPENSANCTIONS_MIN_SCORE = 0.75
ICIJ_MIN_SIMILARITY = 92  # rapidfuzz token_sort_ratio, 0-100
MAX_NAMES = 8
ATTRIBUTION_ICIJ = "ICIJ Offshore Leaks Database (ODbL / CC BY-SA)"
CAVEAT = "Possible match on name only - not a confirmed identity."

# WHOIS privacy services and placeholders are not names worth screening
_JUNK = re.compile(r"privacy|redacted|proxy|whoisguard|withheld|not disclosed|data protected|"
                   r"contact privacy|domains by|perfect privacy|n/a|^none$|statutory masking", re.I)


def _clean(name: Any) -> Optional[str]:
    if not isinstance(name, str):
        return None
    name = " ".join(name.split()).strip(" .,")
    if len(name) < 4 or len(name) > 120 or _JUNK.search(name) or "@" in name:
        return None
    return name


def collect_names(target_type: str, target: str, results: List[Any]) -> List[Tuple[str, str]]:
    """(name, schema) pairs to screen; schema is Person | Company | LegalEntity."""
    names: List[Tuple[str, str]] = []
    if target_type == "organization":
        names.append((target.strip(), "Company"))
    for r in results:
        d = r.data if isinstance(getattr(r, "data", None), dict) else {}
        dt = r.data_type
        if dt == "legal_entity":
            names.append((d.get("name"), "Company"))
        elif dt == "org_profile":
            for p in [d.get("ceo")] + list(d.get("founders") or []):
                names.append((p, "Person"))
        elif dt == "domain_registration":
            org = d.get("org")
            names.append((org[0] if isinstance(org, list) and org else org, "LegalEntity"))
        elif dt in ("social_profile", "account_existence") and d.get("exists"):
            names.append(((d.get("profile") or {}).get("name"), "Person"))
        elif dt == "profile" and d.get("has_profile"):
            names.append((d.get("name"), "Person"))
    seen, out = set(), []
    for name, schema in names:
        name = _clean(name)
        if name and name.lower() not in seen:
            seen.add(name.lower())
            out.append((name, schema))
    return out[:MAX_NAMES]


def _category(topics: List[str]) -> str:
    if any(t.startswith("sanction") for t in topics):
        return "sanctions"
    if any(t.startswith("role.pep") or t == "role.rca" for t in topics):
        return "pep"
    if any(t.startswith("crime") or t in ("wanted", "debarment") for t in topics):
        return "crime"
    return "other"


def opensanctions(names: List[Tuple[str, str]], api_key: str) -> List[OSINTResult]:
    if not api_key or not names:
        return []
    queries = {f"q{i}": {"schema": schema, "properties": {"name": [name]}}
               for i, (name, schema) in enumerate(names)}
    try:
        r = httpx.post(OPENSANCTIONS_URL, json={"queries": queries}, timeout=20,
                       headers={**UA, "Authorization": f"ApiKey {api_key}"})
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    out: List[OSINTResult] = []
    responses = (r.json() or {}).get("responses") or {}
    for i, (name, _schema) in enumerate(names):
        for hit in ((responses.get(f"q{i}") or {}).get("results") or [])[:5]:
            score = float(hit.get("score") or 0)
            if score < OPENSANCTIONS_MIN_SCORE:
                continue
            props = hit.get("properties") or {}
            topics = list(props.get("topics") or [])
            entity_id = hit.get("id")
            out.append(OSINTResult(
                source="OpenSanctions",
                source_url=f"https://www.opensanctions.org/entities/{entity_id}/" if entity_id else None,
                data_type="sanctions_match",
                data={
                    "name_queried": name, "matched_name": hit.get("caption"), "score": round(score, 2),
                    "category": _category(topics), "topics": topics,
                    "datasets": list(hit.get("datasets") or [])[:10],
                    "countries": list(props.get("country") or props.get("jurisdiction") or [])[:6],
                    "schema": hit.get("schema"), "entity_id": entity_id,
                    "possible_match": True, "note": CAVEAT,
                },
                confidence=min(0.9, score),
            ))
    return out


def icij_offshore(names: List[Tuple[str, str]]) -> List[OSINTResult]:
    if not names:
        return []
    from rapidfuzz import fuzz
    queries = {f"q{i}": {"query": name, "limit": 5} for i, (name, _s) in enumerate(names)}
    try:
        r = httpx.post(ICIJ_URL, json={"queries": queries}, headers=UA, timeout=20)
    except httpx.HTTPError:
        return []
    if r.status_code not in (200, 201):  # the reconcile endpoint answers 201
        return []
    body = r.json() or {}
    out: List[OSINTResult] = []
    for i, (name, _schema) in enumerate(names):
        kept = 0
        for hit in ((body.get(f"q{i}") or {}).get("result") or []):
            matched = str(hit.get("name") or "")
            similarity = fuzz.token_sort_ratio(name.lower(), matched.lower())
            if similarity < ICIJ_MIN_SIMILARITY:
                continue
            node_id = str(hit.get("id") or "")
            types = [t.get("name") or t.get("id") for t in (hit.get("types") or hit.get("type") or []) if isinstance(t, dict)]
            out.append(OSINTResult(
                source="ICIJ Offshore Leaks",
                source_url=f"https://offshoreleaks.icij.org/nodes/{node_id}" if node_id.isdigit() else
                "https://offshoreleaks.icij.org/",
                data_type="offshore_match",
                data={"name_queried": name, "matched_name": matched, "similarity": similarity,
                      "node_type": ", ".join(t for t in types if t) or None, "node_id": node_id or None,
                      "description": hit.get("description"),
                      "possible_match": True, "note": CAVEAT + " Appearing in the leaks does not imply wrongdoing.",
                      "attribution": ATTRIBUTION_ICIJ},
                confidence=0.5,
            ))
            kept += 1
            if kept >= 3:
                break
    return out


class ComplianceIntelModule(BaseOSINTModule):
    def __init__(self, target_type: str = "organization"):
        super().__init__(name="compliance_intel", display_name="Sanctions & Offshore Screening")
        self.target_type = target_type

    def run(self, target: str, scan_id: Optional[str] = None) -> List[OSINTResult]:
        from app.core.config import settings
        self.log_start(target)
        names = collect_names(self.target_type, target, prior_results(scan_id))
        results: List[OSINTResult] = []
        for check in (lambda: opensanctions(names, settings.OPENSANCTIONS_API_KEY), lambda: icij_offshore(names)):
            try:
                results.extend(check())
            except Exception as e:  # one source failing must not sink the other
                self.logger.info(f"Screening source failed: {e}")
        self.log_success(len(results))
        return results

