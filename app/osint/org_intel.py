"""
Organization Intelligence Module (target type: organization)

Quick:
- Wikidata: the best-matching entity and its public facts (website, HQ,
  founding date, parent/subsidiaries, executives, industry, social handles)
- GLEIF: legal entities (LEI register) with registered address and status
Deep adds:
- OpenCorporates company register search (when OPENCORPORATES_API_TOKEN is set)
"""
from typing import Any, Dict, List, Optional

import httpx

from app.osint.base import BaseOSINTModule, OSINTResult

UA = {"User-Agent": "OSIG/1.0 (open source intelligence research; https://github.com/crossben/osig)"}
WIKIDATA = "https://www.wikidata.org/w/api.php"

# property -> (field, kind) ; kind: url | time | item | items | text | quantity
PROPS = {
    "P856": ("website", "url"),
    "P571": ("founded", "time"),
    "P159": ("headquarters", "item"),
    "P17": ("country", "item"),
    "P749": ("parent_organization", "item"),
    "P355": ("subsidiaries", "items"),
    "P169": ("ceo", "item"),
    "P112": ("founders", "items"),
    "P452": ("industry", "items"),
    "P1128": ("employees", "quantity"),
    "P1454": ("legal_form", "item"),
    "P2002": ("x_handle", "text"),
    "P4264": ("linkedin_company", "text"),
    "P2037": ("github", "text"),
    "P2013": ("facebook", "text"),
    "P1278": ("lei", "text"),
}


class OrganizationIntelModule(BaseOSINTModule):
    def __init__(self):
        super().__init__(name="org_intel", display_name="Organization Intelligence")

    def run(self, target: str, deep: bool = False) -> List[OSINTResult]:
        self.log_start(target)
        name = target.strip()
        results: List[OSINTResult] = []
        checks = [lambda: self._wikidata(name), lambda: self._gleif(name)]
        if deep:
            checks.append(lambda: self._opencorporates(name))
        for check in checks:
            try:
                results.extend(check() or [])
            except Exception as e:
                self.logger.warning(f"Organization check failed: {e}")
        self.log_success(len(results))
        return results

    # ── Wikidata ─────────────────────────────────────────────
    def _wikidata(self, name: str) -> List[OSINTResult]:
        with httpx.Client(headers=UA, timeout=20) as client:
            hits = client.get(WIKIDATA, params={"action": "wbsearchentities", "search": name, "language": "en",
                                                "type": "item", "format": "json", "limit": 5}).json().get("search", [])
            if not hits:
                return []
            ids = [h["id"] for h in hits]
            entities = client.get(WIKIDATA, params={"action": "wbgetentities", "ids": "|".join(ids),
                                                    "props": "labels|descriptions|claims", "languages": "en",
                                                    "format": "json"}).json().get("entities", {})
            # Best match: an entity that looks like an organization (has a website, HQ or founding date)
            def score(qid):
                claims = entities.get(qid, {}).get("claims", {})
                return sum(p in claims for p in ("P856", "P159", "P571", "P452", "P1128"))
            best = max(ids, key=lambda q: (score(q), -ids.index(q)))
            if score(best) == 0:
                return []
            entity = entities[best]
            facts = self._facts(entity.get("claims", {}))
            labels = self._labels(client, [v for v in self._item_ids(facts)])
        resolve = lambda v: labels.get(v, v)
        for field, (_, kind) in {PROPS[p][0]: PROPS[p] for p in PROPS}.items():
            if field in facts and kind == "item":
                facts[field] = resolve(facts[field])
            elif field in facts and kind == "items":
                facts[field] = [resolve(v) for v in facts[field]]
        label = (entity.get("labels", {}).get("en") or {}).get("value", name)
        description = (entity.get("descriptions", {}).get("en") or {}).get("value")
        return [OSINTResult(
            source="Wikidata",
            source_url=f"https://www.wikidata.org/wiki/{best}",
            data_type="org_profile",
            data={"name": label, "description": description, "wikidata_id": best, **facts},
            confidence=0.85 if label.lower() == name.lower() else 0.65,
        )]

    @staticmethod
    def _facts(claims: Dict[str, Any]) -> Dict[str, Any]:
        facts: Dict[str, Any] = {}
        for pid, (field, kind) in PROPS.items():
            values = []
            for claim in claims.get(pid, []):
                v = ((claim.get("mainsnak") or {}).get("datavalue") or {}).get("value")
                if v is None:
                    continue
                if kind in ("item", "items"):
                    values.append(v.get("id"))
                elif kind == "time":
                    values.append(str(v.get("time", "")).lstrip("+")[:10].replace("-00", ""))
                elif kind == "quantity":
                    values.append(str(v.get("amount", "")).lstrip("+"))
                else:
                    values.append(v if isinstance(v, str) else str(v))
            if values:
                facts[field] = values[:12] if kind == "items" else values[0]
        return facts

    @staticmethod
    def _item_ids(facts: Dict[str, Any]):
        for field, kind in {f: k for f, k in PROPS.values()}.items():
            if field in facts and kind == "item":
                yield facts[field]
            elif field in facts and kind == "items":
                yield from facts[field]

    @staticmethod
    def _labels(client: httpx.Client, ids: List[str]) -> Dict[str, str]:
        ids = [i for i in dict.fromkeys(ids) if i]
        out: Dict[str, str] = {}
        for i in range(0, len(ids), 50):
            data = client.get(WIKIDATA, params={"action": "wbgetentities", "ids": "|".join(ids[i:i + 50]),
                                                "props": "labels", "languages": "en", "format": "json"}).json()
            for qid, ent in data.get("entities", {}).items():
                out[qid] = (ent.get("labels", {}).get("en") or {}).get("value", qid)
        return out

    # ── GLEIF (LEI register) ────────────────────────────────
    def _gleif(self, name: str) -> List[OSINTResult]:
        r = httpx.get("https://api.gleif.org/api/v1/lei-records", headers=UA, timeout=20,
                      params={"filter[fulltext]": name, "page[size]": 8})
        if r.status_code != 200:
            return []
        out = []
        for rec in r.json().get("data", []):
            a = rec.get("attributes", {})
            e = a.get("entity", {})
            addr = e.get("legalAddress") or {}
            out.append(OSINTResult(
                source="GLEIF",
                source_url=f"https://search.gleif.org/#/record/{a.get('lei')}",
                data_type="legal_entity",
                data={
                    "name": (e.get("legalName") or {}).get("name"),
                    "lei": a.get("lei"),
                    "status": e.get("status"),
                    "jurisdiction": e.get("jurisdiction"),
                    "legal_form": (e.get("legalForm") or {}).get("id"),
                    "city": addr.get("city"),
                    "country": addr.get("country"),
                    "address": ", ".join(x for x in (addr.get("addressLines") or []) + [addr.get("postalCode"), addr.get("city")] if x),
                    "registered_at": (e.get("registeredAt") or {}).get("other") or (e.get("registeredAt") or {}).get("id"),
                },
                confidence=0.8,
            ))
        return out

    # ── OpenCorporates (token) ──────────────────────────────
    def _opencorporates(self, name: str) -> List[OSINTResult]:
        from app.core.config import settings
        if not settings.OPENCORPORATES_API_TOKEN:
            return []
        r = httpx.get("https://api.opencorporates.com/v0.4/companies/search", timeout=20,
                      params={"q": name, "per_page": 10, "api_token": settings.OPENCORPORATES_API_TOKEN})
        if r.status_code != 200:
            return []
        out = []
        for item in (r.json().get("results") or {}).get("companies", []):
            c = item.get("company", {})
            out.append(OSINTResult(
                source="OpenCorporates",
                source_url=c.get("opencorporates_url"),
                data_type="legal_entity",
                data={"name": c.get("name"), "company_number": c.get("company_number"),
                      "jurisdiction": c.get("jurisdiction_code"), "status": c.get("current_status"),
                      "incorporated": c.get("incorporation_date"), "dissolved": c.get("dissolution_date"),
                      "address": c.get("registered_address_in_full")},
                confidence=0.85,
            ))
        return out
