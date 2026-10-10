"""
OSIG Backend - Entity Graph

Turns a scan's raw results into an entity graph: every IP, host, email,
account, URL... a source returned becomes a node, deduplicated across sources,
so the same IP found by DNS, subdomain enumeration and IP intel is ONE node
linked to all three. Entities that relate to each other are linked directly
(subdomain -> IP, IP -> network, IP -> location, ...).
"""
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
VERIFICATION_RE = re.compile(r"^([a-z0-9][a-z0-9_.-]*?)[-_](?:domain[-_])?(?:site[-_])?verification", re.I)

# Display order / grouping on the client
KINDS = [
    "target", "source", "ip", "subdomain", "domain", "nameserver", "mailserver",
    "email", "network", "location", "organization", "service", "url",
    "account", "breach", "port", "phone", "person", "lookalike",
]


def _norm(value: Any) -> str:
    return str(value).strip().rstrip(".").lower()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


class _GraphBuilder:
    """
    One or more scans (an investigation) into one graph. Each scan's target is
    a root; an entity equal to ANY target collapses onto that root, which is
    what joins pivoted scans together.
    """

    def __init__(self, scans: List[Any]):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: Dict[str, Dict[str, Any]] = {}
        self.multi = len(scans) > 1
        self.roots: Dict[str, str] = {}  # normalized target value -> root node id
        for scan in scans:
            value = _norm(scan.target_value)
            root_id = f"target:{value}"
            self.roots[value] = root_id
            node = self.nodes.setdefault(root_id, {
                "id": root_id, "kind": "target", "label": scan.target_value,
                "target_type": scan.target_type.value, "sources": [], "details": {}, "risk": None,
            })
            node["details"].setdefault("scan_ids", []).append(str(scan.id))
        self.root_id = f"target:{_norm(scans[0].target_value)}"

    # ── primitives ──────────────────────────────────────────
    def entity(self, kind: str, value: Any, source: Optional[str] = None,
               label: Optional[str] = None, details: Optional[Dict[str, Any]] = None,
               risk: Optional[str] = None) -> Optional[str]:
        if value is None or str(value).strip() == "":
            return None
        key = _norm(value)
        # A scan target is its root node, whatever kind it was found as
        if key in self.roots:
            node = self.nodes[self.roots[key]]
        else:
            node_id = f"{kind}:{key}"
            node = self.nodes.get(node_id)
            if node is None:
                node = self.nodes[node_id] = {
                    "id": node_id,
                    "kind": kind,
                    "label": label or str(value).strip().rstrip("."),
                    "sources": [],
                    "details": {},
                    "risk": None,
                }
        if source and source not in node["sources"]:
            node["sources"].append(source)
        if details:
            for k, v in details.items():
                if v not in (None, "", [], {}):
                    node["details"].setdefault(k, v)
        if risk == "high" or (risk and not node["risk"]):
            node["risk"] = risk
        return node["id"]

    def source_node(self, source: str) -> str:
        # Per scan when several scans share the graph, so each source hangs off its own target
        node_id = f"source:{self.current_scan}:{_norm(source)}" if self.multi else f"source:{_norm(source)}"
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id, "kind": "source", "label": source,
                "sources": [source], "details": {"findings": 0}, "risk": None,
            }
            self.link(self.current_root, node_id, "checked by")
        self.nodes[node_id]["details"]["findings"] += 1
        return node_id

    def link(self, a: Optional[str], b: Optional[str], label: str):
        if not a or not b or a == b:
            return
        edge_id = f"{a}->{b}"
        if edge_id not in self.edges and f"{b}->{a}" not in self.edges:
            self.edges[edge_id] = {"id": edge_id, "source": a, "target": b, "label": label}

    def found(self, src: str, kind: str, value: Any, rel: str, **kw) -> Optional[str]:
        """Entity reported by a source: create it and link source -> entity."""
        node_id = self.entity(kind, value, source=self.nodes[src]["label"], **kw)
        self.link(src, node_id, rel)
        return node_id

    def emails_in(self, src: str, values: Iterable[Any], rel: str):
        for v in values:
            for email in EMAIL_RE.findall(str(v)):
                self.found(src, "email", email, rel)

    # ── per data type ───────────────────────────────────────
    current_scan: str = ""
    current_root: str = ""

    def add(self, result) -> None:
        data = result.data or {}
        src = self.source_node(result.source)
        dt = result.data_type

        if dt == "dns_record":
            rtype = str(data.get("record_type", "")).upper()
            for rec in _as_list(data.get("records")):
                if rtype in ("A", "AAAA"):
                    self.found(src, "ip", rec, f"{rtype} record")
                elif rtype == "NS":
                    self.found(src, "nameserver", rec, "nameserver")
                elif rtype == "MX":
                    host = rec.get("exchange") if isinstance(rec, dict) else rec
                    self.found(src, "mailserver", host, "MX record",
                               details={"priority": rec.get("priority")} if isinstance(rec, dict) else None)
                elif rtype == "CNAME":
                    self.found(src, "domain", rec, "CNAME")
                elif rtype == "TXT":
                    m = VERIFICATION_RE.match(str(rec).strip('"'))
                    if m:
                        self.found(src, "service", m.group(1).replace("_", "").lower(), "verified with",
                                   label=m.group(1).strip("_").replace("-", " ").title())

        elif dt == "domain_registration":
            self.found(src, "organization", data.get("registrar"), "registrar", details={"role": "registrar"})
            if data.get("org"):
                self.found(src, "organization", data.get("org"), "registrant")
            for ns in _as_list(data.get("name_servers")):
                self.found(src, "nameserver", ns, "nameserver")
            self.emails_in(src, _as_list(data.get("emails")), "contact")
            root = self.nodes[self.current_root]["details"]
            for key in ("creation_date", "expiration_date", "updated_date", "country"):
                if data.get(key):
                    root.setdefault(key, data[key])

        elif dt in ("email_address", "email_infrastructure"):
            record = str(data.get("record", ""))
            for addr in re.findall(r"mailto:([^,;\s\"]+)", record) or EMAIL_RE.findall(record):
                self.found(src, "email", addr, "reports to")
            for inc in re.findall(r"include:([^\s\"]+)", record):
                self.found(src, "domain", inc, "SPF include")
            for ip in re.findall(r"ip[46]:([^\s\"/]+)", record):
                self.found(src, "ip", ip, "SPF allows")

        elif dt in ("subdomain", "email_subdomain"):
            host = data.get("full_domain") or data.get("subdomain")
            if data.get("exists", True):
                sub = self.found(src, "subdomain", host, "subdomain",
                                 details={"mail": True if dt == "email_subdomain" else None,
                                          "live": data.get("live")})
                for ip in _as_list(data.get("ip_addresses")):
                    self.link(sub, self.entity("ip", ip, source=result.source), "resolves to")

        elif dt == "subdomains":
            for host in _as_list(data.get("subdomains")):
                self.found(src, "subdomain", host, "subdomain")

        elif dt in ("ip_info", "ip_intel"):
            ip = self.found(src, "ip", data.get("ip_address") or data.get("ip"), "inspected")
            if data.get("reverse_hostname"):
                self.link(ip, self.entity("domain", data["reverse_hostname"], source=result.source), "reverse DNS")
            if data.get("asn"):
                net = self.entity("network", f"AS{data['asn']}", source=result.source,
                                  label=f"AS{data['asn']} {data.get('asn_description') or ''}".strip(),
                                  details={"cidr": data.get("cidr"), "name": data.get("network_name")})
                self.link(ip, net, "announced by")
            geo = data.get("geo") or {}
            place = ", ".join(p for p in (geo.get("city"), geo.get("country")) if p)
            if place:
                self.link(ip, self.entity("location", place, source=result.source,
                                          details={"lat": geo.get("lat"), "lon": geo.get("lon")}), "located in")
            for host in _as_list(data.get("domains") or data.get("hosted_domains")):
                self.link(ip, self.entity("domain", host, source=result.source), "also hosts")

        elif dt == "open_ports":
            ip = self.entity("ip", data.get("ip") or data.get("ip_address"), source=result.source)
            for p in _as_list(data.get("open_ports")):
                if not isinstance(p, dict):
                    continue
                label = f"{p.get('port')}/{p.get('protocol', 'tcp')} {p.get('name') or ''}".strip()
                port = self.found(src, "port", f"{ip or ''}:{p.get('port')}", "open port", label=label,
                                  details={"product": p.get("product")})
                self.link(ip, port, "listens on")

        elif dt == "infostealer":
            n = data.get("infection_count") or len(data.get("infections") or [])
            self.found(src, "breach", f"infostealer:{self.current_root}", "infected device", risk="high",
                       label=f"Infostealer infection{'s' if n != 1 else ''} ({n})",
                       details={"latest": data.get("latest")})

        elif dt == "infostealer_domain":
            n = (data.get("employee_infections") or 0) + (data.get("user_infections") or 0)
            hit = self.found(src, "breach", f"infostealer-domain:{self.current_root}", "stolen logins", risk="high",
                             label=f"Infostealer logs ({n} logins)",
                             details={"employee_infections": data.get("employee_infections"),
                                      "user_infections": data.get("user_infections")})
            for u in _as_list(data.get("employee_login_urls"))[:8]:
                self.link(hit, self.entity("url", u, source=result.source,
                                           label=urlparse(u).netloc + urlparse(u).path[:24]), "employee login")

        elif dt == "pgp_key":
            key = data.get("key") or {}
            fp = key.get("fingerprint") or data.get("keyserver")
            node = self.found(src, "account", f"pgp:{fp}", "PGP key",
                              label=f"PGP key {str(fp)[-8:]}" + ("" if data.get("verified") else " (unverified)"),
                              details={"verified": data.get("verified"), "created": key.get("created"),
                                       "keyserver": data.get("keyserver")},
                              risk=None if data.get("verified") else "low")
            for uid in _as_list(key.get("uids")):
                for email in EMAIL_RE.findall(uid):
                    self.link(node, self.entity("email", email, source=result.source), "key for")
                name = re.sub(r"<[^>]*>|\([^)]*\)", "", uid).strip()
                if name and "@" not in name:
                    self.link(node, self.entity("person", name, source=result.source), "key owner")

        elif dt == "ip_reputation":
            ip = self.entity("ip", data.get("ip"), source=result.source)
            node = self.nodes.get(ip) if ip else None
            if node:
                if data.get("scanning_internet"):
                    node["details"]["greynoise"] = data.get("classification") or "scanning"
                    if data.get("classification") == "malicious":
                        node["risk"] = "high"
                if data.get("known_benign_service"):
                    node["details"]["known_service"] = data.get("name")
                if data.get("abuse_score") is not None:
                    node["details"]["abuse_score"] = data["abuse_score"]
                    if data["abuse_score"] >= 50:
                        node["risk"] = "high"

        elif dt == "org_profile":
            root = self.nodes[self.current_root]["details"]
            for key in ("description", "founded", "industry", "employees", "legal_form", "wikidata_id", "lei"):
                if data.get(key):
                    root.setdefault(key, data[key])
            if data.get("website"):
                host = urlparse(data["website"]).hostname or data["website"]
                self.found(src, "domain", host.removeprefix("www."), "official website")
            for key, rel in (("headquarters", "headquartered in"), ("country", "country")):
                if data.get(key):
                    self.found(src, "location", data[key], rel)
            if data.get("parent_organization"):
                self.found(src, "organization", data["parent_organization"], "parent company")
            for sub in _as_list(data.get("subsidiaries")):
                self.found(src, "organization", sub, "subsidiary")
            for person in _as_list(data.get("ceo")) + _as_list(data.get("founders")):
                self.found(src, "person", person, "CEO" if person == data.get("ceo") else "founder")
            for key, base, label in (("x_handle", "https://x.com/", "X"), ("github", "https://github.com/", "GitHub"),
                                     ("linkedin_company", "https://www.linkedin.com/company/", "LinkedIn"),
                                     ("facebook", "https://www.facebook.com/", "Facebook")):
                if data.get(key):
                    self.found(src, "account", base + str(data[key]).lstrip("@"), "official account",
                               label=f"{label} @{str(data[key]).lstrip('@')}")

        elif dt == "legal_entity":
            org = self.found(src, "organization", data.get("lei") or data.get("company_number") or data.get("name"),
                             "legal entity", label=data.get("name"),
                             details={"lei": data.get("lei"), "status": data.get("status"),
                                      "jurisdiction": data.get("jurisdiction"), "registered": data.get("incorporated")})
            place = ", ".join(p for p in (data.get("city"), data.get("country")) if p)
            if place:
                self.link(org, self.entity("location", place, source=result.source), "registered in")

        elif dt == "lookalike_domain":
            look = self.found(src, "lookalike", data.get("domain"), data.get("technique") or "lookalike",
                              details={"technique": data.get("technique"),
                                       "receives_mail": data.get("can_receive_mail")},
                              risk="medium" if data.get("can_receive_mail") else None)
            for ip in _as_list(data.get("ip_addresses"))[:4]:
                self.link(look, self.entity("ip", ip, source=result.source), "resolves to")
            for mx in _as_list(data.get("mail_servers"))[:3]:
                self.link(look, self.entity("mailserver", mx, source=result.source), "MX record")

        elif dt == "web_hygiene":
            root = self.nodes[self.current_root]["details"]
            if data.get("favicon_hash") is not None:
                root.setdefault("favicon_hash", data["favicon_hash"])
            for contact in _as_list((data.get("security_txt") or {}).get("contact")):
                for email in EMAIL_RE.findall(contact):
                    self.found(src, "email", email, "security contact")

        elif dt == "mail_security":
            root = self.nodes[self.current_root]["details"]
            root.setdefault("dkim_selectors", ", ".join(data.get("dkim_selectors") or []) or None)
            root.setdefault("mta_sts", data.get("mta_sts"))

        elif dt == "host_exposure":
            ip = self.found(src, "ip", data.get("ip"), "exposure",
                            details={"known_cves": len(data.get("vulns") or []) or None,
                                     "software": ", ".join((data.get("software") or [])[:5]) or None},
                            risk="high" if data.get("vulns") else None)
            for port in _as_list(data.get("ports")):
                self.link(ip, self.entity("port", f"{data.get('ip')}:{port}", source=result.source,
                                          label=f"{port}/tcp"), "listens on")
            for host in _as_list(data.get("hostnames"))[:10]:
                self.link(ip, self.entity("domain", host, source=result.source), "serves")

        elif dt == "web_scan":
            host = self.found(src, "domain", data.get("domain"), "scanned page")
            if data.get("ip"):
                self.link(host, self.entity("ip", data["ip"], source=result.source), "resolves to")

        elif dt == "reputation" and "malicious" in data:
            root = self.nodes[self.current_root]
            root["details"].setdefault("virustotal_malicious", data.get("malicious"))
            if data.get("malicious"):
                root["risk"] = "high"

        elif dt == "webpage_info":
            self.emails_in(src, _as_list(data.get("visible_emails")), "listed on site")
            for link in _as_list(data.get("social_links")):
                self.found(src, "url", link, "links to")
            ents = data.get("nlp_entities") or {}
            for org in _as_list(ents.get("organizations"))[:8]:
                self.found(src, "organization", org, "mentions")

        elif dt in ("account_existence", "social_profile"):
            if data.get("exists"):
                platform = data.get("platform") or result.source
                profile = data.get("profile") or {}
                acct = self.found(src, "account", data.get("url") or platform, "account on", label=platform,
                                  details={"url": data.get("url"), "username": data.get("username"),
                                           **{k: profile.get(k) for k in ("name", "bio", "followers", "created")}})
                self._profile_links(acct, result.source, profile)

        elif dt == "profile":
            if data.get("has_profile"):
                acct = self.found(src, "account", data.get("profile_url") or data.get("avatar_url") or result.source,
                                  "profile", label=result.source,
                                  details={"name": data.get("name"), "url": data.get("profile_url"),
                                           "job_title": data.get("job_title")})
                self._profile_links(acct, result.source, data)

        elif dt == "breach":
            name = data.get("name") or f"{data.get('leaks_found', '?')} leak signals"
            classes = data.get("data_classes") or []
            breach = self.found(src, "breach", name, "exposed in", risk=data.get("risk") or "high",
                                details={"date": data.get("breach_date"), "records": data.get("records"),
                                         "exposed": ", ".join(classes[:8]) if classes else None})
            if data.get("domain"):
                self.link(breach, self.entity("domain", data["domain"], source=result.source), "breached site")

        elif dt == "web_server":
            for tech in _as_list(data.get("technologies"))[:12]:
                if isinstance(tech, dict) and tech.get("name"):
                    self.found(src, "service", f"tech:{tech['name']}", "uses", label=tech["name"],
                               details={"category": tech.get("category")})
            tls = data.get("tls") or {}
            if tls.get("issuer"):
                self.found(src, "organization", tls["issuer"], "TLS issued by", details={"role": "certificate authority"})
            final = urlparse(data.get("final_url") or "").hostname
            if final:
                self.found(src, "domain", final, "redirects to")
            root = self.nodes[self.current_root]["details"]
            for key in ("status", "server", "title"):
                if data.get(key):
                    root.setdefault(f"web_{key}", data[key])

        elif dt == "web_history":
            root = self.nodes[self.current_root]["details"]
            root.setdefault("first_archived", data.get("first_capture"))

        elif dt == "email_validation":
            for mx in _as_list(data.get("mx_records")):
                self.found(src, "mailserver", mx.get("exchange") if isinstance(mx, dict) else mx, "MX record")
            if data.get("is_disposable"):
                self.nodes[self.current_root]["risk"] = "high"

        elif dt == "phone_info":
            if data.get("carrier"):
                self.found(src, "organization", data["carrier"], "carrier")
            if data.get("location"):
                self.found(src, "location", data["location"], "registered in")

        elif dt == "dork_result":
            url = data.get("url")
            if url:
                parsed = urlparse(url)
                label = (parsed.netloc + (parsed.path if len(parsed.path) < 32 else parsed.path[:30] + "…"))
                page = self.found(src, "url", url, "mentioned at", label=label,
                                  details={"title": data.get("title"), "query": data.get("query")})
                for email in _as_list(data.get("emails")):
                    self.link(page, self.entity("email", email, source=result.source), "lists")

    def _profile_links(self, acct: Optional[str], source: str, profile: Dict[str, Any]) -> None:
        """Websites, locations, employers and linked accounts named on a public profile."""
        if not acct:
            return
        for key in ("website", "blog"):
            if profile.get(key):
                url = profile[key] if "://" in str(profile[key]) else f"https://{profile[key]}"
                self.link(acct, self.entity("url", url, source=source, label=urlparse(url).netloc or url), "website")
        for url in _as_list(profile.get("links")):
            if isinstance(url, str) and url.startswith("http"):
                self.link(acct, self.entity("url", url, source=source, label=urlparse(url).netloc + urlparse(url).path[:24]), "links to")
        if profile.get("location"):
            self.link(acct, self.entity("location", profile["location"], source=source), "located in")
        if profile.get("company"):
            self.link(acct, self.entity("organization", str(profile["company"]).lstrip("@"), source=source), "works at")
        if profile.get("email"):
            self.link(acct, self.entity("email", profile["email"], source=source), "public email")
        for handle_key, base in (("twitter", "https://x.com/"), ("github", "https://github.com/")):
            if profile.get(handle_key):
                url = base + str(profile[handle_key]).lstrip("@")
                self.link(acct, self.entity("account", url, source=source, label=f"{'X' if handle_key == 'twitter' else 'GitHub'} @{profile[handle_key]}"), "same person")
        for repo in _as_list(profile.get("repositories"))[:10]:
            self.link(acct, self.entity("url", f"https://github.com/{repo}", source=source, label=repo), "commits to")
        for linked in _as_list(profile.get("linked_accounts")) + _as_list(profile.get("verified_accounts")):
            if not isinstance(linked, dict):
                continue
            service = linked.get("service") or "account"
            url = linked.get("url")
            handle = linked.get("handle")
            if service == "dns" and handle:
                self.link(acct, self.entity("domain", handle, source=source), "proves ownership")
            elif url or handle:
                self.link(acct, self.entity("account", url or f"{service}:{handle}", source=source,
                                            label=f"{service} {('@' + handle) if handle else ''}".strip()), "same person")

    def _merge_urls_into_accounts(self) -> None:
        """A search hit for https://github.com/x IS the GitHub account node: fold it in."""
        def key(url: str) -> str:
            u = urlparse(url if "://" in url else f"https://{url}")
            return (u.netloc.lower().removeprefix("www.") + u.path.rstrip("/").lower())

        accounts = {key(n["id"].split(":", 1)[1]): n["id"] for n in self.nodes.values() if n["kind"] == "account"}
        for node_id in [n["id"] for n in self.nodes.values() if n["kind"] == "url"]:
            target = accounts.get(key(node_id.split(":", 1)[1]))
            if not target:
                continue
            url_node, acct = self.nodes.pop(node_id), self.nodes[target]
            for src in url_node["sources"]:
                if src not in acct["sources"]:
                    acct["sources"].append(src)
            for edge_id, e in list(self.edges.items()):
                if node_id in (e["source"], e["target"]):
                    del self.edges[edge_id]
                    a = target if e["source"] == node_id else e["source"]
                    b = target if e["target"] == node_id else e["target"]
                    self.link(a, b, e["label"])

    def build(self) -> Dict[str, Any]:
        self._merge_urls_into_accounts()
        degree: Dict[str, int] = {n: 0 for n in self.nodes}
        for e in self.edges.values():
            degree[e["source"]] = degree.get(e["source"], 0) + 1
            degree[e["target"]] = degree.get(e["target"], 0) + 1
        nodes = []
        for n in self.nodes.values():
            # Drop sources that produced no entity (e.g. TLDExtract)
            if n["kind"] == "source" and degree.get(n["id"], 0) <= 1:
                continue
            nodes.append({**n, "degree": degree.get(n["id"], 0)})
        kept = {n["id"] for n in nodes}
        edges = [e for e in self.edges.values() if e["source"] in kept and e["target"] in kept]
        counts: Dict[str, int] = {}
        for n in nodes:
            counts[n["kind"]] = counts.get(n["kind"], 0) + 1
        return {"nodes": nodes, "edges": edges, "kinds": [k for k in KINDS if k in counts], "counts": counts}


def build_graph(scans_with_results: List[tuple]) -> Dict[str, Any]:
    """[(scan, results), ...] -> graph. Pivot lineage becomes explicit edges."""
    builder = _GraphBuilder([scan for scan, _ in scans_with_results])
    for scan, results in scans_with_results:
        builder.current_scan = str(scan.id)
        builder.current_root = builder.roots[_norm(scan.target_value)]
        for result in results:
            try:
                builder.add(result)
            except Exception:  # one malformed result must not break the whole graph
                continue
    by_id = {str(scan.id): scan for scan, _ in scans_with_results}
    for scan, _ in scans_with_results:
        parent = by_id.get(str(scan.parent_scan_id)) if getattr(scan, "parent_scan_id", None) else None
        if parent:
            builder.link(builder.roots[_norm(parent.target_value)], builder.roots[_norm(scan.target_value)], "pivoted to")
    return builder.build()


def build_entity_graph(scan, results) -> Dict[str, Any]:
    return build_graph([(scan, results)])
