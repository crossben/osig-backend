"""
Document metadata harvesting (background module; domain targets).

Finds public documents on the domain (DuckDuckGo via ddgs, filetype: dorks,
plus document links the search-dork module already found in this scan),
downloads at most MAX_DOCS through safe_http.safe_get (SSRF-safe, bodies capped
at 2 MB) within a time budget, and reads their metadata:
- PDF: pypdf document info (author, creator, producer, dates)
- docx/xlsx/pptx: docProps/core.xml + app.xml, parsed with defusedxml (no XXE /
  entity expansion) and size-checked before decompression (no zip bombs).

Terms: only documents the site publishes; ddgs is the same free search used by
google_dork. Nothing is executed or rendered.
"""
import io
import re
import time
import zipfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.osint.base import BaseOSINTModule, OSINTResult, prior_results

EXTENSIONS = ("pdf", "docx", "xlsx", "pptx")
MAX_DOCS = 10
TIME_BUDGET = 38
MAX_XML_BYTES = 512 * 1024
PDF_DATE = re.compile(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?")
NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}


def _ext(url: str) -> Optional[str]:
    path = urlparse(url).path.lower()
    return next((e for e in EXTENSIONS if path.endswith("." + e)), None)


def _on_domain(url: str, domain: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host == domain or host.endswith("." + domain)


def _pdf_date(value: Any) -> Optional[str]:
    m = PDF_DATE.match(str(value or ""))
    if not m:
        return None
    y, mo, d, h, mi, s = (g or "00" for g in m.groups())
    mo, d = mo if mo != "00" else "01", d if d != "00" else "01"
    return f"{y}-{mo}-{d}T{h}:{mi}:{s}"


def _text(value: Any) -> Optional[str]:
    value = " ".join(str(value).split()) if value is not None else ""
    return value[:120] or None


def pdf_metadata(body: bytes) -> Dict[str, Any]:
    from pypdf import PdfReader
    info = PdfReader(io.BytesIO(body)).metadata or {}
    return {
        "title": _text(info.get("/Title")), "author": _text(info.get("/Author")),
        "creator": _text(info.get("/Creator")), "producer": _text(info.get("/Producer")),
        "document_created": _pdf_date(info.get("/CreationDate")),
        "document_modified": _pdf_date(info.get("/ModDate")),
    }


def office_metadata(body: bytes) -> Dict[str, Any]:
    from defusedxml import ElementTree as ET

    out: Dict[str, Any] = {}
    with zipfile.ZipFile(io.BytesIO(body)) as zf:
        def xml(name: str):
            try:
                info = zf.getinfo(name)
            except KeyError:
                return None
            if info.file_size > MAX_XML_BYTES:
                return None
            return ET.fromstring(zf.read(info))

        core = xml("docProps/core.xml")
        if core is not None:
            def get(tag: str):
                el = core.find(tag, NS)
                return el.text if el is not None else None
            out.update({"title": _text(get("dc:title")), "author": _text(get("dc:creator")),
                        "last_modified_by": _text(get("cp:lastModifiedBy")),
                        "document_created": _text(get("dcterms:created")),
                        "document_modified": _text(get("dcterms:modified"))})
        app = xml("docProps/app.xml")
        if app is not None:
            def aget(tag: str):
                el = app.find(f"ep:{tag}", NS)
                return el.text if el is not None else None
            tool = " ".join(x for x in (aget("Application"), aget("AppVersion")) if x)
            out.update({"creator": _text(tool), "company": _text(aget("Company"))})
    return out


def extract(body: bytes, ext: str) -> Dict[str, Any]:
    meta = pdf_metadata(body) if ext == "pdf" else office_metadata(body)
    return {k: v for k, v in meta.items() if v}


def find_documents(domain: str, known_urls: List[str]) -> List[str]:
    urls = [u for u in known_urls if _ext(u) and _on_domain(u, domain)]
    try:
        from ddgs import DDGS
        query = f"site:{domain} " + " OR ".join(f"filetype:{e}" for e in EXTENSIONS)
        with DDGS(timeout=10) as ddgs:
            for hit in ddgs.text(query, max_results=25):
                url = hit.get("href") or hit.get("url") or ""
                if _ext(url) and _on_domain(url, domain):
                    urls.append(url)
    except Exception:
        pass
    return list(dict.fromkeys(urls))[:MAX_DOCS]


class DocMetadataModule(BaseOSINTModule):
    def __init__(self):
        super().__init__(name="doc_metadata", display_name="Document Metadata")

    def run(self, target: str, scan_id: Optional[str] = None) -> List[OSINTResult]:
        from app.osint.safe_http import safe_get
        self.log_start(target)
        domain = target.strip().lower()
        known = [str((r.data or {}).get("url") or "") for r in prior_results(scan_id) if r.data_type == "dork_result"]
        start = time.time()
        results: List[OSINTResult] = []
        for url in find_documents(domain, known):
            if time.time() - start > TIME_BUDGET:
                break
            try:
                resp = safe_get(url, timeout=8, headers={"User-Agent": "OSIG/1.0"})
                if resp.status_code != 200:
                    continue
                meta = extract(resp.content, _ext(url))
            except Exception as e:  # truncated, encrypted or malformed files are skipped
                self.logger.info(f"Metadata read failed for {url}: {e}")
                continue
            if not meta:
                continue
            results.append(OSINTResult(source="Document Metadata", source_url=url, data_type="document_metadata",
                                       data={"url": url, "file_type": _ext(url), **meta}, confidence=0.9))
        if results:
            people = sorted({r.data[k] for r in results for k in ("author", "last_modified_by") if r.data.get(k)})
            software = sorted({r.data[k] for r in results for k in ("creator", "producer") if r.data.get(k)})
            companies = sorted({r.data["company"] for r in results if r.data.get("company")})
            results.append(OSINTResult(source="Document Metadata", data_type="document_metadata_summary",
                                       data={"domain": domain, "documents": len(results), "people": people[:30],
                                             "software": software[:30], "companies": companies[:10]},
                                       confidence=0.9))
        self.log_success(len(results))
        return results
