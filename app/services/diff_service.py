"""
What changed between two scans of the same kind of target: entity-level diff
built on the entity graph (so 'new subdomain', 'new breach', 'MX changed').
Used by watch alerts, the watch changes view and scan compare.
"""
from typing import Dict

from sqlalchemy.orm import Session

from app.models.result import Result
from app.models.scan import Scan, ScanStatus
from app.services.graph_service import build_entity_graph


def entities(db: Session, scan: Scan, include_search: bool = False) -> Dict[str, dict]:
    results = db.query(Result).filter(Result.scan_id == scan.id).all()
    if not include_search:
        # Search-engine hits reshuffle between runs; they'd drown real changes
        results = [r for r in results if r.data_type != "dork_result"]
    graph = build_entity_graph(scan, results)
    return {n["id"]: {"id": n["id"], "kind": n["kind"], "label": n["label"]}
            for n in graph["nodes"] if n["kind"] not in ("target", "source")}


def finished(scan: Scan) -> bool:
    """Completed AND every module (incl. background ones) has answered."""
    return scan.status == ScanStatus.COMPLETED and all(
        m.status.value not in ("pending", "running") for m in scan.modules)


def diff(db: Session, before_scan: Scan, after_scan: Scan, include_search: bool = False) -> dict:
    before, after = entities(db, before_scan, include_search), entities(db, after_scan, include_search)
    key = lambda e: (e["kind"], e["label"])  # noqa: E731
    return {
        "added": sorted((after[k] for k in after.keys() - before.keys()), key=key),
        "removed": sorted((before[k] for k in before.keys() - after.keys()), key=key),
        "unchanged": len(after.keys() & before.keys()),
    }
