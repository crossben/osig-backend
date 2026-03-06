"""
OSIG Backend - Scan API Endpoints

Handles scan creation, listing, and management.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from math import ceil

from app.core.deps import get_db, get_current_user
from app.schemas.scan import (
    CreateScanRequest,
    ScanResponse,
    ScanListResponse,
    ScanQueryParams
)
from app.models.scan import ScanStatus, TargetType, ScanType
from app.models.user import User
from app.services.scan_service import scan_service

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    scan_data: CreateScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new OSINT scan.
    
    - **target_type**: Type of target (email, username, domain, phone)
    - **target_value**: The actual target value
    - **scan_type**: Scan depth (quick or deep)
    - **disclaimer_accepted**: Must be true
    
    Quota limits apply based on user plan:
    - Free: 5 scans/day
    - Pro: 50 scans/day
    - Enterprise: Unlimited
    """
    scan = scan_service.create_scan(db, current_user, scan_data)
    return ScanResponse.model_validate(scan)


@router.get("", response_model=ScanListResponse)
def list_scans(
    status: Optional[ScanStatus] = Query(None, description="Filter by status"),
    target_type: Optional[TargetType] = Query(None, description="Filter by target type"),
    scan_type: Optional[ScanType] = Query(None, description="Filter by scan type"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List user's scans with pagination and filtering.
    
    Returns paginated list of scans with total count.
    """
    # Build query params
    params = ScanQueryParams(
        status=status,
        target_type=target_type,
        scan_type=scan_type,
        page=page,
        page_size=page_size
    )
    
    # Get scans
    scans, total = scan_service.get_user_scans(db, str(current_user.id), params)
    
    # Build response
    return ScanListResponse(
        scans=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=ceil(total / page_size) if total > 0 else 0
    )


@router.get("/quota/status")
def get_quota_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get user's current scan quota status.
    
    Returns used scans today and daily limit.
    """
    has_quota, used_today, daily_limit = scan_service.check_scan_quota(db, current_user)
    
    return {
        "plan": current_user.plan.value,
        "daily_limit": daily_limit,
        "used_today": used_today,
        "remaining": daily_limit - used_today,
        "has_quota": has_quota
    }


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get scan details by ID.
    
    User must own the scan.
    """
    scan = scan_service.get_scan(db, scan_id, str(current_user.id))
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}/details")
def get_scan_details(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get full scan details including modules, results, sources.
    """
    from app.models.scan import ScanModule
    from app.models.result import Result

    scan = scan_service.get_scan(db, scan_id, str(current_user.id))
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    scan_data = ScanResponse.model_validate(scan)

    # Load modules and results from actual DB rows
    db_modules = db.query(ScanModule).filter(ScanModule.scan_id == scan.id).all()
    db_results = db.query(Result).filter(Result.scan_id == scan.id).all()

    modules_out = [
        {
            "id": str(m.id),
            "scan_id": str(m.scan_id),
            "name": m.name,
            "display_name": m.display_name,
            "status": m.status,
            "progress": m.progress,
            "started_at": m.started_at.isoformat() if m.started_at else None,
            "completed_at": m.completed_at.isoformat() if m.completed_at else None,
            "result_count": m.result_count,
            "error": m.error,
        }
        for m in db_modules
    ]

    results_out = [
        {
            "id": str(r.id),
            "scan_id": str(r.scan_id),
            "module_id": str(r.module_id),
            "module": r.module,
            "data_type": r.data_type,
            "data": r.data,
            "source": r.source,
            "source_url": r.source_url,
            "confidence": r.confidence,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in db_results
    ]

    total_results = len(db_results)
    unique_sources = list({r.source for r in db_results})

    status_label = scan.status.value
    top_findings = []
    if status_label in ("pending", "running"):
        top_findings = [f"Scan is currently {status_label}..."]
    elif total_results > 0:
        top_findings = [f"Found {total_results} result(s) across {len(unique_sources)} source(s)"]
        for r in db_results[:3]:
            top_findings.append(f"{r.source}: {r.data_type}")
    else:
        top_findings = ["No results found for this target."]

    return {
        "scan": scan_data,
        "modules": modules_out,
        "results": results_out,
        "sources": [
            {"id": s, "name": s, "url": "", "category": "osint", "last_checked": None, "reliability": 0.8, "data_types": []}
            for s in unique_sources
        ],
        "risk_flags": [],
        "summary": {
            "total_results": total_results,
            "total_sources": len(unique_sources),
            "risk_score": 0,
            "data_categories": list({r.data_type for r in db_results}),
            "top_findings": top_findings,
        }
    }

@router.get("/{scan_id}/graph")
def get_scan_graph(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Build a semantic relationship graph from scan results.
    Nodes are grouped by source/platform. Edges describe the relationship type.
    """
    from app.models.result import Result

    scan = scan_service.get_scan(db, scan_id, str(current_user.id))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    db_results = db.query(Result).filter(Result.scan_id == scan.id).all()

    nodes = []
    edges = []

    # Root node: the scan target
    root_id = f"target-{scan_id}"
    nodes.append({
        "id": root_id,
        "type": str(scan.target_type.value),
        "label": scan.target_value,
        "data": {
            "target_type": scan.target_type.value,
            "scan_type": scan.scan_type.value,
            "status": scan.status.value,
        },
        "found": True,
        "risk_level": None,
        "is_root": True,
    })

    # Group results by source platform to avoid duplicate nodes
    # source_key → merged node data
    source_groups: dict = {}
    for result in db_results:
        data = result.data or {}
        source = result.source

        # Determine if this result found something meaningful
        found = (
            data.get("exists") is True or
            data.get("has_profile") is True or
            data.get("domain_valid") is True or
            result.data_type == "dork_result" or
            result.data_type == "domain_registration" or
            result.data_type == "dns_record" or
            result.data_type == "subdomain" or
            result.data_type == "ip_info" or
            result.data_type == "email_infrastructure"
        )

        # Determine relationship label
        type_to_rel = {
            "social_profile": "registered on" if found else "not registered",
            "profile": "profile linked" if found else "no profile",
            "email_validation": "email validated",
            "dns_record": "DNS record",
            "domain_registration": "domain owner",
            "subdomain": "subdomain found",
            "ip_info": "resolves to IP",
            "email_infrastructure": "email infrastructure",
            "dork_result": "found via dork",
        }
        relationship = type_to_rel.get(result.data_type, result.data_type)

        # Determine node type
        type_map = {
            "social_profile": "social",
            "profile": "profile",
            "email_validation": "email",
            "dns_record": "domain",
            "domain_registration": "domain",
            "subdomain": "domain",
            "ip_info": "domain",
            "email_infrastructure": "domain",
            "dork_result": "profile",
        }
        node_type = type_map.get(result.data_type, "profile")

        # Risk detection heuristics
        risky = (
            data.get("is_disposable") is True or
            data.get("risk") == "high" or
            (result.data_type == "dork_result" and any(
                kw in str(data.get("snippet", "")).lower()
                for kw in ["password", "leaked", "breach", "dump", "credentials", "hack"]
            ))
        )

        if source not in source_groups:
            # Generate a node label
            label = (
                data.get("platform") or
                data.get("domain") or
                data.get("record_type") or
                source
            )
            source_groups[source] = {
                "id": f"node-{source.replace(' ', '_').lower()}",
                "type": node_type,
                "label": str(label),
                "source": source,
                "source_url": result.source_url,
                "found": found,
                "risk_level": "high" if risky else None,
                "results": [],
                "relationship": relationship,
            }
        else:
            # Upgrade found/risk status if any result in this group is positive
            if found:
                source_groups[source]["found"] = True
            if risky:
                source_groups[source]["risk_level"] = "high"

        source_groups[source]["results"].append({
            "data_type": result.data_type,
            "data": data,
            "confidence": result.confidence,
        })

    # Build final nodes and edges from groups
    for source, group in source_groups.items():
        nodes.append({
            "id": group["id"],
            "type": group["type"],
            "label": group["label"],
            "source": group["source"],
            "source_url": group["source_url"],
            "found": group["found"],
            "risk_level": group["risk_level"],
            "is_root": False,
            "data": {
                "results": group["results"],
                "result_count": len(group["results"]),
            },
        })
        edges.append({
            "id": f"edge-{root_id}-{group['id']}",
            "source": root_id,
            "target": group["id"],
            "label": group["relationship"],
            "found": group["found"],
        })

    # Optional: Use networkx to calculate node centrality (importance)
    try:
        import networkx as nx
        G = nx.Graph()
        for node in nodes:
            G.add_node(node["id"])
        for edge in edges:
            G.add_edge(edge["source"], edge["target"])
        
        # Compute centrality (degree centrality is safe for disconnected or strict star graphs)
        centrality = nx.degree_centrality(G)
        
        for node in nodes:
            # Map centrality score into the node properties (default to 0.1 if not found)
            node["data"]["centrality"] = centrality.get(node["id"], 0.1)
    except Exception as e:
        # Fallback if networkx isn't installed or fails
        pass

    return {"nodes": nodes, "edges": edges}


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Cancel a running scan.
    
    Only pending or running scans can be cancelled.
    """
    scan = scan_service.get_scan(db, scan_id, str(current_user.id))
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    scan = scan_service.cancel_scan(db, scan)
    return ScanResponse.model_validate(scan)
