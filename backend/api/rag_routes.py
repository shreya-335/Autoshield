# api/rag_routes.py
# FastAPI router for RAG endpoints.

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from rag.services.rag_service import analyze_vulnerability, analyze_batch
from rag.vector_store.chroma_client import get_collection_stats

router = APIRouter(prefix="/rag", tags=["RAG"])


# ── Request Models ────────────────────────────────────────────────────────────

class VulnerabilityRequest(BaseModel):
    code_snippet: str = Field(..., description="The vulnerable code snippet")
    cwe_id: str = Field(..., description="CWE ID e.g. 'CWE-89'")
    severity: str = Field(..., description="low | medium | high | critical")
    vuln_type: Optional[str] = Field(None, description="Vulnerability type from static tool")
    # Extended fields used by Chrome extension
    file_path: Optional[str] = Field("unknown", description="File path or page URL")
    line: Optional[int] = Field(0, description="Line number (0 for browser extension)")
    tool: Optional[str] = Field("unknown", description="Scanner tool name")
    use_llm: Optional[bool] = Field(True, description="Whether to invoke LLM reasoning layer")


class BatchRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., description="List of static findings to analyze")
    use_llm: Optional[bool] = Field(False, description="LLM for batch (default off for speed)")


# ── NOTE: RAGResponse model removed ──────────────────────────────────────────
# Previously this route used response_model=RAGResponse which was a Pydantic
# model with only 5 fields (owasp_category, related_cves, exploitability,
# confidence, context_chunks). This caused FastAPI to STRIP the full verdict
# returned by build_final_verdict() — so risk_score, risk_category, reasoning,
# fix_code, key_risks, recommended_fix etc. never reached the Chrome extension.
#
# Fix: remove response_model so the full Dict is returned as-is.
# The Chrome extension sidepanel.js already knows how to render all these fields.
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/analyze")
async def analyze(request: VulnerabilityRequest):
    """
    Main RAG endpoint — Tri-Layer analysis (Static + RAG + LLM).

    Returns full verdict including:
      risk_score, risk_category, owasp_category, related_cves,
      key_risks, recommended_fix, fix_code, reasoning,
      conflict_resolution trace, score_components breakdown.

    Used by both the VS Code extension and Chrome extension sidepanel.
    """
    try:
        result = analyze_vulnerability(
            code_snippet=request.code_snippet,
            cwe_id=request.cwe_id,
            severity=request.severity,
            vuln_type=request.vuln_type or "",
            file_path=request.file_path or "unknown",
            line=request.line or 0,
            tool=request.tool or "unknown",
            use_llm=request.use_llm if request.use_llm is not None else True,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze-batch")
async def analyze_batch_endpoint(request: BatchRequest):
    """
    Batch analysis endpoint for multiple findings at once.
    Used by VS Code extension full-scan mode.
    LLM disabled by default for speed — enable with use_llm=true.
    """
    try:
        results = analyze_batch(
            findings=request.findings,
            use_llm=request.use_llm if request.use_llm is not None else False,
        )
        return {"results": results, "count": len(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health():
    """Check RAG system health and document count."""
    try:
        stats = get_collection_stats()
        return {
            "status": "ok",
            "collection": stats["name"],
            "documents_indexed": stats["count"],
        }
    except Exception as e:
        return {
            "status": "degraded",
            "error": str(e),
            "documents_indexed": 0,
        }