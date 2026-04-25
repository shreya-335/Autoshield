# backend/main.py

import asyncio
import sys

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import List, Optional
import models
import database
import scanner
from crawler import scan_website_runtime

# RAG imports
from rag.retrieval.retriever import retrieve_context
from rag.services.rag_service import analyze_vulnerability, analyze_batch
from rag.services.llm_service import generate_fix_for_snippet

app = FastAPI(title="AutoShield API", version="2.0.0")

# ──────────────────────────────────────────────────────────────────────
# CORS
# ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────────────────────
# Request / Response Models
# ──────────────────────────────────────────────────────────────────────
class RAGRequest(BaseModel):
    code_snippet: str = Field(..., description="The vulnerable code or message")
    cwe_id: str = Field(default="CWE-Unknown")
    severity: str = Field(default="medium")
    vuln_type: str = Field(default="")
    file_path: str = Field(default="unknown")
    line: int = Field(default=0)
    tool: str = Field(default="unknown")
    use_llm: bool = Field(default=True)


class FullScanRequest(BaseModel):
    path: str = Field(..., description="Absolute path to the project directory")
    use_llm: bool = Field(default=True)


class ApplyFixRequest(BaseModel):
    file_path: str = Field(..., description="Absolute path to the file to fix")
    line: int = Field(..., description="Line number of the vulnerability (1-indexed)")
    original_code: str = Field(..., description="The vulnerable code snippet")
    fix_code: str = Field(..., description="The corrected code to apply")


class GenerateFixRequest(BaseModel):
    code_snippet: str
    vuln_type: str = ""
    cwe_id: str = "CWE-Unknown"


# ──────────────────────────────────────────────────────────────────────
# Startup
# ──────────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup():
    models.Base.metadata.create_all(bind=database.engine)


# ──────────────────────────────────────────────────────────────────────
# Health Check
# ──────────────────────────────────────────────────────────────────────
@app.get("/")
def health_check():
    return {"status": "AutoShield Backend Online", "version": "2.0.0"}


# ──────────────────────────────────────────────────────────────────────
# Static Code Analysis (Path A only)
# ──────────────────────────────────────────────────────────────────────
@app.post("/analyze-code")
def analyze_code(path: str, db: Session = Depends(database.get_db)):
    try:
        findings = scanner.run_scanners(path)
        for f in findings:
            db_vuln = models.Vulnerability(**f)
            db.add(db_vuln)
        db.commit()
        return {"count": len(findings), "results": findings}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────────────────────────────
# FULL TRI-LAYER ANALYSIS
# ──────────────────────────────────────────────────────────────────────
@app.post("/analyze-full")
def analyze_full(request: FullScanRequest, db: Session = Depends(database.get_db)):
    try:
        static_findings = scanner.run_scanners(request.path)

        if not static_findings:
            return {
                "status": "clean",
                "message": "No static findings detected.",
                "count": 0,
                "results": [],
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            }

        scan_record = models.Scan(scan_type="full", status="processing")
        db.add(scan_record)
        db.flush()

        for f in static_findings:
            db_vuln = models.Vulnerability(scan_id=scan_record.id, **f)
            db.add(db_vuln)

        enriched = analyze_batch(static_findings, use_llm=request.use_llm)
        summary = _build_summary(enriched)

        scan_record.status = "completed"
        db.commit()

        return {
            "status": "completed",
            "count": len(enriched),
            "results": enriched,
            "summary": summary,
            "llm_enabled": request.use_llm,
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────────────────────────────
# SINGLE VULNERABILITY RAG+LLM ANALYSIS
# ──────────────────────────────────────────────────────────────────────
@app.post("/rag/analyze")
def rag_analyze(payload: RAGRequest):
    try:
        result = analyze_vulnerability(
            code_snippet=payload.code_snippet,
            cwe_id=payload.cwe_id,
            severity=payload.severity,
            vuln_type=payload.vuln_type,
            file_path=payload.file_path,
            line=payload.line,
            tool=payload.tool,
            use_llm=payload.use_llm,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────────────────────────────
# GENERATE FIX (Gemini-powered)
# ──────────────────────────────────────────────────────────────────────
@app.post("/rag/generate-fix")
def generate_fix(payload: GenerateFixRequest):
    """
    Given a code snippet and vulnerability type, generate a targeted fix
    using Gemini. Returns fix_code, explanation, and step-by-step guidance.
    """
    try:
        result = generate_fix_for_snippet(
            code_snippet=payload.code_snippet,
            vuln_type=payload.vuln_type,
            cwe_id=payload.cwe_id,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────────────────────────────
# APPLY FIX (writes to disk)
# ──────────────────────────────────────────────────────────────────────
@app.post("/apply-fix")
def apply_fix(payload: ApplyFixRequest):
    """
    Applies an AI-generated fix to a file on disk.
    Reads the file, replaces the vulnerable snippet, writes back.
    Returns success status and the diff preview.
    """
    import os

    if not os.path.isfile(payload.file_path):
        raise HTTPException(status_code=404, detail=f"File not found: {payload.file_path}")

    try:
        with open(payload.file_path, "r", encoding="utf-8", errors="replace") as f:
            original_content = f.read()

        # Strategy 1: Replace the exact snippet if found
        if payload.original_code.strip() and payload.original_code.strip() in original_content:
            new_content = original_content.replace(
                payload.original_code.strip(),
                payload.fix_code.strip(),
                1  # Replace first occurrence only
            )
            strategy = "exact_match"
        else:
            # Strategy 2: Replace lines around the reported line number
            lines = original_content.splitlines(keepends=True)
            vuln_lines = payload.original_code.strip().splitlines()
            n = len(vuln_lines)
            line_idx = max(0, payload.line - 1)

            # Try to find the snippet near the reported line
            best_start = line_idx
            for search_start in range(max(0, line_idx - 3), min(len(lines), line_idx + 3)):
                window = "".join(lines[search_start:search_start + n]).strip()
                if window == payload.original_code.strip():
                    best_start = search_start
                    break

            fix_lines = payload.fix_code.strip().splitlines(keepends=True)
            if not fix_lines[-1].endswith("\n"):
                fix_lines[-1] += "\n"

            lines[best_start:best_start + n] = fix_lines
            new_content = "".join(lines)
            strategy = "line_replacement"

        with open(payload.file_path, "w", encoding="utf-8") as f:
            f.write(new_content)

        return {
            "success": True,
            "strategy": strategy,
            "file_path": payload.file_path,
            "message": f"Fix applied successfully using {strategy}",
        }

    except PermissionError:
        raise HTTPException(status_code=403, detail=f"Permission denied: {payload.file_path}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────────────────────────────
# RAG HEALTH + STATS
# ──────────────────────────────────────────────────────────────────────
@app.get("/rag/health")
def rag_health():
    try:
        from rag.vector_store.chroma_client import get_collection_stats
        stats = get_collection_stats()
        return {
            "status": "ok",
            "collection": stats["name"],
            "documents_indexed": stats["count"],
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ──────────────────────────────────────────────────────────────────────
# Runtime Analysis (Playwright)
# ──────────────────────────────────────────────────────────────────────
@app.post("/analyze-runtime")
async def analyze_runtime(url: str, db: Session = Depends(database.get_db)):
    new_scan = models.Scan(scan_type="runtime", status="processing")
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    try:
        findings = await scan_website_runtime(url)
        for f in findings:
            vuln = models.Vulnerability(scan_id=new_scan.id, **f)
            db.add(vuln)
        new_scan.status = "completed"
        db.commit()
        return {
            "status": "success",
            "scan_id": new_scan.id,
            "url": url,
            "issues": len(findings),
        }
    except Exception as e:
        db.rollback()
        new_scan.status = "failed"
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────────────────────────────
@app.get("/projects")
def get_projects(db: Session = Depends(database.get_db)):
    return db.query(models.Project).all()


@app.get("/dashboard-summary/{project_id}")
def get_project_summary(project_id: str, db: Session = Depends(database.get_db)):
    scans = db.query(models.Scan).filter(models.Scan.project_id == project_id).all()
    scan_ids = [s.id for s in scans]
    vulns = db.query(models.Vulnerability).filter(
        models.Vulnerability.scan_id.in_(scan_ids)
    ).all()

    high = len([v for v in vulns if v.severity.upper() == "HIGH"])
    medium = len([v for v in vulns if v.severity.upper() == "MEDIUM"])
    low = len([v for v in vulns if v.severity.upper() == "LOW"])

    trend = [
        {"month": "Jan", "count": 5},
        {"month": "Feb", "count": high + medium},
        {"month": "Mar", "count": high},
    ]
    score = min(100, (high * 15) + (medium * 8) + (low * 3))

    return {
        "risk_score": 100 - score,
        "stats": {"high": high, "medium": medium, "low": low},
        "trend": trend,
        "recent_vulns": vulns[:5],
    }


@app.get("/dashboard-summary")
def get_summary(db: Session = Depends(database.get_db)):
    high = db.query(models.Vulnerability).filter(
        models.Vulnerability.severity == "HIGH"
    ).count()
    medium = db.query(models.Vulnerability).filter(
        models.Vulnerability.severity == "MEDIUM"
    ).count()
    low = db.query(models.Vulnerability).filter(
        models.Vulnerability.severity == "LOW"
    ).count()
    score = min(100, (high * 15) + (medium * 8) + (low * 3))
    return {
        "risk_score": 100 - score,
        "stats": {"high": high, "medium": medium, "low": low},
        "total_scans": db.query(models.Scan).count(),
    }


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────
def _build_summary(results: List[dict]) -> dict:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for r in results:
        cat = r.get("risk_category", "MEDIUM").upper()
        if cat == "CRITICAL":
            summary["critical"] += 1
        elif cat == "HIGH":
            summary["high"] += 1
        elif cat == "MEDIUM":
            summary["medium"] += 1
        elif cat == "LOW":
            summary["low"] += 1
        else:
            summary["informational"] += 1
    return summary