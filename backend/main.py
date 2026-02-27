# backend/main.py

import asyncio
import sys

# ✅ Fix Playwright subprocess issue on Windows
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, Depends, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import models
import database
import scanner
from crawler import scan_website_runtime

app = FastAPI(title="AutoShield API")

# ✅ Enable CORS (required for browser extension)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development. Restrict in production.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Create tables at startup
@app.on_event("startup")
def startup():
    models.Base.metadata.create_all(bind=database.engine)


# ---------------------------------
# Health Check
# ---------------------------------
@app.get("/")
def health_check():
    return {"status": "AutoShield Backend Online"}


# ---------------------------------
# Static Code Analysis
# ---------------------------------
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


# ---------------------------------
# Runtime Analysis (Playwright)
# ---------------------------------
@app.post("/analyze-runtime")
async def analyze_runtime(url: str, db: Session = Depends(database.get_db)):

    # 1️⃣ Create scan entry
    new_scan = models.Scan(scan_type="runtime", status="processing")
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    try:
        # 2️⃣ Run crawler
        findings = await scan_website_runtime(url)

        # 3️⃣ Save findings
        for f in findings:
            vuln = models.Vulnerability(scan_id=new_scan.id, **f)
            db.add(vuln)

        # 4️⃣ Mark completed
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