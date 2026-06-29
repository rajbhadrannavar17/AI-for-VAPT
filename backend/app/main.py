from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .ai_engine import assess_target, generate_script, local_ai_response, overall_severity, report_markdown
from .database import get_conn, init_db, row_to_scan
from .live_audit import passive_live_audit
from .nvd import search_cves


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="AI for VAPT API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"
    notes: str = ""


class AIRequest(BaseModel):
    prompt: str


class ScriptRequest(BaseModel):
    language: Literal["python", "bash", "powershell"]
    task: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "engine": "local-ai-heuristic", "signin": False}


@app.get("/api/documentation")
def documentation() -> dict:
    return {
        "title": "AI for VAPT Professional Playbook",
        "sections": [
            {
                "name": "Engagement Discipline",
                "items": [
                    "Confirm written authorization, scope, target URLs, test windows, and data-handling expectations.",
                    "Use passive testing first, then escalate to manual verification only under supervision.",
                    "Maintain confidentiality and avoid exposing client-specific evidence in public repositories.",
                ],
            },
            {
                "name": "OWASP Testing Coverage",
                "items": [
                    "Injection: reflected input, SQLi candidates, output encoding, and parameter handling.",
                    "Broken Access Control: IDOR candidates, object identifiers, and role-based verification.",
                    "Cryptographic Failures: HTTPS, TLS, HSTS, and cookie protection.",
                    "Security Misconfiguration: headers, technology disclosure, debug text, and default behavior.",
                    "Vulnerable Components: technology fingerprinting and NVD CVE follow-up.",
                ],
            },
            {
                "name": "Tool Workflow",
                "items": [
                    "Burp Suite: Proxy history, Repeater, DOM Invader, Logger, Comparer, Autorize, CSRF PoC Generator.",
                    "Nmap: service discovery, port inventory, and XML parsing for reports.",
                    "Nessus: severity correlation, remediation prioritization, and retest evidence.",
                    "AI tools: prompt-risk classification, scripting support, report drafting, and triage assistance.",
                ],
            },
            {
                "name": "Reporting Standard",
                "items": [
                    "Every report includes scope, methodology, severity summary, CVSS-style score, evidence, impact, safe validation, remediation, and retest checklist.",
                    "Each candidate issue is clearly separated from confirmed exploitability.",
                    "Reports are written for technical teams, management, and interview demonstration.",
                ],
            },
        ],
    }


@app.post("/api/scan")
def create_scan(req: ScanRequest) -> dict:
    is_web_target = req.target.lower().startswith(("http://", "https://"))
    if is_web_target and req.scan_type.lower() != "demo":
        findings = passive_live_audit(req.target)
    else:
        findings = assess_target(req.target, req.scan_type, req.notes)
    severity, score = overall_severity(findings)
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans(target, scan_type, status, severity, score, findings) VALUES(?,?,?,?,?,?)",
            (req.target, req.scan_type, "completed", severity, score, json.dumps(findings)),
        )
        scan_id = cur.lastrowid
    return {"id": scan_id, "target": req.target, "scan_type": req.scan_type, "severity": severity, "score": score, "findings": findings}


@app.get("/api/scans")
def list_scans() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 50").fetchall()
    return [row_to_scan(r) for r in rows]


@app.post("/api/ai/analyze")
def ai_analyze(req: AIRequest) -> dict:
    return local_ai_response(req.prompt)


@app.get("/api/cves")
def cves(q: str) -> list[dict]:
    return search_cves(q)


@app.post("/api/scripts")
def scripts(req: ScriptRequest) -> dict:
    return {"language": req.language, "task": req.task, "script": generate_script(req.language, req.task)}


@app.post("/api/report/{scan_id}")
def create_report(scan_id: int) -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return {"error": "scan not found"}
        scan = row_to_scan(row)
        body = report_markdown(scan["target"], scan["findings"])
        cur = conn.execute(
            "INSERT INTO reports(title, target, body) VALUES(?,?,?)",
            (f"Pentest Report {scan_id}", scan["target"], body),
        )
    return {"id": cur.lastrowid, "body": body}
