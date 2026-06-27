from __future__ import annotations

import re
from dataclasses import dataclass


SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


@dataclass(frozen=True)
class Finding:
    title: str
    category: str
    severity: str
    score: float
    evidence: str
    recommendation: str
    burp_tool: str
    owasp: str

    def as_dict(self) -> dict:
        return self.__dict__


OWASP_TESTS = [
    ("SQL Injection", "A03:2021 Injection", "Burp Repeater + Intruder", ["id=", "q=", "search=", "filter="]),
    ("Cross-Site Scripting", "A03:2021 Injection", "Burp Proxy + DOM Invader", ["comment=", "message=", "callback=", "returnUrl="]),
    ("CSRF", "A01:2021 Broken Access Control", "Burp CSRF PoC Generator", ["POST /", "PUT /", "DELETE /"]),
    ("IDOR", "A01:2021 Broken Access Control", "Burp Autorize + Comparer", ["/users/", "/invoice/", "accountId=", "userId="]),
]


def local_ai_response(prompt: str) -> dict:
    lower = prompt.lower()
    risks = []
    if any(x in lower for x in ["ignore previous", "system prompt", "developer message", "jailbreak"]):
        risks.append("prompt injection")
    if any(x in lower for x in ["api_key", "password", "secret", "token", "private key"]):
        risks.append("data leakage")
    if any(x in lower for x in ["malware", "steal", "phishing", "credential", "exploit this"]):
        risks.append("model misuse")
    classification = "Benign security assistance"
    if "model misuse" in risks:
        classification = "Potential misuse request"
    elif risks:
        classification = "LLM security risk detected"
    return {
        "classification": classification,
        "risks": risks or ["none detected"],
        "response": (
            "AI analysis complete. I found "
            + (", ".join(risks) if risks else "no obvious LLM abuse markers")
            + ". Apply least-privilege context, output filtering, and human review for high-impact actions."
        ),
    }


def assess_target(target: str, scan_type: str, notes: str = "") -> list[dict]:
    text = f"{target} {notes}".lower()
    findings: list[Finding] = []
    for title, owasp, burp, indicators in OWASP_TESTS:
        matched = [i for i in indicators if i.lower() in text]
        if matched or scan_type.lower() in title.lower():
            severity = "High" if title in {"SQL Injection", "IDOR"} else "Medium"
            findings.append(
                Finding(
                    title=f"Potential {title}",
                    category="Web Application",
                    severity=severity,
                    score=8.1 if severity == "High" else 6.1,
                    evidence=f"Matched indicators: {', '.join(matched) or scan_type}",
                    recommendation="Validate authorization, encode output, use parameterized queries, and verify with authenticated Burp workflows.",
                    burp_tool=burp,
                    owasp=owasp,
                )
            )
    ports = re.findall(r"\b(21|22|23|25|53|80|110|139|143|389|443|445|3306|3389|5432|6379|8080|8443|9200)\b", text)
    for port in sorted(set(ports), key=int):
        sev = "Critical" if port in {"23", "445", "6379", "9200"} else "Medium"
        findings.append(
            Finding(
                title=f"Exposed service on TCP/{port}",
                category="Network",
                severity=sev,
                score=9.0 if sev == "Critical" else 5.8,
                evidence=f"Service exposure observed or requested for port {port}",
                recommendation="Confirm business need, restrict by firewall/security groups, fingerprint service version, and patch vulnerable daemons.",
                burp_tool="Nmap simulation + Nessus correlation",
                owasp="Network service exposure",
            )
        )
    if not findings:
        findings.append(
            Finding(
                title="Baseline reconnaissance completed",
                category="Reconnaissance",
                severity="Info",
                score=0.0,
                evidence="No high-confidence vulnerable pattern in submitted target text.",
                recommendation="Run authenticated testing, Nmap service discovery, and NVD CVE correlation before final sign-off.",
                burp_tool="Burp Target Sitemap",
                owasp="Security logging and monitoring",
            )
        )
    return [f.as_dict() for f in findings]


def overall_severity(findings: list[dict]) -> tuple[str, float]:
    top = max(findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 0), f["score"]))
    return top["severity"], float(top["score"])


def generate_script(language: str, task: str) -> str:
    task_l = task.lower()
    if language == "python":
        return """#!/usr/bin/env python3
import socket, sys
host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
for port in [21,22,80,443,445,3306,3389,8080]:
    s = socket.socket(); s.settimeout(0.5)
    if s.connect_ex((host, port)) == 0:
        print(f"open tcp/{port}")
    s.close()
"""
    if language == "powershell":
        return """param([string]$HostName="127.0.0.1")
80,443,445,3389 | ForEach-Object {
  if (Test-NetConnection $HostName -Port $_ -InformationLevel Quiet) {
    Write-Output "open tcp/$_"
  }
}
"""
    return f"""#!/usr/bin/env bash
set -euo pipefail
target="${{1:-127.0.0.1}}"
echo "Security task: {task_l}"
for port in 22 80 443 445 3306 8080; do
  timeout 1 bash -c "cat < /dev/null > /dev/tcp/$target/$port" 2>/dev/null && echo "open tcp/$port" || true
done
"""


def report_markdown(target: str, findings: list[dict]) -> str:
    sev, score = overall_severity(findings)
    lines = [
        f"# AI for VAPT Pentest Report: {target}",
        "",
        f"Overall risk: **{sev}** (CVSS-style score {score:.1f})",
        "",
        "## Executive Summary",
        "This assessment correlates OWASP Top 10 checks, network exposure review, Burp Suite workflow mapping, Nmap-style service discovery, Nessus-style severity reasoning, and local AI security review.",
        "",
        "## Findings",
    ]
    for idx, f in enumerate(findings, 1):
        lines += [
            f"### {idx}. {f['title']}",
            f"- Severity: {f['severity']} ({f['score']})",
            f"- Category: {f['category']}",
            f"- OWASP / domain: {f['owasp']}",
            f"- Burp / tool workflow: {f['burp_tool']}",
            f"- Evidence: {f['evidence']}",
            f"- Recommendation: {f['recommendation']}",
            "",
        ]
    return "\n".join(lines)
