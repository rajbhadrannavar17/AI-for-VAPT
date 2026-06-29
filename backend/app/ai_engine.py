from __future__ import annotations

import re
from dataclasses import dataclass


SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

CVSS_VECTORS = {
    "Critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "High": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "Medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Low": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "Info": "Informational finding; CVSS score not assigned",
}

EDUCATOR_GUIDANCE = {
    "content-security-policy": {
        "attacker": "If another input-handling flaw exists, an attacker can try to run script in a victim browser. Without CSP, the browser has fewer guardrails to block unauthorized script sources, inline script, or unsafe framing behavior.",
        "validation": "Use Burp passive checks and browser devtools to confirm the response lacks CSP. Then review pages that render user-controlled data and verify output encoding. Do not test with real user accounts without authorization.",
        "remediation": "Deploy a CSP starting with default-src 'self', define script-src/style-src/img-src/connect-src for required assets, remove unsafe-inline where possible, and monitor violations before enforcing tightly.",
    },
    "strict-transport-security": {
        "attacker": "On networks an attacker controls, users can be downgraded or kept on HTTP if the browser has no HSTS policy for the site.",
        "validation": "Confirm HTTPS is enabled first, then check for Strict-Transport-Security on HTTPS responses using Burp, curl, or browser network tools.",
        "remediation": "Add Strict-Transport-Security with a conservative max-age first, then increase after confirming all subdomains support HTTPS.",
    },
    "x-frame-options": {
        "attacker": "A malicious page can frame the site and trick users into clicking hidden buttons or UI elements, known as clickjacking.",
        "validation": "Confirm whether X-Frame-Options or CSP frame-ancestors is present. Use a local proof page only against owned or authorized systems.",
        "remediation": "Set X-Frame-Options: DENY or SAMEORIGIN, or preferably CSP frame-ancestors with the exact allowed origins.",
    },
    "x-content-type-options": {
        "attacker": "Browsers may guess a file type incorrectly. If user-uploaded or dynamic content is served with the wrong type, MIME sniffing can increase script execution risk.",
        "validation": "Review response headers for static and uploaded content. Confirm X-Content-Type-Options: nosniff is present.",
        "remediation": "Set X-Content-Type-Options: nosniff and serve files with accurate Content-Type values.",
    },
    "referrer-policy": {
        "attacker": "URLs can leak to third-party sites through the Referer header. If URLs contain identifiers or tokens, this can expose sensitive data.",
        "validation": "Check response headers and review whether sensitive values appear in URLs.",
        "remediation": "Set Referrer-Policy: strict-origin-when-cross-origin or a stricter policy based on business needs.",
    },
    "permissions-policy": {
        "attacker": "If browser APIs are broadly available, compromised third-party content has a larger set of features to abuse.",
        "validation": "Check whether Permissions-Policy is configured and whether sensitive APIs are needed.",
        "remediation": "Disable unnecessary APIs by default and allow features only for trusted origins.",
    },
    "not using https": {
        "attacker": "Plain HTTP lets network-positioned attackers observe or modify traffic, inject content, steal session data, or redirect users.",
        "validation": "Confirm the final URL remains HTTP and that no HTTPS redirect is enforced.",
        "remediation": "Enable HTTPS everywhere, redirect HTTP to HTTPS, set secure cookies, and then enable HSTS.",
    },
    "cookie missing flags": {
        "attacker": "Cookies without Secure, HttpOnly, or SameSite are easier to expose through network downgrade, client-side script access, or cross-site request contexts.",
        "validation": "Inspect Set-Cookie headers in Burp or browser devtools and confirm each security-relevant cookie has the right flags.",
        "remediation": "Set Secure, HttpOnly, and SameSite=Lax or Strict for session cookies. Use SameSite=None only when required and always with Secure.",
    },
    "reflected parameter": {
        "attacker": "If reflected input is inserted into HTML, JavaScript, attributes, or URLs without context-aware encoding, it can become reflected XSS.",
        "validation": "Use a harmless marker to identify reflection, then manually inspect the output context. Confirm whether framework escaping protects the value before classifying as exploitable XSS.",
        "remediation": "Apply context-aware output encoding, avoid dangerously setting HTML, validate expected parameter values, and add CSP as defense in depth.",
    },
    "technology header disclosure": {
        "attacker": "Visible platform and version details help attackers choose known CVEs and targeted fingerprinting paths.",
        "validation": "Confirm Server and X-Powered-By headers plus framework markers in responses.",
        "remediation": "Remove unnecessary version headers and keep server/framework packages patched.",
    },
    "technology fingerprint": {
        "attacker": "Technology fingerprints help attackers narrow testing to framework-specific CVEs, misconfigurations, and public exploit paths.",
        "validation": "Correlate detected technologies with package manifests, deployment platform, and NVD results.",
        "remediation": "Track dependency versions, patch quickly, and document compensating controls for components that cannot be updated immediately.",
    },
    "sql injection": {
        "attacker": "When user input reaches SQL queries unsafely, attackers may read, change, or delete database records and bypass login or business logic.",
        "validation": "Use Burp Repeater with authorized test accounts and benign timing/logic checks. Confirm server-side parameterization rather than relying on client validation.",
        "remediation": "Use parameterized queries, ORM binding, least-privilege database users, input validation, and query logging.",
    },
    "cross-site scripting": {
        "attacker": "XSS lets attacker-controlled script run in a user's browser, which can steal data, perform actions as the user, or modify page content.",
        "validation": "Identify reflection/storage points with harmless markers, inspect context, and verify framework escaping.",
        "remediation": "Use context-aware encoding, trusted sanitizers, avoid unsafe HTML sinks, and enforce CSP.",
    },
    "csrf": {
        "attacker": "A victim's browser can be tricked into sending an authenticated state-changing request if tokens and SameSite protections are missing.",
        "validation": "In an authorized environment, compare state-changing requests for per-request tokens and SameSite cookie behavior.",
        "remediation": "Use anti-CSRF tokens, SameSite cookies, origin checks, and re-authentication for sensitive actions.",
    },
    "idor": {
        "attacker": "Changing object IDs can expose or modify another user's data when server-side authorization is missing.",
        "validation": "Use two authorized test accounts and Burp Comparer/Autorize to verify object-level access control.",
        "remediation": "Enforce server-side object authorization on every request and avoid relying on hidden UI controls.",
    },
}


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
    counts = {name: 0 for name in ["Critical", "High", "Medium", "Low", "Info"]}
    for finding in findings:
        counts[finding.get("severity", "Info")] = counts.get(finding.get("severity", "Info"), 0) + 1
    lines = [
        f"# AI for VAPT Professional Assessment Report",
        "",
        f"**Target:** {target}",
        f"**Overall Risk:** {sev}",
        f"**Highest CVSS-style Score:** {score:.1f}",
        "**Assessment Type:** Passive live web audit with educator-focused VAPT reporting",
        "",
        "## Executive Summary",
        "This report summarizes security observations discovered through a safe passive assessment. It is designed for VAPT education, supervised testing, and professional reporting practice. Findings are mapped to OWASP Top 10, CVSS-style scoring, Burp Suite workflows, networking concepts, and remediation guidance.",
        "",
        "The assessment does not prove exploitability by itself. Items marked as candidates require authorized manual verification before being treated as confirmed vulnerabilities.",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
        *[f"| {name} | {counts.get(name, 0)} |" for name in ["Critical", "High", "Medium", "Low", "Info"]],
        "",
        "## Methodology",
        "",
        "1. Scope confirmation and authorization reminder.",
        "2. Passive HTTP/TLS request and same-origin crawl.",
        "3. Security header and cookie review.",
        "4. OWASP issue classification for security misconfiguration, cryptographic failures, injection candidates, and access-control review points.",
        "5. Burp Suite workflow mapping for manual verification.",
        "6. NVD/CVE follow-up guidance for detected technologies.",
        "7. Professional remediation and retest notes.",
        "",
        "## Findings Detail",
        "",
        "| ID | Finding | Severity | CVSS | OWASP | Tool Mapping |",
        "|---|---|---|---:|---|---|",
    ]
    for idx, finding in enumerate(findings, 1):
        lines.append(
            f"| F-{idx:02d} | {finding['title']} | {finding['severity']} | {float(finding['score']):.1f} | {finding['owasp']} | {finding['burp_tool']} |"
        )
    lines += [
        "",
        "## Educator Notes and Remediation",
    ]
    for idx, f in enumerate(findings, 1):
        guide = _guidance_for(f["title"])
        lines += [
            f"### F-{idx:02d}: {f['title']}",
            "",
            f"**Severity:** {f['severity']}  ",
            f"**CVSS-style Score:** {float(f['score']):.1f}  ",
            f"**CVSS-style Vector:** {CVSS_VECTORS.get(f['severity'], CVSS_VECTORS['Info'])}  ",
            f"**Category:** {f['category']}  ",
            f"**OWASP Mapping:** {f['owasp']}  ",
            f"**Burp / Tool Workflow:** {f['burp_tool']}",
            "",
            f"**Evidence:** {f['evidence']}",
            "",
            f"**How attackers typically abuse this weakness:** {guide['attacker']}",
            "",
            f"**Safe validation approach:** {guide['validation']}",
            "",
            f"**Recommended remediation:** {guide['remediation']}",
            "",
            f"**Project recommendation:** {f['recommendation']}",
            "",
        ]
    lines += [
        "## Competency Mapping",
        "",
        "| Job Skill | Evidence in This Project |",
        "|---|---|",
        "| OWASP Top 10 | Findings map to Injection, Security Misconfiguration, Cryptographic Failures, Broken Access Control, and vulnerable components. |",
        "| Networking fundamentals | TLS, HTTPS/HTTP, ports, protocols, service exposure, and header behavior are represented in audit logic and reports. |",
        "| Burp Suite familiarity | Each finding includes Burp workflow guidance such as Proxy history, Repeater, DOM Invader, Logger, Comparer, and passive scanner checks. |",
        "| Nmap/Nessus exposure | Scripts and report language support service discovery, XML parsing, and severity correlation. |",
        "| AI/LLM security | Local analyzer classifies prompt injection, data leakage, and misuse patterns. |",
        "| Manual penetration testing support | Report separates passive evidence from manual verification steps. |",
        "| Scripting | Python, Bash, and PowerShell script generation plus standalone scripts are included. |",
        "| Documentation | This report provides executive summary, methodology, severity tables, CVSS-style scoring, remediation, and retest guidance. |",
        "",
        "## Retest Checklist",
        "",
        "- Confirm high and medium findings are remediated in a staging environment first.",
        "- Re-run the passive audit after deployment.",
        "- Manually verify reflected-input and authorization candidates using authorized accounts only.",
        "- Update the final status of each finding as Open, Risk Accepted, False Positive, or Remediated.",
        "- Keep evidence, screenshots, timestamps, and tool versions for audit traceability.",
        "",
        "## Confidentiality Note",
        "",
        "This report may contain target-specific infrastructure details. Share it only with authorized stakeholders and avoid publishing sensitive evidence publicly.",
    ]
    return "\n".join(lines)


def _guidance_for(title: str) -> dict[str, str]:
    lowered = title.lower()
    for key, guide in EDUCATOR_GUIDANCE.items():
        if key in lowered:
            return guide
    return {
        "attacker": "Attackers use this type of weakness to gather information, increase exploit reliability, or chain it with other issues discovered during reconnaissance.",
        "validation": "Confirm the observation with passive tooling first, then perform manual testing only in an authorized scope with documented test accounts and change windows.",
        "remediation": "Reduce exposed information, enforce secure defaults, validate inputs server-side, and retest after deployment.",
    }
