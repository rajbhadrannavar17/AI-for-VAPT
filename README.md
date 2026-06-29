# AI for VAPT

AI for VAPT is a full-stack vulnerability assessment and penetration testing workflow platform. It combines passive live website auditing, OWASP Top 10 checks, network reconnaissance concepts, Burp Suite workflow mapping, Nmap/Nessus-style correlation, local AI security analysis, CVE lookups through the public NVD API, script generation, report generation, and SQLite scan history.

## Stack

- React + Tailwind dark terminal UI
- Python FastAPI backend
- Local heuristic AI engine, no sign-in or API key required
- SQLite persistence
- Docker Compose one-command setup

## Live Audit Scope

For HTTP/HTTPS targets, the default scan mode performs a real passive audit:

- Fetches the target and a small number of same-origin links
- Checks TLS reachability and certificate validation
- Checks common security headers
- Reviews cookie security flags
- Identifies forms missing obvious CSRF token fields
- Finds object-like parameters that need IDOR authorization testing
- Sends one harmless reflection marker to parameterized URLs to identify reflected-input candidates
- Looks for client-side secret markers and debug/error text
- Fingerprints common technologies for CVE follow-up

It does not submit forms, brute force, exploit vulnerabilities, authenticate, or run destructive payloads. Use the explicit Demo Simulation mode for presentation-only OWASP examples.

## Professional Documentation and Reports

The report generator creates an educator-ready VAPT report with:

- Executive summary and scope
- Severity summary table
- CVSS-style score and vector for every finding
- OWASP Top 10 mapping
- Burp Suite workflow mapping
- Evidence and impact explanation
- Conceptual explanation of how attackers abuse each weakness
- Safe validation approach for supervised manual testing
- Remediation and retest checklist
- Competency mapping to VAPT job-description skills

The application separates passive evidence from confirmed exploitability. Reflected-input, IDOR, SQLi, XSS, and CSRF candidates must be manually validated only in authorized scope.

## Job Competency Coverage

- OWASP Top 10 awareness: SQLi, XSS, CSRF, IDOR, security misconfiguration, cryptographic failures, vulnerable components
- Networking fundamentals: HTTP/HTTPS, TLS, headers, ports, protocols, service exposure
- Tool familiarity: Burp workflow mapping, Nmap-style scripts, Nessus-style severity triage
- AI/LLM security: prompt injection, data leakage, and model misuse classification
- Vulnerability scanning support: passive live audit, CVE lookup, scan history, reports
- Scripting: Python, Bash, PowerShell script generation plus standalone tools
- Documentation: professional report generation, retest checklist, confidentiality note

## Run with Docker

```bash
docker compose up --build
```

Frontend: http://localhost:5173  
Backend: http://localhost:8000/docs

## Local Development

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

```bash
cd frontend
npm install
npm run dev
```

## Standalone Scripts

Scripts live in `/scripts`:

- `port_scanner.py`
- `http_header_auditor.py`
- `sqli_param_finder.py`
- `xss_payload_tester.py`
- `subdomain_enumerator.py`
- `nmap_xml_parser.py`
- `event_log_analyzer.ps1`

Only test systems you own or have explicit written authorization to assess.
