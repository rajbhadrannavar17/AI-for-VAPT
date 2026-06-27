# AI for VAPT

AI for VAPT is a full-stack demonstration platform for vulnerability assessment and penetration testing workflows. It combines OWASP Top 10 checks, network reconnaissance concepts, Burp Suite workflow mapping, Nmap/Nessus-style correlation, local AI security analysis, CVE lookups through the public NVD API, script generation, report generation, and SQLite scan history.

## Stack

- React + Tailwind dark terminal UI
- Python FastAPI backend
- Local heuristic AI engine, no sign-in or API key required
- SQLite persistence
- Docker Compose one-command setup

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
