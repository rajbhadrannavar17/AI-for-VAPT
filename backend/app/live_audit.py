from __future__ import annotations

import re
import socket
import ssl
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

from .ai_engine import Finding

USER_AGENT = "AI-for-VAPT-passive-auditor/1.0"
MAX_PAGES = 6
TIMEOUT = 8

SECURITY_HEADERS = {
    "content-security-policy": ("High", 7.1, "A05:2021 Security Misconfiguration", "Reduces XSS and content injection impact."),
    "strict-transport-security": ("Medium", 5.3, "A02:2021 Cryptographic Failures", "Forces repeat visitors onto HTTPS."),
    "x-frame-options": ("Medium", 5.0, "A05:2021 Security Misconfiguration", "Reduces clickjacking exposure."),
    "x-content-type-options": ("Low", 3.1, "A05:2021 Security Misconfiguration", "Prevents MIME sniffing."),
    "referrer-policy": ("Low", 3.1, "A01:2021 Broken Access Control", "Limits sensitive URL leakage in referrers."),
    "permissions-policy": ("Low", 3.1, "A05:2021 Security Misconfiguration", "Restricts browser feature abuse."),
}

SENSITIVE_PATTERNS = [
    ("Possible API key in client content", re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("Private key marker in response", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |PRIVATE )?PRIVATE KEY-----")),
    ("Cloud credential marker", re.compile(r"(?i)(aws_access_key_id|firebase|supabase|service_role|stripe_secret)")),
]

TECH_PATTERNS = [
    ("Next.js", re.compile(r"(?i)__next|next/static|x-nextjs")),
    ("Vercel", re.compile(r"(?i)x-vercel|vercel")),
    ("React", re.compile(r"(?i)react|vite|root")),
    ("Supabase", re.compile(r"(?i)supabase")),
]


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.forms: list[dict] = []
        self.scripts: set[str] = set()
        self.inputs: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k.lower(): v or "" for k, v in attrs}
        if tag == "a" and data.get("href"):
            self.links.add(data["href"])
        if tag == "script" and data.get("src"):
            self.scripts.add(data["src"])
        if tag == "form":
            self._current_form = {
                "method": data.get("method", "get").lower(),
                "action": data.get("action", ""),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        if tag in {"input", "textarea", "select"}:
            field = {"name": data.get("name", ""), "type": data.get("type", tag).lower()}
            self.inputs.append(field)
            if self._current_form is not None:
                self._current_form["inputs"].append(field)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None


def passive_live_audit(target: str) -> list[dict]:
    parsed = urlparse(target if re.match(r"^https?://", target, re.I) else f"https://{target}")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return [
            Finding(
                title="Invalid web target",
                category="Input validation",
                severity="Low",
                score=2.0,
                evidence="Target must be an HTTP or HTTPS URL.",
                recommendation="Use a full URL such as https://example.com.",
                burp_tool="Burp Target Scope",
                owasp="Testing setup",
            ).as_dict()
        ]

    base = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
    findings: list[Finding] = []
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    try:
        first = session.get(base, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as exc:
        return [
            Finding(
                title="Target could not be reached",
                category="Availability",
                severity="Medium",
                score=5.0,
                evidence=f"GET {base} failed: {exc}",
                recommendation="Confirm DNS, TLS, firewall rules, and that the target is reachable from this scanner.",
                burp_tool="Burp Logger + browser replay",
                owasp="Reconnaissance",
            ).as_dict()
        ]

    final_url = first.url
    final_host = urlparse(final_url).netloc
    findings.extend(_transport_findings(final_url, first))
    findings.extend(_header_findings(first))
    findings.extend(_cookie_findings(first))

    pages = _crawl_same_origin(session, first, final_url, final_host)
    findings.extend(_content_findings(pages))
    findings.extend(_form_findings(pages))
    findings.extend(_parameter_findings(session, pages))
    findings.extend(_technology_findings(first, pages))
    findings.append(
        Finding(
            title="Passive live audit completed",
            category="Reconnaissance",
            severity="Info",
            score=0.0,
            evidence=f"Fetched {len(pages)} same-origin page(s). No form submission or destructive payloads were sent.",
            recommendation="Use authenticated Burp testing and manual verification for exploitable SQLi, XSS, CSRF, and IDOR confirmation.",
            burp_tool="Burp Target Sitemap + Logger",
            owasp="VAPT methodology",
        )
    )
    return _dedupe([f.as_dict() for f in findings])


def _transport_findings(final_url: str, response: requests.Response) -> list[Finding]:
    findings: list[Finding] = []
    final = urlparse(final_url)
    if final.scheme != "https":
        findings.append(
            Finding(
                title="Site is not using HTTPS",
                category="Transport Security",
                severity="High",
                score=7.4,
                evidence=f"Final URL is {final_url}",
                recommendation="Redirect all HTTP traffic to HTTPS and enable HSTS.",
                burp_tool="Burp Proxy history",
                owasp="A02:2021 Cryptographic Failures",
            )
        )
    if 500 <= response.status_code:
        findings.append(
            Finding(
                title="Server error observed",
                category="Availability",
                severity="Medium",
                score=5.0,
                evidence=f"GET {final_url} returned HTTP {response.status_code}",
                recommendation="Review server logs and error handling for stack traces or instability.",
                burp_tool="Burp Logger",
                owasp="A09:2021 Security Logging and Monitoring Failures",
            )
        )
    findings.extend(_tls_findings(final.hostname, final.port or 443) if final.scheme == "https" and final.hostname else [])
    return findings


def _tls_findings(hostname: str | None, port: int) -> list[Finding]:
    if not hostname:
        return []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                version = tls.version()
    except Exception as exc:
        return [
            Finding(
                title="TLS handshake or certificate validation issue",
                category="Transport Security",
                severity="High",
                score=7.0,
                evidence=f"TLS validation failed for {hostname}:{port}: {exc}",
                recommendation="Use a publicly trusted certificate and disable obsolete TLS configuration.",
                burp_tool="Burp TLS inspector",
                owasp="A02:2021 Cryptographic Failures",
            )
        ]
    subject = dict(x[0] for x in cert.get("subject", []))
    return [
        Finding(
            title="TLS endpoint verified",
            category="Transport Security",
            severity="Info",
            score=0.0,
            evidence=f"{hostname}:{port} negotiated {version}; certificate CN={subject.get('commonName', 'n/a')}",
            recommendation="Continue monitoring certificate expiry and TLS policy.",
            burp_tool="Burp Target issue activity",
            owasp="A02:2021 Cryptographic Failures",
        )
    ]


def _header_findings(response: requests.Response) -> list[Finding]:
    headers = {k.lower(): v for k, v in response.headers.items()}
    findings: list[Finding] = []
    for header, (severity, score, owasp, reason) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(
                Finding(
                    title=f"Missing security header: {header}",
                    category="Security Headers",
                    severity=severity,
                    score=score,
                    evidence=f"{header} was not present on {response.url}",
                    recommendation=f"Add {header}. {reason}",
                    burp_tool="Burp Scanner passive checks",
                    owasp=owasp,
                )
            )
    server = headers.get("server") or headers.get("x-powered-by")
    if server:
        findings.append(
            Finding(
                title="Technology header disclosure",
                category="Information Disclosure",
                severity="Low",
                score=2.7,
                evidence=f"Server technology header observed: {server}",
                recommendation="Remove or minimize framework/version disclosure headers where possible.",
                burp_tool="Burp passive scanner",
                owasp="A05:2021 Security Misconfiguration",
            )
        )
    return findings


def _cookie_findings(response: requests.Response) -> list[Finding]:
    findings: list[Finding] = []
    for cookie in response.cookies:
        missing = []
        if not cookie.secure:
            missing.append("Secure")
        if "httponly" not in cookie._rest:
            missing.append("HttpOnly")
        same_site = cookie._rest.get("SameSite") or cookie._rest.get("samesite")
        if not same_site:
            missing.append("SameSite")
        if missing:
            findings.append(
                Finding(
                    title=f"Cookie missing flags: {cookie.name}",
                    category="Session Security",
                    severity="Medium",
                    score=5.4,
                    evidence=f"Cookie {cookie.name} missing {', '.join(missing)}",
                    recommendation="Set Secure, HttpOnly, and SameSite=Lax/Strict on session cookies.",
                    burp_tool="Burp Proxy cookie jar",
                    owasp="A01:2021 Broken Access Control",
                )
            )
    return findings


def _crawl_same_origin(session: requests.Session, first: requests.Response, final_url: str, final_host: str) -> list[dict]:
    queue = [final_url]
    seen: set[str] = set()
    pages: list[dict] = []
    first_used = False
    while queue and len(pages) < MAX_PAGES:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = first if not first_used and url == final_url else session.get(url, timeout=TIMEOUT, allow_redirects=True)
            first_used = True
        except requests.RequestException:
            continue
        content_type = resp.headers.get("content-type", "")
        text = resp.text[:500_000] if "text/html" in content_type or "<html" in resp.text[:500].lower() else ""
        parser = PageParser()
        if text:
            parser.feed(text)
        page = {"url": resp.url, "status": resp.status_code, "headers": resp.headers, "text": text, "parser": parser}
        pages.append(page)
        for link in parser.links:
            absolute = urljoin(resp.url, link)
            parsed = urlparse(absolute)
            normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
            if parsed.scheme in {"http", "https"} and parsed.netloc == final_host and normalized not in seen:
                queue.append(normalized)
    return pages


def _content_findings(pages: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        text = page["text"]
        for title, pattern in SENSITIVE_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    Finding(
                        title=title,
                        category="Data Leakage",
                        severity="High",
                        score=7.5,
                        evidence=f"Pattern matched on {page['url']}: {match.group(0)[:80]}",
                        recommendation="Remove secrets from client bundles and rotate any exposed credentials.",
                        burp_tool="Burp Search + Logger",
                        owasp="A02:2021 Cryptographic Failures",
                    )
                )
        if re.search(r"(?i)(stack trace|traceback|uncaught exception|syntaxerror|typeerror)", text):
            findings.append(
                Finding(
                    title="Client-visible error/debug text",
                    category="Information Disclosure",
                    severity="Medium",
                    score=4.7,
                    evidence=f"Debug/error marker found on {page['url']}",
                    recommendation="Disable verbose errors in production and return generic error pages.",
                    burp_tool="Burp passive scanner",
                    owasp="A05:2021 Security Misconfiguration",
                )
            )
    return findings


def _form_findings(pages: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        parser: PageParser = page["parser"]
        for form in parser.forms:
            names = {field["name"].lower() for field in form["inputs"] if field["name"]}
            method = form["method"]
            has_password = any(field["type"] == "password" for field in form["inputs"])
            has_csrf = any("csrf" in name or "token" in name for name in names)
            if method == "post" and not has_csrf:
                findings.append(
                    Finding(
                        title="POST form without obvious CSRF token",
                        category="CSRF",
                        severity="Medium",
                        score=6.1,
                        evidence=f"Form on {page['url']} action={form['action'] or '[same page]'} has no csrf/token field.",
                        recommendation="Use server-side anti-CSRF tokens and SameSite cookies for state-changing forms.",
                        burp_tool="Burp CSRF PoC Generator",
                        owasp="A01:2021 Broken Access Control",
                    )
                )
            if has_password and urlparse(page["url"]).scheme != "https":
                findings.append(
                    Finding(
                        title="Password form served without HTTPS",
                        category="Transport Security",
                        severity="Critical",
                        score=9.1,
                        evidence=f"Password field found on non-HTTPS page {page['url']}",
                        recommendation="Serve login and account flows only over HTTPS.",
                        burp_tool="Burp Proxy history",
                        owasp="A02:2021 Cryptographic Failures",
                    )
                )
    return findings


def _parameter_findings(session: requests.Session, pages: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        parsed = urlparse(page["url"])
        params = parse_qsl(parsed.query, keep_blank_values=True)
        for key, value in params[:5]:
            if key.lower() in {"id", "user", "userid", "account", "accountid", "order", "invoice"} or value.isdigit():
                findings.append(
                    Finding(
                        title=f"IDOR candidate parameter: {key}",
                        category="Broken Access Control",
                        severity="Medium",
                        score=5.9,
                        evidence=f"{page['url']} contains object-like parameter {key}={value!r}",
                        recommendation="Verify object-level authorization with two accounts before exposing resource IDs.",
                        burp_tool="Burp Autorize + Comparer",
                        owasp="A01:2021 Broken Access Control",
                    )
                )
            reflected = _safe_reflection_check(session, parsed, key, params)
            if reflected:
                findings.append(reflected)
    return findings


def _safe_reflection_check(session: requests.Session, parsed: object, key: str, params: list[tuple[str, str]]) -> Finding | None:
    marker = "AI_VAPT_REFLECT_7429"
    updated = [(k, marker if k == key else v) for k, v in params]
    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urlencode(updated), ""))
    try:
        resp = session.get(test_url, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        return None
    if marker in resp.text:
        return Finding(
            title=f"Reflected parameter observed: {key}",
            category="XSS Candidate",
            severity="Medium",
            score=6.0,
            evidence=f"Harmless marker reflected in response from {test_url}",
            recommendation="Manually verify context-aware encoding; reflected input can become XSS if not escaped.",
            burp_tool="Burp Repeater + DOM Invader",
            owasp="A03:2021 Injection",
        )
    return None


def _technology_findings(response: requests.Response, pages: list[dict]) -> list[Finding]:
    haystack = "\n".join([str(response.headers)] + [page["text"][:20_000] for page in pages])
    detected = [name for name, pattern in TECH_PATTERNS if pattern.search(haystack)]
    if not detected:
        return []
    return [
        Finding(
            title="Technology fingerprint detected",
            category="CVE Intelligence",
            severity="Info",
            score=0.0,
            evidence=f"Detected: {', '.join(sorted(set(detected)))}",
            recommendation="Use the NVD CVE panel to correlate framework/runtime versions and patch advisories.",
            burp_tool="Burp Target technologies",
            owasp="A06:2021 Vulnerable and Outdated Components",
        )
    ]


def _dedupe(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    unique: list[dict] = []
    for finding in findings:
        key = (finding["title"], finding["evidence"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
