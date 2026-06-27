#!/usr/bin/env python3
import argparse
import urllib.request


REQUIRED = {
    "content-security-policy": "Mitigates XSS and content injection.",
    "strict-transport-security": "Enforces HTTPS for repeat visitors.",
    "x-frame-options": "Reduces clickjacking exposure.",
    "x-content-type-options": "Prevents MIME sniffing.",
    "referrer-policy": "Limits sensitive URL leakage.",
    "permissions-policy": "Restricts browser feature abuse.",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP security header auditor")
    parser.add_argument("url")
    args = parser.parse_args()
    req = urllib.request.Request(args.url, headers={"User-Agent": "AI-for-VAPT-header-auditor/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
    for header, reason in REQUIRED.items():
        status = "OK" if header in headers else "MISSING"
        print(f"{status:8} {header:30} {reason}")


if __name__ == "__main__":
    main()
