#!/usr/bin/env python3
import argparse
from urllib.parse import parse_qsl, urlparse


SUSPICIOUS = {"id", "uid", "user", "account", "order", "invoice", "search", "q", "filter", "sort"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Find URL parameters that deserve SQLi testing")
    parser.add_argument("url")
    args = parser.parse_args()
    parsed = urlparse(args.url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        print("No query parameters found.")
        return
    for key, value in params:
        risk = "candidate" if key.lower() in SUSPICIOUS or value.isdigit() else "review"
        print(f"{risk:9} {key}={value!r} payloads: ' OR '1'='1 | 1 AND SLEEP(2)")


if __name__ == "__main__":
    main()
