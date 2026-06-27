#!/usr/bin/env python3
import argparse
import socket


WORDS = ["www", "api", "app", "admin", "dev", "test", "stage", "staging", "vpn", "mail", "portal"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Small DNS-based subdomain enumerator")
    parser.add_argument("domain")
    parser.add_argument("--wordlist")
    args = parser.parse_args()
    words = WORDS
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8") as f:
            words = [line.strip() for line in f if line.strip()]
    for word in words:
        host = f"{word}.{args.domain}"
        try:
            print(f"{host:40} {socket.gethostbyname(host)}")
        except socket.gaierror:
            pass


if __name__ == "__main__":
    main()
