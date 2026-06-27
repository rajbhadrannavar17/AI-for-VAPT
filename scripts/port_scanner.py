#!/usr/bin/env python3
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor


def check(host: str, port: int) -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.8)
    try:
        if sock.connect_ex((host, port)) == 0:
            return f"open tcp/{port}"
    finally:
        sock.close()
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Authorized TCP port scanner")
    parser.add_argument("host")
    parser.add_argument("--ports", default="21,22,25,53,80,110,139,143,443,445,3306,3389,5432,6379,8080,8443")
    args = parser.parse_args()
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    with ThreadPoolExecutor(max_workers=64) as pool:
        for result in pool.map(lambda p: check(args.host, p), ports):
            if result:
                print(result)


if __name__ == "__main__":
    main()
