#!/usr/bin/env python3
import argparse
import xml.etree.ElementTree as ET


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse Nmap XML into concise service findings")
    parser.add_argument("xml_file")
    args = parser.parse_args()
    root = ET.parse(args.xml_file).getroot()
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.attrib.get("addr", "unknown") if addr is not None else "unknown"
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            service = port.find("service")
            name = service.attrib.get("name", "unknown") if service is not None else "unknown"
            product = service.attrib.get("product", "") if service is not None else ""
            version = service.attrib.get("version", "") if service is not None else ""
            print(f"{ip} tcp/{port.attrib.get('portid')} {name} {product} {version}".strip())


if __name__ == "__main__":
    main()
