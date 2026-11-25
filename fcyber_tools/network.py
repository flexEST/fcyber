"""Report local Linux socket bindings without probing any hosts."""

import ipaddress
import json
from pathlib import Path
import socket
import sys


def decode_address(address):
    raw = bytes.fromhex(address)
    if sys.byteorder == "little":
        raw = b"".join(raw[index:index + 4][::-1] for index in range(0, len(raw), 4))
    return ipaddress.ip_address(raw)


def bindings(args):
    if not sys.platform.startswith("linux"):
        raise ValueError("bindings requires Linux /proc socket tables")
    report = []
    for table in ("tcp", "tcp6", "udp", "udp6"):
        try:
            stream = (Path("/proc/net") / table).open(encoding="ascii")
        except FileNotFoundError:
            if table.endswith("6"):
                continue
            raise
        with stream:
            next(stream, None)
            for line in stream:
                fields = line.split()
                protocol = table[:3]
                if protocol == "tcp" and fields[3] != "0A":
                    continue
                address_hex, port_hex = fields[1].split(":")
                address = decode_address(address_hex)
                port = int(port_hex, 16)
                if not port:
                    continue
                mapped = getattr(address, "ipv4_mapped", None)
                effective_address = mapped if mapped is not None else address
                if args.non_loopback and effective_address.is_loopback:
                    continue
                report.append({
                    "protocol": protocol,
                    "family": "IPv6" if address.version == 6 else "IPv4",
                    "address": str(address),
                    "port": port,
                    "uid": int(fields[7]),
                })
    print(json.dumps(sorted(report, key=lambda item: (
        item["protocol"], item["port"], item["address"], item["uid"]
    )), indent=2))
    return 0


def resolve(args):
    records = socket.getaddrinfo(args.host, None, type=socket.SOCK_STREAM)
    addresses = {ipaddress.ip_address(record[4][0]) for record in records}
    print(json.dumps({
        "host": args.host,
        "ipv4": sorted(str(address) for address in addresses if address.version == 4),
        "ipv6": sorted(str(address) for address in addresses if address.version == 6),
    }, indent=2))
    return 0
