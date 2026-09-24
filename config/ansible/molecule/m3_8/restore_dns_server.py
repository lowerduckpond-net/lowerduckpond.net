"""Controlled SOA/NS discovery around Pebble's real TXT challenge responder.

Only the two run-owned zones are synthesized. Other questions go to the
fixture's original resolver, allowing ordinary package/bootstrap downloads.
"""

from __future__ import annotations

import socket
import socketserver
import struct
import threading
from pathlib import Path

ZONES = ("lowerduckpond.com", "lowerduckpond.net")
PORT = 8054
TXT_PORT = 8053
MAX_PACKET = 65535
A, NS, SOA = 1, 2, 6


def encoded(name: str) -> bytes:
    return (
        b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\0"
    )


def question(packet: bytes) -> tuple[str, int, int]:
    if len(packet) < 17 or struct.unpack("!H", packet[4:6])[0] != 1:  # noqa: PLR2004
        raise ValueError("invalid fixture DNS question")
    labels = []
    position = 12
    while position < len(packet):
        length = packet[position]
        position += 1
        if length == 0:
            break
        if length > 63 or position + length >= len(packet):  # noqa: PLR2004
            raise ValueError("compressed or oversized fixture DNS question")
        labels.append(packet[position : position + length].decode("ascii").lower())
        position += length
    if position + 4 > len(packet):
        raise ValueError("truncated fixture DNS question")
    kind, klass = struct.unpack("!HH", packet[position : position + 4])
    if klass != 1:
        raise ValueError("unsupported fixture DNS class")
    return ".".join(labels), kind, position + 4


class Resolver:
    def __init__(self, address: str, upstream: str) -> None:
        self.address = address
        self.upstream = upstream

    def answer(self, packet: bytes) -> bytes:
        name, kind, end = question(packet)
        zone = next((zone for zone in ZONES if name == zone or name.endswith("." + zone)), None)
        if zone is None or kind not in {A, NS, SOA}:
            target = (self.upstream, 53) if zone is None else ("127.0.0.1", TXT_PORT)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                connection.settimeout(5)
                connection.connect(target)
                connection.send(packet)
                return connection.recv(MAX_PACKET)
        nameserver = "ns." + zone
        soa = (
            encoded(nameserver)
            + encoded("hostmaster." + zone)
            + struct.pack("!IIIII", 1, 30, 30, 300, 1)
        )
        answers = []
        if kind == A:
            answers.append((name, A, socket.inet_aton(self.address)))
        elif kind == NS and name == zone:
            answers.append((zone, NS, encoded(nameserver)))
        elif kind == SOA and name == zone:
            answers.append((zone, SOA, soa))
        authority = [] if answers else [(zone, SOA, soa)]
        flags = 0x8480 | (struct.unpack("!H", packet[2:4])[0] & 0x0100)
        result = packet[:2] + struct.pack("!HHHHH", flags, 1, len(answers), len(authority), 0)
        result += packet[12:end]
        for owner, rrtype, data in (*answers, *authority):
            result += encoded(owner) + struct.pack("!HHIH", rrtype, 1, 1, len(data)) + data
        return result


def serve(address: str) -> None:
    upstream = next(
        line.split()[1]
        for line in Path("/etc/resolv.conf").read_text().splitlines()
        if line.startswith("nameserver ")
    )
    resolver = Resolver(address, upstream)

    class UDP(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            packet, connection = self.request
            connection.sendto(resolver.answer(packet), self.client_address)

    class TCP(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            header = self.rfile.read(2)
            if len(header) != 2:  # noqa: PLR2004
                return
            length = struct.unpack("!H", header)[0]
            response = resolver.answer(self.rfile.read(length))
            self.wfile.write(struct.pack("!H", len(response)) + response)

    for server in (
        socketserver.ThreadingUDPServer(("0.0.0.0", PORT), UDP),  # noqa: S104 - owned fixture
        socketserver.ThreadingTCPServer(("0.0.0.0", PORT), TCP),  # noqa: S104
    ):
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
