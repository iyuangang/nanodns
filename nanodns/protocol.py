"""
DNS protocol parsing and building.
Supports: A, AAAA, CNAME, MX, TXT, PTR, NS record types.
"""

import struct
import socket
from dataclasses import dataclass, field
from typing import Optional
from enum import IntEnum


class QType(IntEnum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    ANY = 255


class QClass(IntEnum):
    IN = 1
    ANY = 255


QTYPE_NAMES = {v: k for k, v in QType.__members__.items()}


@dataclass
class DNSQuestion:
    name: str
    qtype: int
    qclass: int

    @property
    def qtype_name(self) -> str:
        return QTYPE_NAMES.get(self.qtype, f"TYPE{self.qtype}")


@dataclass
class DNSRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes

    @property
    def rtype_name(self) -> str:
        return QTYPE_NAMES.get(self.rtype, f"TYPE{self.rtype}")


@dataclass
class DNSMessage:
    msg_id: int
    flags: int
    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSRecord] = field(default_factory=list)
    authority: list[DNSRecord] = field(default_factory=list)
    additional: list[DNSRecord] = field(default_factory=list)

    @property
    def is_query(self) -> bool:
        return not bool(self.flags & 0x8000)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    def set_rcode(self, code: int):
        self.flags = (self.flags & ~0x000F) | (code & 0x000F)


def encode_name(name: str) -> bytes:
    """Encode a domain name to DNS wire format."""
    if name == ".":
        return b"\x00"
    parts = name.rstrip(".").split(".")
    result = b""
    for part in parts:
        encoded = part.encode()
        result += bytes([len(encoded)]) + encoded
    return result + b"\x00"


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name from wire format, handling compression pointers."""
    labels = []
    visited = set()
    original_offset = offset

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            # Compression pointer
            if offset in visited:
                raise ValueError("DNS name compression loop detected")
            visited.add(offset)
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            sub_name, _ = decode_name(data, pointer)
            if sub_name:
                labels.append(sub_name)
            break
        else:
            offset += 1
            labels.append(data[offset : offset + length].decode())
            offset += length

    return ".".join(labels), offset


def parse_message(data: bytes) -> DNSMessage:
    """Parse raw DNS message bytes into a DNSMessage object."""
    if len(data) < 12:
        raise ValueError("DNS message too short")

    msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    msg = DNSMessage(msg_id=msg_id, flags=flags)

    offset = 12

    # Questions
    for _ in range(qdcount):
        name, offset = decode_name(data, offset)
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        msg.questions.append(DNSQuestion(name=name, qtype=qtype, qclass=qclass))

    # Resource records (answers, authority, additional)
    def parse_records(count):
        nonlocal offset
        records = []
        for _ in range(count):
            name, offset = decode_name(data, offset)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            rdata = data[offset : offset + rdlen]
            offset += rdlen
            records.append(DNSRecord(name=name, rtype=rtype, rclass=rclass, ttl=ttl, rdata=rdata))
        return records

    msg.answers = parse_records(ancount)
    msg.authority = parse_records(nscount)
    msg.additional = parse_records(arcount)

    return msg


def build_message(msg: DNSMessage) -> bytes:
    """Serialize a DNSMessage to bytes."""
    header = struct.pack(
        "!HHHHHH",
        msg.msg_id,
        msg.flags,
        len(msg.questions),
        len(msg.answers),
        len(msg.authority),
        len(msg.additional),
    )

    body = b""
    for q in msg.questions:
        body += encode_name(q.name) + struct.pack("!HH", q.qtype, q.qclass)

    for section in (msg.answers, msg.authority, msg.additional):
        for r in section:
            body += encode_name(r.name)
            body += struct.pack("!HHIH", r.rtype, r.rclass, r.ttl, len(r.rdata))
            body += r.rdata

    return header + body


# --- rdata encoders ---

def encode_a(ip: str) -> bytes:
    return socket.inet_aton(ip)


def encode_aaaa(ip: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, ip)


def encode_cname(name: str) -> bytes:
    return encode_name(name)


def encode_ptr(name: str) -> bytes:
    return encode_name(name)


def encode_ns(name: str) -> bytes:
    return encode_name(name)


def encode_mx(priority: int, exchange: str) -> bytes:
    return struct.pack("!H", priority) + encode_name(exchange)


def encode_txt(text: str) -> bytes:
    encoded = text.encode()
    # TXT records can have multiple strings; we use a single string here
    return bytes([len(encoded)]) + encoded


def encode_soa(
    mname: str,
    rname: str,
    serial: int,
    refresh: int,
    retry: int,
    expire: int,
    minimum: int,
) -> bytes:
    return (
        encode_name(mname)
        + encode_name(rname)
        + struct.pack("!IIIII", serial, refresh, retry, expire, minimum)
    )
