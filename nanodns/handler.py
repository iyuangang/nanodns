"""
Core DNS request handler.
Handles local records, rewrites, caching, and upstream forwarding.
"""

import logging
import copy
import time
from typing import Optional

from .protocol import (
    DNSMessage, DNSQuestion, DNSRecord,
    QType, QClass,
    encode_a, encode_aaaa, encode_cname, encode_mx,
    encode_txt, encode_ptr, encode_ns, encode_soa,
    build_message, parse_message,
)
from .config import Config, RecordEntry, ZoneConfig
from .cache import DNSCache
from .resolver import resolve_upstream

logger = logging.getLogger(__name__)

# RCODE constants
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5


def make_response(query: DNSMessage, rcode: int = RCODE_NOERROR) -> DNSMessage:
    """Create a base response message from a query."""
    # QR=1 (response), AA=1 (authoritative), RD=1, RA=1
    flags = 0x8000 | 0x0400 | 0x0100 | 0x0080 | rcode
    resp = DNSMessage(msg_id=query.msg_id, flags=flags, questions=list(query.questions))
    return resp


def encode_record(rec: RecordEntry) -> Optional[bytes]:
    """Encode a RecordEntry's value to DNS wire format rdata."""
    rtype = rec.rtype.upper()
    try:
        if rtype == "A":
            return encode_a(rec.value)
        elif rtype == "AAAA":
            return encode_aaaa(rec.value)
        elif rtype == "CNAME":
            return encode_cname(rec.value)
        elif rtype == "PTR":
            return encode_ptr(rec.value)
        elif rtype == "NS":
            return encode_ns(rec.value)
        elif rtype == "MX":
            return encode_mx(rec.priority, rec.value)
        elif rtype == "TXT":
            return encode_txt(rec.value)
        else:
            logger.warning(f"Unsupported record type: {rtype}")
            return None
    except Exception as e:
        logger.error(f"Failed to encode record {rec}: {e}")
        return None


RTYPE_MAP = {
    "A": QType.A,
    "AAAA": QType.AAAA,
    "CNAME": QType.CNAME,
    "MX": QType.MX,
    "TXT": QType.TXT,
    "PTR": QType.PTR,
    "NS": QType.NS,
    "SOA": QType.SOA,
}


class DNSHandler:
    def __init__(self, config: Config, cache: DNSCache):
        self.config = config
        self.cache = cache

    def handle(self, data: bytes) -> bytes:
        """Process a raw DNS query and return a raw DNS response."""
        try:
            query = parse_message(data)
        except Exception as e:
            logger.warning(f"Failed to parse DNS query: {e}")
            return b""

        if not query.questions:
            resp = make_response(query, RCODE_FORMERR)
            return build_message(resp)

        question = query.questions[0]
        name = question.name.rstrip(".").lower()
        qtype = question.qtype
        qclass = question.qclass

        if self.config.server.log_queries:
            qtype_name = question.qtype_name
            logger.info(f"Query: {name} {qtype_name}")

        # 1. Check rewrites
        rewrite = self.config.get_rewrite(name)
        if rewrite:
            if rewrite.action == "nxdomain":
                logger.debug(f"Rewrite NXDOMAIN: {name}")
                resp = make_response(query, RCODE_NXDOMAIN)
                return build_message(resp)

        # 2. Check local records
        local_response = self._resolve_local(query, name, qtype, qclass)
        if local_response is not None:
            return build_message(local_response)

        # 3. Check cache
        cached = self.cache.get(name, qtype, qclass)
        if cached is not None:
            logger.debug(f"Cache hit: {name}")
            cached_copy = copy.copy(cached)
            cached_copy.msg_id = query.msg_id
            return build_message(cached_copy)

        # 4. Forward to upstream
        upstream = self.config.server.upstream
        if not upstream:
            resp = make_response(query, RCODE_SERVFAIL)
            return build_message(resp)

        upstream_resp = resolve_upstream(
            query,
            upstream,
            port=self.config.server.upstream_port,
            timeout=self.config.server.upstream_timeout,
        )

        if upstream_resp is None:
            resp = make_response(query, RCODE_SERVFAIL)
            return build_message(resp)

        # Cache the upstream response
        if self.config.server.cache_enabled and upstream_resp.answers:
            min_ttl = min((r.ttl for r in upstream_resp.answers), default=self.config.server.cache_ttl)
            effective_ttl = min(min_ttl, self.config.server.cache_ttl)
            self.cache.set(name, qtype, qclass, upstream_resp, effective_ttl)

        return build_message(upstream_resp)

    def _resolve_local(
        self, query: DNSMessage, name: str, qtype: int, qclass: int
    ) -> Optional[DNSMessage]:
        """Try to answer from local records. Returns None if not found."""

        # Handle SOA queries for known zones
        if qtype == QType.SOA:
            for zone_name, zone in self.config.zones.items():
                if name == zone_name.lower() and zone.soa:
                    resp = make_response(query)
                    soa = zone.soa
                    rdata = encode_soa(
                        soa.mname, soa.rname,
                        soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
                    )
                    resp.answers.append(DNSRecord(
                        name=name, rtype=QType.SOA, rclass=QClass.IN,
                        ttl=soa.minimum, rdata=rdata
                    ))
                    return resp

        # Determine what record type names to look up
        rtype_names: list[str] = []
        if qtype == QType.ANY:
            rtype_names = list(RTYPE_MAP.keys())
        else:
            for rtype_name, qt in RTYPE_MAP.items():
                if qt == qtype:
                    rtype_names = [rtype_name]
                    break

        if not rtype_names:
            return None  # Unsupported type, forward upstream

        found_records: list[DNSRecord] = []

        for rtype_name in rtype_names:
            matches = self.config.get_records(name, rtype_name)
            for rec in matches:
                rdata = encode_record(rec)
                if rdata is None:
                    continue
                qtype_val = RTYPE_MAP.get(rtype_name, qtype)
                found_records.append(DNSRecord(
                    name=name,
                    rtype=qtype_val,
                    rclass=QClass.IN,
                    ttl=rec.ttl,
                    rdata=rdata,
                ))

        if not found_records:
            # Check if the name is within a known zone (NXDOMAIN vs forward)
            for zone_name in self.config.zones:
                if name == zone_name.lower() or name.endswith("." + zone_name.lower()):
                    # Name is in our zone but no record found → NXDOMAIN
                    resp = make_response(query, RCODE_NXDOMAIN)
                    return resp
            return None

        resp = make_response(query)
        resp.answers = found_records
        return resp
