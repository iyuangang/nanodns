"""
Upstream DNS resolver — forwards queries to upstream servers.
Tries each server in order, falls back on timeout/error.
"""

import socket
import logging
import struct
from typing import Optional
from .protocol import DNSMessage, build_message, parse_message

logger = logging.getLogger(__name__)


def resolve_upstream(
    query: DNSMessage,
    upstream_servers: list[str],
    port: int = 53,
    timeout: float = 3.0,
) -> Optional[DNSMessage]:
    """
    Forward a DNS query to upstream servers.
    Returns the parsed response, or None if all upstreams fail.
    """
    raw_query = build_message(query)

    for server in upstream_servers:
        try:
            response = _query_udp(raw_query, server, port, timeout)
            if response is not None:
                return response
        except Exception as e:
            logger.debug(f"Upstream {server} failed: {e}")

    logger.warning(f"All upstream servers failed for query {query.questions}")
    return None


def _query_udp(
    raw_query: bytes,
    server: str,
    port: int,
    timeout: float,
) -> Optional[DNSMessage]:
    """Send a DNS query over UDP and return the parsed response."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(raw_query, (server, port))
        data, _ = sock.recvfrom(4096)
        return parse_message(data)
