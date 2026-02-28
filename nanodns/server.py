"""
Async UDP DNS server using asyncio.
Supports hot-reload of config and periodic cache pruning.
"""

import asyncio
import logging
import signal
import threading
import time
from pathlib import Path
from typing import Optional

from .config import Config, load_config
from .cache import DNSCache
from .handler import DNSHandler

logger = logging.getLogger(__name__)


class DNSServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler: DNSHandler):
        self.handler = handler
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        try:
            response = self.handler.handle(data)
            if response:
                self.transport.sendto(response, addr)
        except Exception as e:
            logger.error(f"Error handling query from {addr}: {e}", exc_info=True)

    def error_received(self, exc: Exception):
        logger.error(f"DNS protocol error: {exc}")


class DNSServer:
    def __init__(self, config: Config):
        self.config = config
        self.cache = DNSCache(max_size=config.server.cache_size)
        self.handler = DNSHandler(config, self.cache)
        self._protocol: Optional[DNSServerProtocol] = None
        self._running = False

    def reload_config(self, path: Optional[str] = None):
        """Reload configuration from disk."""
        try:
            new_config = load_config(path or str(self.config._path))
            self.config = new_config
            self.cache.clear()
            self.handler = DNSHandler(self.config, self.cache)
            logger.info("Configuration reloaded successfully")
        except Exception as e:
            logger.error(f"Failed to reload config: {e}")

    async def _watch_config(self):
        """Periodically check if config file has changed and reload."""
        while self._running:
            await asyncio.sleep(5)
            if self.config.is_stale():
                logger.info("Config file changed, reloading...")
                self.reload_config()

    async def _prune_cache(self):
        """Periodically remove expired cache entries."""
        while self._running:
            await asyncio.sleep(60)
            self.cache.prune()
            stats = self.cache.stats
            logger.debug(
                f"Cache stats: size={stats['size']}, "
                f"hits={stats['hits']}, misses={stats['misses']}, "
                f"hit_rate={stats['hit_rate']}%"
            )

    async def start(self):
        """Start the DNS server."""
        host = self.config.server.host
        port = self.config.server.port

        loop = asyncio.get_running_loop()

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: DNSServerProtocol(self.handler),
            local_addr=(host, port),
        )
        self._protocol = protocol
        self._running = True

        logger.info(f"NanoDNS listening on {host}:{port}/udp")
        logger.info(f"Upstream servers: {self.config.server.upstream}")
        logger.info(
            f"Cache: {'enabled' if self.config.server.cache_enabled else 'disabled'} "
            f"(max_size={self.config.server.cache_size}, ttl={self.config.server.cache_ttl}s)"
        )
        logger.info(f"Loaded {len(self.config.records)} records, {len(self.config.zones)} zones")

        tasks = [
            asyncio.create_task(self._watch_config()),
            asyncio.create_task(self._prune_cache()),
        ]

        try:
            # Wait forever (until cancelled)
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        finally:
            transport.close()
            self._running = False
            logger.info("NanoDNS stopped")

    def cache_stats(self) -> dict:
        return self.cache.stats


def setup_logging(level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


async def run_server(config: Config):
    """Entry point to run the server with graceful shutdown."""
    server = DNSServer(config)

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def handle_signal():
        logger.info("Received shutdown signal")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, handle_signal)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    server_task = asyncio.create_task(server.start())

    await stop_event.wait()
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass
