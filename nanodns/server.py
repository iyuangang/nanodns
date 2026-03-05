"""
Async UDP DNS server.
Supports hot-reload, cache pruning, peer config-sync, and catch-up.
"""

import asyncio
import logging
import signal
from typing import Optional

from .config import Config, bump_version, load_config
from .cache import DNSCache
from .handler import DNSHandler
from .mgmt import MgmtServer

logger = logging.getLogger(__name__)


class DNSServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: "DNSServer"):
        self.server    = server          # always points at the live DNSServer
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        try:
            # Read handler from the server each time so that apply_config()
            # swaps take effect immediately without restarting the transport.
            response = self.server.handler.handle(data)
            if response:
                self.transport.sendto(response, addr)
        except Exception as exc:
            logger.error("Query error from %s: %s", addr, exc, exc_info=True)

    def error_received(self, exc: Exception):
        logger.error("DNS protocol error: %s", exc)


class DNSServer:
    def __init__(self, config: Config):
        self.config   = config
        self.cache    = DNSCache(max_size=config.server.cache_size)
        self.handler  = DNSHandler(config, self.cache)
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._running = False
        self._mgmt:   Optional[MgmtServer] = None

    # ── config management ─────────────────────────────────────────────────────

    def reload_config(self, path: Optional[str] = None) -> None:
        """Read config from disk, bump the version, and apply in-process.

        The version bump ensures every disk-originated reload produces a
        strictly higher version number that peers will accept.
        """
        try:
            cfg_path = path or (str(self.config._path) if self.config._path else None)
            new_cfg  = load_config(cfg_path)

            # Bump: new version = max(disk version, current in-memory version) + 1
            # This handles the case where the operator manually edited the file
            # and set an arbitrary version number.
            new_version = max(new_cfg.version, self.config.version) + 1
            raw_bumped  = _set_version(new_cfg._raw, new_version)

            from .config import load_config_from_bytes
            final_cfg = load_config_from_bytes(raw_bumped, new_cfg._path)
            self.apply_config(final_cfg)

        except Exception as exc:
            logger.error("Failed to reload config: %s", exc)

    def apply_config(self, new_cfg: Config) -> None:
        """Swap in a new Config object and clear the cache.

        Called from reload_config() (file-originated) and from /sync
        (peer-push-originated).  The UDP transport keeps running — no gap.
        """
        self.config  = new_cfg
        self.cache.clear()
        self.handler = DNSHandler(self.config, self.cache)
        logger.info(
            "Config applied  v%d  checksum=%s  (%d records  %d zones)",
            new_cfg.version, new_cfg.checksum,
            len(new_cfg.records), len(new_cfg.zones),
        )

    # ── background tasks ──────────────────────────────────────────────────────

    async def _watch_config(self) -> None:
        """Detect mtime changes → reload + push to peers."""
        while self._running:
            await asyncio.sleep(5)
            if not self.config.is_stale():
                continue
            logger.info("Config file changed — reloading")
            old_version = self.config.version
            try:
                self.reload_config()
            except Exception:
                continue
            # Push to peers only if content changed (version advanced).
            if self._mgmt and self.config.version > old_version:
                loop = asyncio.get_running_loop()
                cfg  = self.config
                loop.run_in_executor(None, self._mgmt.push_to_peers, cfg)

    async def _prune_cache(self) -> None:
        """Evict expired cache entries and log stats every 60 s."""
        while self._running:
            await asyncio.sleep(60)
            self.cache.prune()
            s = self.cache.stats
            logger.debug(
                "Cache  size=%d  hits=%d  misses=%d  hit_rate=%s%%",
                s["size"], s["hits"], s["misses"], s["hit_rate"],
            )

    async def _reconcile_peers(self) -> None:
        """Periodically check peers for a newer config version and pull it.

        This is the catch-up mechanism: a node that was offline while a
        config change happened will automatically get the latest version
        within one reconcile interval after it comes back.
        """
        if not self.config.server.peers:
            return
        # Wait a bit after startup so the mgmt server is ready on all nodes.
        await asyncio.sleep(10)
        while self._running:
            if self._mgmt:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, self._mgmt.catchup_from_peers)
            await asyncio.sleep(30)   # reconcile every 30 s

    # ── lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        host = self.config.server.host
        port = self.config.server.port

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: DNSServerProtocol(self),
            local_addr=(host, port),
        )
        self._transport = transport
        self._running   = True

        logger.info("NanoDNS listening on udp %s:%d", host, port)
        logger.info(
            "Config  v%d  checksum=%s  (%d records  %d zones)",
            self.config.version, self.config.checksum,
            len(self.config.records), len(self.config.zones),
        )
        logger.info(
            "Cache: %s  max=%d  ttl=%ds",
            "on" if self.config.server.cache_enabled else "off",
            self.config.server.cache_size, self.config.server.cache_ttl,
        )
        if self.config.server.peers:
            logger.info("Peers: %s", self.config.server.peers)

        # Start management HTTP server if mgmt_port is non-zero.
        if self.config.server.mgmt_port:
            self._mgmt = MgmtServer(
                host=self.config.server.mgmt_host,
                port=self.config.server.mgmt_port,
            )
            self._mgmt.start(self)

        tasks = [
            asyncio.create_task(self._watch_config(),    name="watch_config"),
            asyncio.create_task(self._prune_cache(),     name="prune_cache"),
            asyncio.create_task(self._reconcile_peers(), name="reconcile_peers"),
        ]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        finally:
            transport.close()
            self._running = False
            if self._mgmt:
                self._mgmt.stop()
            logger.info("NanoDNS stopped")

    def cache_stats(self) -> dict:
        return self.cache.stats


# ── helpers ───────────────────────────────────────────────────────────────────

def _set_version(raw: bytes, version: int) -> bytes:
    """Return *raw* with server.config_version set to *version*."""
    data = __import__("json").loads(raw)
    data.setdefault("server", {})["config_version"] = version
    return __import__("json").dumps(data, indent=2, ensure_ascii=False).encode()


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


async def run_server(config: Config) -> None:
    """Run the server with clean SIGINT / SIGTERM shutdown."""
    server = DNSServer(config)
    loop   = asyncio.get_running_loop()
    stop   = asyncio.Event()

    def _on_signal():
        logger.info("Received shutdown signal")
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except NotImplementedError:
            pass   # Windows

    task = asyncio.create_task(server.start())
    await stop.wait()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
