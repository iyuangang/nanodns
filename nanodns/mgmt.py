"""
HTTP management server for NanoDNS HA.

Runs in a daemon thread alongside the DNS server (no extra dependencies).

Endpoints
─────────
GET  /health        Liveness probe   200 ok  /  503 unavailable
GET  /ready         Readiness probe  200 ready  /  503 not_ready
GET  /metrics       Cache stats, uptime, version
GET  /cluster       This node + all peer statuses (version + health)
GET  /config/raw    Return raw config JSON bytes  (peers pull from here)
POST /reload        Reload from disk, bump version, push to peers
POST /sync          Receive a versioned config push from a peer

Config-sync protocol
────────────────────
  Push (on reload):
    1. Node A reloads from disk.
    2. A calls bump_version() → new _raw with version N+1.
    3. A applies the new config in-process.
    4. A POSTs the raw bytes to POST /sync on every peer.
    5. Peer checks: if its own version >= incoming version → 200 already_current.
       Otherwise it writes the bytes to disk, applies in-process → 200 applied.

  Pull (catch-up on startup or periodic reconcile):
    1. Node B queries GET /cluster on any reachable peer.
    2. If any peer reports a higher version, B fetches GET /config/raw from
       that peer and applies it (same path as /sync but initiated by B).
    3. B then pushes the fetched config onward to its own peers so any
       other lagging node also catches up.

  This gives:
    • Push: sub-second propagation for online nodes.
    • Pull: automatic catch-up when a node comes back online after downtime.
    • Idempotency: checksum guard prevents re-applying identical bytes.
    • No split-brain write: only the node that reloads from disk increments
      the version; peers never increment on their own.
"""

import json
import logging
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .server import DNSServer

logger = logging.getLogger(__name__)

_PEER_TIMEOUT = 5   # seconds for outbound HTTP calls to peers


# ── HTTP request handler ──────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):
    """One instance per request; shared state accessed via self.mgmt."""

    mgmt: "MgmtServer"   # class-level, injected by MgmtServer.start()

    def log_message(self, fmt, *args):   # suppress default stdout logging
        logger.debug("mgmt %s  %s", self.address_string(), fmt % args)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _send_json(self, code: int, body: dict) -> None:
        payload = json.dumps(body, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_raw(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n else b""

    def _srv(self):
        return self.mgmt.dns_server

    # ── GET ───────────────────────────────────────────────────────────────────

    def do_GET(self):
        path = self.path.split("?")[0]
        srv  = self._srv()

        if path == "/health":
            if srv is None or not srv._running:
                self._send_json(503, {"status": "unavailable"})
            else:
                self._send_json(200, {
                    "status":   "ok",
                    "version":  srv.config.version,
                    "uptime_s": self.mgmt.uptime,
                })

        elif path == "/ready":
            if srv is None or not srv._running or srv.config is None:
                self._send_json(503, {"status": "not_ready"})
            else:
                cfg = srv.config
                self._send_json(200, {
                    "status":   "ready",
                    "version":  cfg.version,
                    "checksum": cfg.checksum,
                    "records":  len(cfg.records),
                    "zones":    len(cfg.zones),
                })

        elif path == "/metrics":
            if srv is None:
                self._send_json(503, {"error": "server not initialised"})
                return
            cfg   = srv.config
            stats = srv.cache_stats()
            self._send_json(200, {
                "uptime_s": self.mgmt.uptime,
                "version":  cfg.version,
                "checksum": cfg.checksum,
                "records":  len(cfg.records),
                "zones":    len(cfg.zones),
                "cache":    stats,
            })

        elif path == "/cluster":
            self._send_json(200, self.mgmt.cluster_status())

        elif path == "/config/raw":
            # Peers call this to pull the current raw config during catch-up.
            if srv is None or not srv.config or not srv.config._raw:
                self._send_json(503, {"error": "no config available"})
                return
            self._send_raw(200, srv.config._raw, "application/json")

        else:
            self._send_json(404, {"error": f"unknown path: {path}"})

    # ── POST ──────────────────────────────────────────────────────────────────

    def do_POST(self):
        path = self.path.split("?")[0]
        srv  = self._srv()

        if path == "/reload":
            # Reload config from disk, bump version, push to all peers.
            if srv is None:
                self._send_json(503, {"error": "server not initialised"})
                return
            try:
                srv.reload_config()            # reads disk, bumps version, applies
                push_results = self.mgmt.push_to_peers(srv.config)
                cfg = srv.config
                self._send_json(200, {
                    "status":   "reloaded",
                    "version":  cfg.version,
                    "checksum": cfg.checksum,
                    "records":  len(cfg.records),
                    "zones":    len(cfg.zones),
                    "peers":    push_results,
                })
            except Exception as exc:
                logger.exception("Reload failed")
                self._send_json(500, {"error": str(exc)})

        elif path == "/sync":
            # Receive a versioned config push from a peer.
            raw = self._read_body()
            if not raw:
                self._send_json(400, {"error": "empty body"})
                return
            if srv is None:
                self._send_json(503, {"error": "server not initialised"})
                return
            try:
                import hashlib
                from .config import load_config_from_bytes
                incoming_checksum = hashlib.sha256(raw).hexdigest()[:16]

                # Parse just the version without full parsing first.
                incoming_version = json.loads(raw).get("server", {}).get("config_version", 1)
                my_version       = srv.config.version if srv.config else 0

                # Already up to date (same checksum) — idempotency guard.
                if srv.config and srv.config.checksum == incoming_checksum:
                    self._send_json(200, {
                        "status":   "already_current",
                        "version":  my_version,
                        "checksum": incoming_checksum,
                    })
                    return

                # Peer is behind us — reject to prevent rollback.
                if incoming_version < my_version:
                    self._send_json(409, {
                        "status":          "rejected_stale",
                        "my_version":      my_version,
                        "incoming_version": incoming_version,
                    })
                    return

                # Accept and apply.
                new_cfg = load_config_from_bytes(raw, srv.config._path)
                srv.apply_config(new_cfg)
                logger.info(
                    "Config applied from peer push  v%d  checksum=%s",
                    new_cfg.version, new_cfg.checksum,
                )
                self._send_json(200, {
                    "status":   "applied",
                    "version":  new_cfg.version,
                    "checksum": new_cfg.checksum,
                    "records":  len(new_cfg.records),
                    "zones":    len(new_cfg.zones),
                })
            except Exception as exc:
                logger.exception("Sync push failed")
                self._send_json(500, {"error": str(exc)})

        else:
            self._send_json(404, {"error": f"unknown path: {path}"})


# ── MgmtServer ────────────────────────────────────────────────────────────────

class MgmtServer:
    """Lightweight HTTP management server in a daemon thread."""

    def __init__(self, host: str = "0.0.0.0", port: int = 9053):
        self.host = host
        self.port = port
        self.dns_server: Optional["DNSServer"] = None
        self._started_at: float = time.monotonic()
        self._httpd:  Optional[HTTPServer] = None
        self._thread: Optional[Thread]     = None

    @property
    def uptime(self) -> float:
        return round(time.monotonic() - self._started_at, 1)

    def start(self, dns_server: "DNSServer") -> None:
        self.dns_server = dns_server
        # Inject self as a class attribute so every request handler can reach it.
        handler_cls = type("_BoundHandler", (_Handler,), {"mgmt": self})
        self._httpd  = HTTPServer((self.host, self.port), handler_cls)
        self._thread = Thread(
            target=self._httpd.serve_forever,
            name="nanodns-mgmt",
            daemon=True,
        )
        self._thread.start()
        logger.info("Management HTTP server on %s:%d", self.host, self.port)

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            logger.info("Management HTTP server stopped")

    # ── cluster status ────────────────────────────────────────────────────────

    def cluster_status(self) -> dict:
        """Return this node's status and probe all configured peers."""
        srv = self.dns_server
        if srv is None:
            self_info: dict = {"status": "unavailable"}
        else:
            cfg = srv.config
            self_info = {
                "status":   "ok" if srv._running else "unavailable",
                "version":  cfg.version,
                "checksum": cfg.checksum,
                "uptime_s": self.uptime,
                "records":  len(cfg.records),
                "peers_configured": cfg.server.peers,
            }

        peers: dict[str, dict] = {}
        if srv and srv.config:
            for peer in srv.config.server.peers:
                peers[peer] = _probe_peer_health(peer)

        return {"self": self_info, "peers": peers}

    # ── push ──────────────────────────────────────────────────────────────────

    def push_to_peers(self, config) -> dict[str, dict]:
        """POST config._raw to every peer's /sync endpoint.

        Non-fatal: failures are logged but never raised.
        Returns a mapping of peer → result dict for inclusion in /reload response.
        """
        results: dict[str, dict] = {}
        if not config._raw or not config.server.peers:
            return results
        for peer in config.server.peers:
            result = _push_sync(peer, config._raw)
            results[peer] = result
            status = result.get("status", "error")
            if status in ("applied", "already_current"):
                logger.info("Peer %s → %s  v%s",
                            peer, status, result.get("version", "?"))
            else:
                logger.warning("Peer %s push failed: %s", peer, result)
        return results

    # ── catch-up (pull) ───────────────────────────────────────────────────────

    def catchup_from_peers(self) -> Optional[dict]:
        """Query all peers; pull config from the one with the highest version.

        Called on startup and periodically from _reconcile_peers() in server.py.
        Returns the peer address we pulled from, or None if already up to date.
        """
        srv = self.dns_server
        if srv is None or not srv.config or not srv.config.server.peers:
            return None

        my_version = srv.config.version

        # Collect versions from all reachable peers.
        best_peer:    Optional[str] = None
        best_version: int = my_version

        for peer in srv.config.server.peers:
            info = _probe_peer_health(peer)
            if not info.get("reachable"):
                continue
            peer_version = info.get("version", 0)
            if peer_version > best_version:
                best_version = peer_version
                best_peer    = peer

        if best_peer is None:
            logger.debug("Catch-up check: already at latest version v%d", my_version)
            return None

        logger.info(
            "Catch-up: local v%d < peer %s v%d — pulling...",
            my_version, best_peer, best_version,
        )
        raw = _fetch_raw_config(best_peer)
        if raw is None:
            logger.error("Catch-up: failed to fetch raw config from %s", best_peer)
            return None

        from .config import load_config_from_bytes
        new_cfg = load_config_from_bytes(raw, srv.config._path)
        srv.apply_config(new_cfg)
        logger.info(
            "Catch-up applied: v%d  checksum=%s  (from %s)",
            new_cfg.version, new_cfg.checksum, best_peer,
        )
        # Cascade: push to other peers so they also catch up.
        self.push_to_peers(new_cfg)
        return {"peer": best_peer, "version": new_cfg.version}


# ── low-level peer I/O ────────────────────────────────────────────────────────

def _probe_peer_health(peer: str) -> dict:
    """GET /health on a peer; returns status dict with reachable flag."""
    try:
        with urllib.request.urlopen(
            f"http://{peer}/health", timeout=_PEER_TIMEOUT
        ) as resp:
            body = json.loads(resp.read())
            body["reachable"] = True
            return body
    except urllib.error.HTTPError as exc:
        return {"reachable": True, "http_error": exc.code}
    except Exception as exc:
        return {"reachable": False, "error": str(exc)}


def _push_sync(peer: str, raw: bytes) -> dict:
    """POST raw JSON bytes to POST /sync on a peer."""
    try:
        req = urllib.request.Request(
            f"http://{peer}/sync",
            data=raw,
            headers={"Content-Type": "application/json",
                     "Content-Length": str(len(raw))},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_PEER_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read())
        except Exception:
            return {"error": f"HTTP {exc.code}"}
    except Exception as exc:
        return {"error": str(exc)}


def _fetch_raw_config(peer: str) -> Optional[bytes]:
    """GET /config/raw from a peer; returns raw bytes or None on failure."""
    try:
        with urllib.request.urlopen(
            f"http://{peer}/config/raw", timeout=_PEER_TIMEOUT
        ) as resp:
            return resp.read()
    except Exception as exc:
        logger.debug("fetch_raw_config from %s failed: %s", peer, exc)
        return None
