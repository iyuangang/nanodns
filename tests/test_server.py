"""
Unit tests for nanodns.server and nanodns.cli
Covers: DNSServerProtocol (including apply_config regression),
        DNSServer (sync and async), setup_logging, run_server,
        CLI init / check / start.
"""

import asyncio
import io
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nanodns.config import _parse_config, load_config
from nanodns.cache import DNSCache
from nanodns.handler import DNSHandler
from nanodns.protocol import (
    DNSMessage, DNSQuestion,
    QType, QClass,
    encode_a, parse_message, build_message,
)
from nanodns.server import DNSServerProtocol, DNSServer, setup_logging, run_server
from nanodns.cli import main


# ═══════════════════════════════════════════════════════════════════════════════
# Shared helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _sdict(**kw):
    """Minimal server config dict."""
    d = {
        "host": "127.0.0.1", "port": 0,
        "upstream": [], "upstream_port": 53, "upstream_timeout": 2,
        "cache_enabled": True, "cache_ttl": 60, "cache_size": 50,
        "log_level": "WARNING", "log_queries": False, "hot_reload": False,
    }
    d.update(kw)
    return d


def _cfg(**kw):
    return _parse_config(
        {"server": _sdict(**kw), "zones": {}, "records": [], "rewrites": []},
        None,
    )


def _cfg_ip(ip: str, name: str = "ping.t.lan"):
    """Config with a single A record pointing to *ip*."""
    return _parse_config({
        "server": _sdict(),
        "zones": {"t.lan": {}},
        "records": [{"name": name, "type": "A", "value": ip, "ttl": 60}],
        "rewrites": [],
    }, None)


def _write_cfg(path, **kw) -> str:
    data = {"server": _sdict(**kw), "zones": {}, "records": [], "rewrites": []}
    Path(path).write_text(json.dumps(data))
    return str(path)


def _query(name: str = "ping.t.lan") -> bytes:
    msg = DNSMessage(msg_id=1, flags=0x0100)
    msg.questions.append(DNSQuestion(name, QType.A, QClass.IN))
    return build_message(msg)


def _run_cli(args):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with patch("sys.argv", ["nanodns"] + args), \
         patch("sys.stdout", out), \
         patch("sys.stderr", err):
        try:
            main()
        except SystemExit as e:
            code = int(e.code) if e.code is not None else 0
    return code, out.getvalue(), err.getvalue()


# ═══════════════════════════════════════════════════════════════════════════════
# DNSServerProtocol
# ═══════════════════════════════════════════════════════════════════════════════

class TestDNSServerProtocol:
    """
    Protocol holds a DNSServer reference (not a bare DNSHandler) so that
    apply_config() handler swaps are immediately visible to in-flight queries.

    Root cause of the stale-record bug:
        Old: DNSServerProtocol(handler)  — handler reference frozen at start-up.
             apply_config() replaces DNSServer.handler; protocol never sees it.
        Fix: DNSServerProtocol(server)   — self.server.handler re-read per packet.
    """

    def _server(self, ip: str = "1.2.3.4") -> DNSServer:
        return DNSServer(_cfg_ip(ip))

    # ── structure ─────────────────────────────────────────────────────────────

    def test_holds_server_not_handler(self):
        """Protocol must store a DNSServer, never a bare DNSHandler.

        If this assertion fails the apply_config() fix has been reverted and
        stale-record queries will reappear in production.
        """
        server = self._server()
        proto  = DNSServerProtocol(server)
        assert hasattr(proto, "server"), "proto must expose .server"
        assert isinstance(proto.server, DNSServer)
        assert not hasattr(proto, "handler") or proto.handler is None, (
            "proto must NOT cache handler directly"
        )

    def test_connection_made_sets_transport(self):
        proto = DNSServerProtocol(self._server())
        t = MagicMock()
        proto.connection_made(t)
        assert proto.transport is t

    # ── normal dispatch ───────────────────────────────────────────────────────

    def test_datagram_sends_response(self):
        proto = DNSServerProtocol(self._server())
        proto.transport = MagicMock()
        proto.datagram_received(_query(), ("127.0.0.1", 9000))
        proto.transport.sendto.assert_called_once()
        data, addr = proto.transport.sendto.call_args[0]
        assert len(data) > 0 and addr == ("127.0.0.1", 9000)

    def test_empty_response_not_sent(self):
        proto = DNSServerProtocol(self._server())
        proto.transport = MagicMock()
        proto.datagram_received(b"\x00\x01", ("127.0.0.1", 9000))  # too short → b""
        proto.transport.sendto.assert_not_called()

    def test_handler_exception_swallowed(self):
        """Exception inside handler.handle() must be caught, not propagated."""
        server = self._server()
        server.handler = MagicMock()
        server.handler.handle.side_effect = RuntimeError("crash")
        proto = DNSServerProtocol(server)
        proto.transport = MagicMock()
        proto.datagram_received(b"\x00" * 20, ("127.0.0.1", 9000))
        proto.transport.sendto.assert_not_called()

    def test_error_received_no_raise(self):
        DNSServerProtocol(self._server()).error_received(OSError("net err"))

    # ── apply_config regression ───────────────────────────────────────────────

    def test_serves_new_records_after_apply_config(self):
        """After apply_config() the protocol must answer with the NEW records.

        Scenario that was broken:
          1. Server starts:  ping.t.lan → 1.1.1.1
          2. apply_config(): ping.t.lan → 2.2.2.2
          3. Query arrives.
          Expected: 2.2.2.2   |   Bug: still 1.1.1.1 (stale handler reference)
        """
        server = DNSServer(_cfg_ip("1.1.1.1"))
        proto  = DNSServerProtocol(server)
        proto.transport = MagicMock()

        def do_query():
            proto.transport.reset_mock()
            proto.datagram_received(_query(), ("127.0.0.1", 9000))
            return parse_message(proto.transport.sendto.call_args[0][0])

        assert do_query().answers[0].rdata == encode_a("1.1.1.1"), "pre-condition"

        server.apply_config(_cfg_ip("2.2.2.2"))

        assert do_query().answers[0].rdata == encode_a("2.2.2.2"), (
            "REGRESSION: protocol served stale record after apply_config()"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# DNSServer — synchronous methods
# ═══════════════════════════════════════════════════════════════════════════════

class TestDNSServerSync:

    def test_init(self):
        s = DNSServer(_cfg())
        assert isinstance(s.cache, DNSCache)
        assert isinstance(s.handler, DNSHandler)
        assert s._running is False

    def test_cache_stats(self):
        assert "size" in DNSServer(_cfg()).cache_stats()

    def test_reload_bad_path_no_raise(self):
        DNSServer(_cfg()).reload_config("/no/such/file.json")

    def test_reload_replaces_handler(self, tmp_path):
        p = _write_cfg(tmp_path / "c.json", hot_reload=True)
        cfg = _parse_config(json.loads(Path(p).read_text()), Path(p))
        s = DNSServer(cfg)
        old = s.handler
        s.reload_config(p)
        assert s.handler is not old

    def test_reload_clears_cache(self, tmp_path):
        p = _write_cfg(tmp_path / "c.json", hot_reload=True)
        cfg = _parse_config(json.loads(Path(p).read_text()), Path(p))
        s = DNSServer(cfg)
        s.cache.set("x", QType.A, QClass.IN, DNSMessage(1, 0x8180), ttl=60)
        s.reload_config(p)
        assert s.cache.stats["size"] == 0

    def test_apply_config_swaps_handler_and_clears_cache(self):
        s = DNSServer(_cfg())
        s.cache.set("x", QType.A, QClass.IN, DNSMessage(1, 0x8180), ttl=60)
        old_handler = s.handler
        s.apply_config(_cfg())
        assert s.handler is not old_handler
        assert s.cache.stats["size"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# DNSServer — async tasks
# ═══════════════════════════════════════════════════════════════════════════════

class TestDNSServerAsync:

    def test_start_then_cancel(self):
        async def run():
            s = DNSServer(_cfg(port=0))
            t = asyncio.create_task(s.start())
            await asyncio.sleep(0.05)
            assert s._running is True
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
            assert s._running is False
        asyncio.run(run())

    def test_watch_config_reloads_when_stale(self, tmp_path):
        p = _write_cfg(tmp_path / "c.json", hot_reload=True)
        cfg = load_config(p)
        reloaded = []

        async def run():
            s = DNSServer(cfg)
            s._running = True
            s.config.server.hot_reload = True
            s.config._mtime = 0.0

            def fake_reload(path=None):
                reloaded.append(1)
                s._running = False

            s.reload_config = fake_reload
            call_count = [0]
            _real_sleep = asyncio.sleep   # capture before patch replaces it

            async def fast_sleep(delay):
                call_count[0] += 1
                if call_count[0] > 100:
                    s._running = False
                await _real_sleep(0)      # use the real coroutine, not the mock

            with patch("nanodns.server.asyncio.sleep", side_effect=fast_sleep):
                await s._watch_config()

        asyncio.run(run())
        assert len(reloaded) >= 1

    def test_watch_config_no_reload_when_fresh(self, tmp_path):
        p = _write_cfg(tmp_path / "c.json", hot_reload=False)
        cfg = load_config(p)
        reloaded = []

        async def run():
            s = DNSServer(cfg)
            s._running = True
            s.config.server.hot_reload = False
            s.reload_config = lambda path=None: reloaded.append(1)
            _real_sleep = asyncio.sleep

            async def fast_sleep(delay):
                s._running = False
                await _real_sleep(0)

            with patch("nanodns.server.asyncio.sleep", side_effect=fast_sleep):
                await s._watch_config()

        asyncio.run(run())
        assert len(reloaded) == 0

    def test_prune_cache_called(self):
        prune_calls = [0]

        async def run():
            s = DNSServer(_cfg())
            s._running = True
            orig = s.cache.prune

            def counting_prune():
                prune_calls[0] += 1
                orig()

            s.cache.prune = counting_prune
            _real_sleep = asyncio.sleep

            async def fast_sleep(delay):
                s._running = False
                await _real_sleep(0)

            with patch("nanodns.server.asyncio.sleep", side_effect=fast_sleep):
                await s._prune_cache()

        asyncio.run(run())
        assert prune_calls[0] == 1


# ═══════════════════════════════════════════════════════════════════════════════
# setup_logging
# ═══════════════════════════════════════════════════════════════════════════════

class TestSetupLogging:
    def test_info(self):    setup_logging("INFO")
    def test_debug(self):   setup_logging("DEBUG")
    def test_warning(self): setup_logging("WARNING")
    def test_error(self):   setup_logging("ERROR")
    def test_invalid(self): setup_logging("NOTREAL")   # getattr fallback → INFO


# ═══════════════════════════════════════════════════════════════════════════════
# run_server
# ═══════════════════════════════════════════════════════════════════════════════

class TestRunServer:

    def test_cancel_cleanly(self):
        async def run():
            t = asyncio.create_task(run_server(_cfg(port=0)))
            await asyncio.sleep(0.05)
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
        asyncio.run(run())

    def test_windows_signal_not_implemented(self):
        """add_signal_handler raising NotImplementedError must be silently ignored."""
        async def run():
            cfg = _cfg(port=0)
            real_loop = asyncio.get_event_loop()
            mock_loop = MagicMock(wraps=real_loop)
            mock_loop.add_signal_handler.side_effect = NotImplementedError
            mock_loop.create_datagram_endpoint = real_loop.create_datagram_endpoint

            with patch("nanodns.server.asyncio.get_running_loop",
                       return_value=mock_loop):
                outer = asyncio.create_task(run_server(cfg))
                await asyncio.sleep(0.05)
                outer.cancel()
                try:
                    await outer
                except (asyncio.CancelledError, Exception):
                    pass

        asyncio.run(run())


# ═══════════════════════════════════════════════════════════════════════════════
# CLI — init
# ═══════════════════════════════════════════════════════════════════════════════

class TestCLIInit:

    def test_default_path(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        code, _, _ = _run_cli(["init"])
        assert code == 0
        assert (tmp_path / "nanodns.json").exists()

    def test_custom_path(self, tmp_path):
        out = str(tmp_path / "out.json")
        code, _, _ = _run_cli(["init", out])
        assert code == 0
        assert "server" in json.loads(Path(out).read_text())


# ═══════════════════════════════════════════════════════════════════════════════
# CLI — check
# ═══════════════════════════════════════════════════════════════════════════════

class TestCLICheck:

    def _valid(self, tmp_path):
        return _write_cfg(tmp_path / "v.json",
                          port=5353, upstream=["8.8.8.8"], log_level="INFO")

    def test_valid_exit_0(self, tmp_path):
        assert _run_cli(["check", self._valid(tmp_path)])[0] == 0

    def test_valid_shows_summary(self, tmp_path):
        _, out, _ = _run_cli(["check", self._valid(tmp_path)])
        assert any(k in out for k in ("valid", "OK", "Records", "Upstream"))

    def test_missing_file_exit_1(self, tmp_path):
        code, _, err = _run_cli(["check", str(tmp_path / "no.json")])
        assert code == 1 and len(err) > 0

    def test_bad_json_exit_1(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{bad json}")
        code, _, err = _run_cli(["check", str(p)])
        assert code == 1 and len(err) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# CLI — start
# ═══════════════════════════════════════════════════════════════════════════════

class TestCLIStart:

    def _p(self, tmp_path, port=5353, **kw):
        return _write_cfg(tmp_path / "cfg.json",
                          port=port, log_level="INFO", **kw)

    # ── error paths ───────────────────────────────────────────────────────────

    def test_missing_config_exit_1(self, tmp_path):
        code, _, err = _run_cli(["start", "--config", str(tmp_path / "no.json")])
        assert code == 1 and len(err) > 0

    def test_bad_json_exit_1(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{bad}")
        assert _run_cli(["start", "--config", str(p)])[0] == 1

    # ── CLI overrides ─────────────────────────────────────────────────────────

    def test_host_override(self, tmp_path):
        cap = {}
        async def fake(cfg): cap["host"] = cfg.server.host
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"):
            _run_cli(["start", "--config", self._p(tmp_path), "--host", "10.0.0.1"])
        assert cap.get("host") == "10.0.0.1"

    def test_port_override(self, tmp_path):
        cap = {}
        async def fake(cfg): cap["port"] = cfg.server.port
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"):
            _run_cli(["start", "--config", self._p(tmp_path), "--port", "5353"])
        assert cap.get("port") == 5353

    def test_loglevel_override(self, tmp_path):
        cap = {}
        async def fake(cfg): cap["level"] = cfg.server.log_level
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"):
            _run_cli(["start", "--config", self._p(tmp_path), "--log-level", "DEBUG"])
        assert cap.get("level") == "DEBUG"

    def test_no_cache_flag(self, tmp_path):
        cap = {}
        async def fake(cfg): cap["cache"] = cfg.server.cache_enabled
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"):
            _run_cli(["start", "--config", self._p(tmp_path), "--no-cache"])
        assert cap.get("cache") is False

    def test_no_overrides_uses_config_values(self, tmp_path):
        cap = {}
        async def fake(cfg):
            cap["host"]  = cfg.server.host
            cap["cache"] = cfg.server.cache_enabled
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"):
            _run_cli(["start", "--config", self._p(tmp_path)])
        assert cap.get("host") == "127.0.0.1"
        assert cap.get("cache") is True

    def test_keyboard_interrupt_exit_0(self, tmp_path):
        async def fake(cfg): raise KeyboardInterrupt
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"):
            code, _, _ = _run_cli(["start", "--config", self._p(tmp_path)])
        assert code == 0

    def test_setup_logging_called(self, tmp_path):
        calls = []
        async def fake(cfg): pass
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging", side_effect=calls.append):
            _run_cli(["start", "--config", self._p(tmp_path)])
        assert len(calls) == 1

    # ── privilege-check branches ──────────────────────────────────────────────

    def test_low_port_unix_nonroot(self, tmp_path):
        import nanodns.cli as _cli_mod
        async def fake(cfg): pass
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"), \
             patch.object(_cli_mod.os, "geteuid", return_value=1000, create=True):
            code, _, _ = _run_cli(["start", "--config", self._p(tmp_path, port=53)])
        assert code == 0

    def test_low_port_unix_root(self, tmp_path):
        import nanodns.cli as _cli_mod
        async def fake(cfg): pass
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"), \
             patch.object(_cli_mod.os, "geteuid", return_value=0, create=True):
            code, _, _ = _run_cli(["start", "--config", self._p(tmp_path, port=53)])
        assert code == 0

    def test_low_port_windows_fallback(self, tmp_path):
        import nanodns.cli as _cli_mod
        async def fake(cfg): pass
        mock_ctypes = MagicMock(spec=[])
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"), \
             patch.object(_cli_mod.os, "geteuid",
                          side_effect=AttributeError, create=True), \
             patch.dict("sys.modules", {"ctypes": mock_ctypes}):
            code, _, _ = _run_cli(["start", "--config", self._p(tmp_path, port=53)])
        assert code == 0

    def test_high_port_skips_privilege_check(self, tmp_path):
        async def fake(cfg): pass
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"):
            code, _, _ = _run_cli(["start", "--config", self._p(tmp_path, port=5353)])
        assert code == 0
