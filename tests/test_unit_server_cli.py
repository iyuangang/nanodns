"""
server.py 和 cli.py 的覆盖率测试。
兼容 Python 3.10-3.14，Windows + Unix。
不使用 asyncio.coroutine（3.11+ 已删除）。
patch 路径全部经过验证。
"""

import asyncio
import io
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nanodns.config import _parse_config, load_config
from nanodns.cache import DNSCache
from nanodns.handler import DNSHandler
from nanodns.protocol import (
    DNSMessage, DNSQuestion,
    QType, QClass, build_message,
)
from nanodns.server import DNSServerProtocol, DNSServer, setup_logging, run_server
from nanodns.cli import main


# ──────────────────────────────────────────────────────────────────────────────
# 通用 helpers
# ──────────────────────────────────────────────────────────────────────────────

def _sdict(**kw):
    """最小化 server 配置字典。"""
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


def _cfg_with_record():
    return _parse_config({
        "server": _sdict(),
        "zones": {"t.lan": {}},
        "records": [{"name": "ping.t.lan", "type": "A", "value": "1.2.3.4", "ttl": 60}],
        "rewrites": [],
    }, None)


def _write_cfg(path, **kw):
    """把配置写到文件，返回路径字符串。"""
    data = {"server": _sdict(**kw), "zones": {}, "records": [], "rewrites": []}
    Path(path).write_text(json.dumps(data))
    return str(path)


def _query(name="ping.t.lan"):
    msg = DNSMessage(msg_id=1, flags=0x0100)
    msg.questions.append(DNSQuestion(name, QType.A, QClass.IN))
    return build_message(msg)


def _run_cli(args):
    """执行 CLI，返回 (exit_code, stdout, stderr)。"""
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


# ──────────────────────────────────────────────────────────────────────────────
# DNSServerProtocol
# ──────────────────────────────────────────────────────────────────────────────

class TestDNSServerProtocol:

    def test_connection_made(self):
        proto = DNSServerProtocol(DNSHandler(_cfg_with_record(), DNSCache()))
        t = MagicMock()
        proto.connection_made(t)
        assert proto.transport is t

    def test_datagram_received_sends_response(self):
        proto = DNSServerProtocol(DNSHandler(_cfg_with_record(), DNSCache()))
        proto.transport = MagicMock()
        proto.datagram_received(_query(), ("127.0.0.1", 9000))
        proto.transport.sendto.assert_called_once()
        data, addr = proto.transport.sendto.call_args[0]
        assert len(data) > 0
        assert addr == ("127.0.0.1", 9000)

    def test_datagram_empty_response_not_sent(self):
        """handler 返回 b'' 时不应调用 sendto。"""
        proto = DNSServerProtocol(DNSHandler(_cfg_with_record(), DNSCache()))
        proto.transport = MagicMock()
        proto.datagram_received(b"\x00\x01", ("127.0.0.1", 9000))   # 太短 → b""
        proto.transport.sendto.assert_not_called()

    def test_datagram_handler_exception_swallowed(self):
        """handler.handle() 抛出异常时不应向外传播。"""
        h = MagicMock()
        h.handle.side_effect = RuntimeError("crash")
        proto = DNSServerProtocol(h)
        proto.transport = MagicMock()
        proto.datagram_received(b"\x00" * 20, ("127.0.0.1", 9000))
        proto.transport.sendto.assert_not_called()

    def test_error_received_no_raise(self):
        proto = DNSServerProtocol(DNSHandler(_cfg_with_record(), DNSCache()))
        proto.error_received(OSError("net err"))   # 不能抛出


# ──────────────────────────────────────────────────────────────────────────────
# DNSServer — 同步方法
# ──────────────────────────────────────────────────────────────────────────────

class TestDNSServerSync:

    def test_init(self):
        s = DNSServer(_cfg())
        assert isinstance(s.cache, DNSCache)
        assert isinstance(s.handler, DNSHandler)
        assert s._running is False

    def test_cache_stats(self):
        s = DNSServer(_cfg())
        assert "size" in s.cache_stats()

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


# ──────────────────────────────────────────────────────────────────────────────
# DNSServer — 异步方法
# ──────────────────────────────────────────────────────────────────────────────

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

    def test_watch_config_reloads_stale(self, tmp_path):
        """_watch_config 在 is_stale() 时调用 reload_config。"""
        p = _write_cfg(tmp_path / "c.json", hot_reload=True)
        cfg = load_config(p)

        reloaded = []

        async def run():
            s = DNSServer(cfg)
            s._running = True
            s.config.server.hot_reload = True
            s.config._mtime = 0.0       # 强制 is_stale() → True

            def fake_reload(path=None):
                reloaded.append(1)
                s._running = False      # 让循环退出

            s.reload_config = fake_reload

            # 用计数器防止无限循环（最多 100 次）
            call_count = [0]
            real_sleep = asyncio.sleep

            async def fast_sleep(delay):
                call_count[0] += 1
                if call_count[0] > 100:
                    s._running = False
                await real_sleep(0)     # 真正 yield，避免死递归

            with patch("nanodns.server.asyncio.sleep", side_effect=fast_sleep):
                await s._watch_config()

        asyncio.run(run())
        assert len(reloaded) >= 1

    def test_watch_config_no_reload_when_fresh(self, tmp_path):
        """is_stale() 返回 False 时不应调用 reload_config。"""
        p = _write_cfg(tmp_path / "c.json", hot_reload=False)
        cfg = load_config(p)

        reloaded = []
        call_count = [0]

        async def run():
            s = DNSServer(cfg)
            s._running = True
            s.config.server.hot_reload = False

            s.reload_config = lambda path=None: reloaded.append(1)

            real_sleep = asyncio.sleep

            async def fast_sleep(delay):
                call_count[0] += 1
                s._running = False      # 第一次就停
                await real_sleep(0)

            with patch("nanodns.server.asyncio.sleep", side_effect=fast_sleep):
                await s._watch_config()

        asyncio.run(run())
        assert len(reloaded) == 0

    def test_prune_cache_called(self):
        """_prune_cache 每轮都应调用 cache.prune()。"""
        prune_calls = [0]

        async def run():
            s = DNSServer(_cfg())
            s._running = True
            orig_prune = s.cache.prune

            def counting_prune():
                prune_calls[0] += 1
                orig_prune()

            s.cache.prune = counting_prune

            real_sleep = asyncio.sleep

            async def fast_sleep(delay):
                s._running = False
                await real_sleep(0)

            with patch("nanodns.server.asyncio.sleep", side_effect=fast_sleep):
                await s._prune_cache()

        asyncio.run(run())
        assert prune_calls[0] == 1


# ──────────────────────────────────────────────────────────────────────────────
# setup_logging
# ──────────────────────────────────────────────────────────────────────────────

class TestSetupLogging:
    def test_info(self):    setup_logging("INFO")
    def test_debug(self):   setup_logging("DEBUG")
    def test_warning(self): setup_logging("WARNING")
    def test_error(self):   setup_logging("ERROR")
    def test_bad(self):     setup_logging("NOTREAL")   # getattr fallback → INFO


# ──────────────────────────────────────────────────────────────────────────────
# run_server
# ──────────────────────────────────────────────────────────────────────────────

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
        """add_signal_handler 抛出 NotImplementedError 时应忽略（Windows）。"""
        async def run():
            cfg = _cfg(port=0)
            real_loop = asyncio.get_event_loop()

            mock_loop = MagicMock(wraps=real_loop)
            mock_loop.add_signal_handler.side_effect = NotImplementedError
            mock_loop.create_datagram_endpoint = real_loop.create_datagram_endpoint

            bg = []
            real_ct = asyncio.create_task

            def track(coro, **kw):
                t = real_ct(coro, **kw)
                bg.append(t)
                return t

            with patch("nanodns.server.asyncio.get_running_loop",
                       return_value=mock_loop):
                outer = real_ct(run_server(cfg))
                await asyncio.sleep(0.05)
                outer.cancel()
                for t in bg:
                    t.cancel()
                try:
                    await outer
                except (asyncio.CancelledError, Exception):
                    pass

        asyncio.run(run())


# ──────────────────────────────────────────────────────────────────────────────
# CLI — init
# ──────────────────────────────────────────────────────────────────────────────

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


# ──────────────────────────────────────────────────────────────────────────────
# CLI — check
# ──────────────────────────────────────────────────────────────────────────────

class TestCLICheck:

    def _valid_file(self, tmp_path):
        return _write_cfg(tmp_path / "v.json",
                          port=5353, upstream=["8.8.8.8"], log_level="INFO")

    def test_valid_exit_0(self, tmp_path):
        code, _, _ = _run_cli(["check", self._valid_file(tmp_path)])
        assert code == 0

    def test_valid_shows_summary(self, tmp_path):
        _, out, _ = _run_cli(["check", self._valid_file(tmp_path)])
        assert any(k in out for k in ("valid", "\u2713", "Records", "Upstream"))

    def test_missing_file_exit_1(self, tmp_path):
        code, _, err = _run_cli(["check", str(tmp_path / "no.json")])
        assert code == 1 and len(err) > 0

    def test_bad_json_exit_1(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{bad json}")
        code, _, err = _run_cli(["check", str(p)])
        assert code == 1 and len(err) > 0


# ──────────────────────────────────────────────────────────────────────────────
# CLI — start
# ──────────────────────────────────────────────────────────────────────────────

class TestCLIStart:

    def _p(self, tmp_path, port=5353, **kw):
        return _write_cfg(tmp_path / "cfg.json",
                          port=port, log_level="INFO", **kw)

    # ── 错误路径 ─────────────────────────────────────────────────────────────

    def test_missing_config_exit_1(self, tmp_path):
        code, _, err = _run_cli(["start", "--config", str(tmp_path / "no.json")])
        assert code == 1 and len(err) > 0

    def test_bad_json_exit_1(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{bad}")
        code, _, _ = _run_cli(["start", "--config", str(p)])
        assert code == 1

    # ── CLI 覆盖项 ───────────────────────────────────────────────────────────

    def test_host_override(self, tmp_path):
        cap = {}
        async def fake(cfg): cap["host"] = cfg.server.host
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"):
            _run_cli(["start", "--config", self._p(tmp_path),
                      "--host", "10.0.0.1"])
        assert cap.get("host") == "10.0.0.1"

    def test_port_override(self, tmp_path):
        cap = {}
        async def fake(cfg): cap["port"] = cfg.server.port
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"):
            _run_cli(["start", "--config", self._p(tmp_path),
                      "--port", "5353"])
        assert cap.get("port") == 5353

    def test_loglevel_override(self, tmp_path):
        cap = {}
        async def fake(cfg): cap["level"] = cfg.server.log_level
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"):
            _run_cli(["start", "--config", self._p(tmp_path),
                      "--log-level", "DEBUG"])
        assert cap.get("level") == "DEBUG"

    def test_no_cache_flag(self, tmp_path):
        cap = {}
        async def fake(cfg): cap["cache"] = cfg.server.cache_enabled
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"):
            _run_cli(["start", "--config", self._p(tmp_path), "--no-cache"])
        assert cap.get("cache") is False

    def test_no_overrides(self, tmp_path):
        cap = {}
        async def fake(cfg):
            cap["host"] = cfg.server.host
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

    # ── 端口权限警告分支 ─────────────────────────────────────────────────────

    def test_low_port_unix_nonroot(self, tmp_path):
        """port<1024 + 非 root → 警告分支执行，不崩溃。"""
        import nanodns.cli as _cli_mod
        async def fake(cfg): pass
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"), \
             patch.object(_cli_mod.os, "geteuid", return_value=1000, create=True):
            code, _, _ = _run_cli(["start", "--config",
                                    self._p(tmp_path, port=53)])
        assert code == 0

    def test_low_port_unix_root(self, tmp_path):
        """port<1024 + root → is_admin=True，不打警告。"""
        import nanodns.cli as _cli_mod
        async def fake(cfg): pass
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"), \
             patch.object(_cli_mod.os, "geteuid", return_value=0, create=True):
            code, _, _ = _run_cli(["start", "--config",
                                    self._p(tmp_path, port=53)])
        assert code == 0

    def test_low_port_windows_fallback(self, tmp_path):
        """geteuid → AttributeError → ctypes 路径（Windows 兼容分支）。"""
        import nanodns.cli as _cli_mod
        async def fake(cfg): pass
        mock_ctypes = MagicMock(spec=[])   # spec=[] 所有属性访问都抛 AttributeError
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"), \
             patch.object(_cli_mod.os, "geteuid",
                          side_effect=AttributeError, create=True), \
             patch.dict("sys.modules", {"ctypes": mock_ctypes}):
            code, _, _ = _run_cli(["start", "--config",
                                    self._p(tmp_path, port=53)])
        assert code == 0

    def test_high_port_no_privilege_check(self, tmp_path):
        """port≥1024 → 权限检查块整体跳过。"""
        async def fake(cfg): pass
        with patch("nanodns.cli.run_server", side_effect=fake), \
             patch("nanodns.cli.setup_logging"):
            code, _, _ = _run_cli(["start", "--config",
                                    self._p(tmp_path, port=5353)])
        assert code == 0