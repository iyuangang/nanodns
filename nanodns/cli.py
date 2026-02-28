"""
NanoDNS CLI entry point.
"""

import argparse
import asyncio
import sys
import os

from . import __version__
from .config import load_config, generate_example_config
from .server import setup_logging, run_server


def main():
    parser = argparse.ArgumentParser(
        prog="nanodns",
        description="NanoDNS — A lightweight, JSON-configurable DNS server",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"nanodns {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- start ---
    start_parser = subparsers.add_parser("start", help="Start the DNS server")
    start_parser.add_argument(
        "--config", "-c",
        metavar="FILE",
        help="Path to JSON config file",
    )
    start_parser.add_argument(
        "--host",
        default=None,
        help="Override listen host (default from config or 0.0.0.0)",
    )
    start_parser.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        help="Override listen port (default from config or 53)",
    )
    start_parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Override log level",
    )
    start_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable DNS caching",
    )

    # --- init ---
    init_parser = subparsers.add_parser("init", help="Generate an example config file")
    init_parser.add_argument(
        "output",
        nargs="?",
        default="nanodns.json",
        help="Output path (default: nanodns.json)",
    )

    # --- check ---
    check_parser = subparsers.add_parser("check", help="Validate a config file")
    check_parser.add_argument(
        "config",
        metavar="FILE",
        help="Path to config file to validate",
    )

    args = parser.parse_args()

    if args.command == "init":
        generate_example_config(args.output)
        return

    if args.command == "check":
        try:
            config = load_config(args.config)
            print(f"✓ Config is valid.")
            print(f"  Records : {len(config.records)}")
            print(f"  Zones   : {len(config.zones)}")
            print(f"  Rewrites: {len(config.rewrites)}")
            print(f"  Upstream: {config.server.upstream}")
            print(f"  Listen  : {config.server.host}:{config.server.port}")
        except Exception as e:
            print(f"✗ Config error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "start":
        try:
            config = load_config(args.config)
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Config error: {e}", file=sys.stderr)
            sys.exit(1)

        # Apply CLI overrides
        if args.host:
            config.server.host = args.host
        if args.port:
            config.server.port = args.port
        if args.log_level:
            config.server.log_level = args.log_level
        if args.no_cache:
            config.server.cache_enabled = False

        setup_logging(config.server.log_level)

        # Warn if not root/admin and port < 1024
        if config.server.port < 1024:
            import logging
            _log = logging.getLogger(__name__)
            try:
                is_admin = os.geteuid() == 0  # Unix
            except AttributeError:
                try:
                    import ctypes
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except Exception:
                    is_admin = True  # can't determine, skip warning
            if not is_admin:
                _log.warning(
                    f"Port {config.server.port} may require administrator privileges. "
                    "Consider using port 5353 or run as Administrator (Windows) / sudo (Unix)."
                )

        try:
            asyncio.run(run_server(config))
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()