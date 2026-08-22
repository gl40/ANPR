"""Command line interface."""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from . import __version__
from .config import Config
from .filtering import Filtering, infer_request_type
from .filters.rules import REQUEST_TYPES, Request
from .net.http1 import Headers
from .net.proxy import Proxy


def _setup_logging(level: str, log_allowed: bool) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)-16s %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("ubproxy.access").setLevel(
        logging.DEBUG if log_allowed else logging.INFO
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ubproxy",
        description="Transparent HTTP(S) proxy filtering with uBlock Origin filter lists.",
    )
    parser.add_argument("--version", action="version", version=f"ubproxy {__version__}")
    parser.add_argument("-c", "--config", help="path to a TOML configuration file")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument(
        "-l", "--list", action="append", dest="extra_lists", metavar="URL|PATH",
        help="filter list to load (repeatable); replaces the configured ones",
    )
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="run the proxy (default)")
    run.add_argument("--http-port", type=int)
    run.add_argument("--tls-port", type=int)
    run.add_argument("--listen", dest="listen_address")
    run.add_argument("--mitm", action="store_true", help="decrypt HTTPS (needs the CA installed)")
    run.add_argument("--no-cosmetic", action="store_true", help="disable element hiding")
    run.add_argument("--log-allowed", action="store_true", help="log allowed requests too")

    check = sub.add_parser("check", help="show the verdict for a URL")
    check.add_argument("url")
    check.add_argument("--type", dest="request_type", choices=sorted(REQUEST_TYPES))
    check.add_argument("--doc", dest="document", default="", help="hostname of the page")
    check.add_argument("--third-party", action="store_true")

    cosmetics = sub.add_parser("cosmetics", help="list the hidden selectors for a hostname")
    cosmetics.add_argument("hostname")
    cosmetics.add_argument("--generic", action="store_true", help="include generic rules")

    sub.add_parser("update-lists", help="refresh the cached filter lists")
    sub.add_parser("gen-ca", help="create the MITM certificate authority")
    sub.add_parser("stats", help="parse the lists and report what was loaded")
    return parser


def _config_from_args(args: argparse.Namespace) -> Config:
    config = Config.load(args.config)
    if args.extra_lists:
        config.lists = list(args.extra_lists)
    for attribute in ("http_port", "tls_port", "listen_address"):
        value = getattr(args, attribute, None)
        if value:
            setattr(config, attribute, value)
    if getattr(args, "mitm", False):
        config.mitm = True
    if getattr(args, "no_cosmetic", False):
        config.cosmetic_filtering = False
    if getattr(args, "log_allowed", False):
        config.log_allowed = True
    if args.verbose:
        config.log_level = "debug"
    return config


async def _run(config: Config) -> int:
    filtering = Filtering(config)
    filtering.load_lists()
    proxy = Proxy(config, filtering)
    await proxy.start()

    loop = asyncio.get_running_loop()
    stop = loop.create_future()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: stop.done() or stop.set_result(None))
        except NotImplementedError:  # pragma: no cover - non-POSIX
            pass
    if config.stats_interval:
        asyncio.create_task(proxy._stats_loop())
    await stop
    logging.getLogger("ubproxy").info("shutting down: %s", proxy.stats.render())
    await proxy.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = _config_from_args(args)
    _setup_logging(config.log_level, config.log_allowed)
    command = args.command or "run"

    if command == "gen-ca":
        from .net.mitm import generate_ca

        cert, key = Path(config.ca_cert), Path(config.ca_key)
        if cert.exists() and key.exists():
            print(f"CA already present: {cert}")
        else:
            generate_ca(cert, key)
            print(f"CA created: {cert}")
        print("Install this certificate as a trusted root on the client devices.")
        return 0

    filtering = Filtering(config)

    if command == "update-lists":
        filtering.load_lists(force_refresh=True)
        print(filtering.engine.summary())
        return 0

    if command == "stats":
        filtering.load_lists()
        stats = filtering.engine.stats
        print(filtering.engine.summary())
        print(f"  network rules : {stats.network}")
        print(f"  cosmetic rules: {stats.cosmetic}")
        print(f"  comments      : {stats.comments}")
        print(f"  unsupported   : {stats.unsupported}")
        for sample in stats.unsupported_samples[:10]:
            print(f"    ~ {sample[:100]}")
        return 0

    if command == "check":
        filtering.load_lists()
        headers = Headers()
        if args.document:
            headers.set("Referer", f"https://{args.document}/")
        request_type = args.request_type or infer_request_type("GET", args.url, headers)
        from urllib.parse import urlsplit

        hostname = (urlsplit(args.url).hostname or "").lower()
        document = args.document or ("" if not args.third_party else "example-page.invalid")
        request = Request(
            args.url,
            request_type,
            document,
            "GET",
            hostname=hostname,
            third_party=True if args.third_party else None,
        )
        decision = filtering.engine.match(request)
        verdict = "BLOCKED" if decision.blocked else "allowed"
        print(f"{verdict}  type={request_type}  third-party={request.third_party}")
        print(f"rule: {decision.reason}")
        return 1 if decision.blocked else 0

    if command == "cosmetics":
        filtering.load_lists()
        selectors = filtering.engine.cosmetic_selectors(args.hostname, include_generic=args.generic)
        for selector in selectors:
            print(selector)
        print(f"# {len(selectors)} selectors for {args.hostname}", file=sys.stderr)
        return 0

    try:
        return asyncio.run(_run(config))
    except KeyboardInterrupt:  # pragma: no cover
        return 130
