#!/usr/bin/env python3
"""A lightweight MITM proxy to inspect PAD REST calls.

This tool spins up a local HTTP/HTTPS proxy (powered by mitmproxy) and logs
all GET/POST requests/responses into a JSONL file so you can diff executions
between PowerShell and Power Automate Desktop.
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional

try:
    from mitmproxy import http, options
    from mitmproxy.tools.dump import DumpMaster
except ModuleNotFoundError as exc:  # pragma: no cover - helps users without deps
    print(
        "mitmproxy is required. Install it with `pip install mitmproxy`.\n"
        "Original error: %s" % exc,
        file=sys.stderr,
    )
    raise


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Intercept HTTP/HTTPS traffic (GET/POST) so you can compare what PAD "
            "and PowerShell send"
        )
    )
    parser.add_argument(
        "--listen-host",
        default="127.0.0.1",
        help="Host/IP for the proxy to bind (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=8899,
        help="Port for the proxy to bind (default: 8899)",
    )
    parser.add_argument(
        "--log-file",
        default="pad_http_log.jsonl",
        help="Path to the JSON lines log file (default: pad_http_log.jsonl)",
    )
    parser.add_argument(
        "--methods",
        nargs="+",
        default=["GET", "POST"],
        help="HTTP methods to capture (default: GET POST)",
    )
    parser.add_argument(
        "--body-bytes",
        type=int,
        default=32_768,
        help="Maximum amount of body bytes to store per flow (default: 32768)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Also print each captured request to stdout",
    )
    return parser.parse_args(argv)


class PadRestLogger:
    """mitmproxy add-on that persists flows to JSONL."""

    def __init__(self, log_path: Path, methods: Iterable[str], body_limit: int, verbose: bool) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.methods = {m.upper() for m in methods}
        self.body_limit = max(0, body_limit)
        self.verbose = verbose
        self._fh = self.log_path.open("a", encoding="utf-8")

    # mitmproxy hook
    def response(self, flow: http.HTTPFlow) -> None:  # pragma: no cover - requires mitmproxy runtime
        method = flow.request.method.upper()
        if self.methods and method not in self.methods:
            return

        entry = {
            "captured_at": datetime.now(tz=timezone.utc).isoformat(),
            "method": method,
            "url": flow.request.pretty_url,
            "request_headers": dict(flow.request.headers),
            "request_body": self._truncate(flow.request.get_text(strict=False)),
            "status_code": flow.response.status_code if flow.response else None,
            "response_headers": dict(flow.response.headers) if flow.response else None,
            "response_body": self._truncate(flow.response.get_text(strict=False))
            if flow.response
            else None,
        }

        json.dump(entry, self._fh)
        self._fh.write("\n")
        self._fh.flush()

        if self.verbose:
            logging.info("%s %s -> %s", method, flow.request.pretty_url, entry["status_code"])

    def done(self):  # pragma: no cover - invoked by mitmproxy
        self._fh.close()

    def _truncate(self, payload: Optional[str]) -> Optional[str]:
        if payload is None:
            return None
        if self.body_limit == 0:
            return ""
        if len(payload) <= self.body_limit:
            return payload
        return payload[: self.body_limit] + "... <truncated>"


def run_proxy(args: argparse.Namespace) -> None:
    opts = options.Options(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        mode="regular",
        http2=True,
    )
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    addon = PadRestLogger(Path(args.log_file), args.methods, args.body_bytes, args.verbose)
    master.addons.add(addon)

    def _shutdown(*_sig) -> None:
        logging.info("Stopping proxy...")
        master.shutdown()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    logging.info(
        "Proxy listening on http://%s:%s - remember to trust mitmproxy's certificate",
        args.listen_host,
        args.listen_port,
    )
    master.run()


if __name__ == "__main__":
    cli_args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run_proxy(cli_args)
