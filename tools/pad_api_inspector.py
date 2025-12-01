#!/usr/bin/env python3
"""Power Automate Desktop REST inspector.

This addon turns ``mitmproxy``/``mitmdump`` into a focused recording proxy so you
can diff the HTTP requests produced by PowerShell vs. Power Automate Desktop
(PAD).

Quick start (once per machine):
    1. ``pip install mitmproxy``
    2. ``mitmdump -s tools/pad_api_inspector.py --listen-host 0.0.0.0 \
           --listen-port 8899 --set rest_log=~/pad_calls.ndjson``
    3. On Windows, route traffic from PAD/PowerShell through the proxy:
         * Temporary: ``netsh winhttp set proxy "<proxy_ip>:8899"``
         * GUI: Settings → Network & Internet → Proxy → Manual proxy setup
    4. Mitmproxy will prompt you to install its root certificate the first time.
       Accepting it lets the proxy decrypt HTTPS traffic so request bodies and
       headers are captured.
    5. Re-run the PAD flow. Each POST/GET request (plus responses) lands in the
       newline-delimited JSON log you pointed ``rest_log`` at.

You can filter by HTTP method or host, capture full payload previews, and feed
this log into any diff/analysis tooling you like.
"""

from __future__ import annotations

import argparse
import base64
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

try:  # mitmproxy injects these modules when it loads the addon
    from mitmproxy import ctx, http
except ImportError:  # pragma: no cover - running the helper CLI instead
    ctx = None  # type: ignore[assignment]
    http = None  # type: ignore[assignment]

_TEXTUAL_HINTS = ("json", "text", "xml", "urlencoded", "form-data")


@dataclass
class BodyPreview:
    size_bytes: int
    preview: str
    truncated: bool
    is_text: bool
    encoding: str


class PadRestInspector:
    """Mitmproxy addon that logs PAD HTTP traffic in a structured way."""

    def __init__(self) -> None:
        self.capture_methods = {"GET", "POST"}
        self.log_path = Path("pad_rest_log.ndjson")
        self.max_body = 4096
        self.host_filter = ""
        self.stdout_only = False

    def load(self, loader) -> None:  # type: ignore[override]
        loader.add_option(
            "rest_log",
            str,
            str(self.log_path),
            "Path to the newline-delimited JSON file.",
        )
        loader.add_option(
            "capture_methods",
            str,
            "GET,POST",
            "Comma-separated HTTP methods to log (e.g. GET,POST,PATCH).",
        )
        loader.add_option(
            "max_body",
            int,
            self.max_body,
            "Maximum number of bytes preserved from request/response bodies.",
        )
        loader.add_option(
            "host_filter",
            str,
            "",
            "Only record flows whose host contains this substring (case-insensitive).",
        )
        loader.add_option(
            "stdout_only",
            bool,
            False,
            "Print entries without touching the filesystem.",
        )

    def configure(self, updated) -> None:  # type: ignore[override]
        capture = {
            m.strip().upper()
            for m in ctx.options.capture_methods.split(",")
            if m.strip()
        }
        self.capture_methods = capture or {"GET", "POST"}
        self.max_body = max(256, ctx.options.max_body)
        self.log_path = Path(ctx.options.rest_log).expanduser()
        self.host_filter = ctx.options.host_filter.lower()
        self.stdout_only = ctx.options.stdout_only

        if not self.stdout_only:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            ctx.log.info(f"Writing REST traces to {self.log_path}")
        else:
            ctx.log.info("stdout_only enabled; not writing to disk")

    def response(self, flow: http.HTTPFlow) -> None:  # type: ignore[override]
        method = flow.request.method.upper()
        if method not in self.capture_methods:
            return

        host = flow.request.host or ""
        if self.host_filter and self.host_filter not in host.lower():
            return

        entry = self._build_entry(flow)
        ctx.log.info(
            f"{entry['request']['method']} {entry['request']['url']} -> "
            f"{entry['response']['status_code']} ({entry['response']['latency_ms']} ms)"
        )
        self._emit(entry)

    # ---------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------
    def _build_entry(self, flow: http.HTTPFlow) -> Dict[str, object]:
        request_body = self._body_preview(flow.request.raw_content, flow.request.headers)
        response_body = self._body_preview(flow.response.raw_content, flow.response.headers)

        latency = 0.0
        if flow.request.timestamp_start and flow.response.timestamp_end:
            latency = (flow.response.timestamp_end - flow.request.timestamp_start) * 1000

        return {
            "id": flow.id,
            "captured_at": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds"),
            "request": {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "host": flow.request.host,
                "http_version": flow.request.http_version,
                "headers": self._headers(flow.request.headers),
                "body": asdict(request_body),
            },
            "response": {
                "status_code": flow.response.status_code,
                "reason": flow.response.reason,
                "http_version": flow.response.http_version,
                "headers": self._headers(flow.response.headers),
                "body": asdict(response_body),
                "latency_ms": round(latency, 2),
            },
        }

    def _body_preview(self, data: Optional[bytes], headers) -> BodyPreview:
        raw = data or b""
        size = len(raw)
        snippet = raw[: self.max_body]
        truncated = size > self.max_body

        content_type = headers.get("content-type", "").lower()
        is_text = any(hint in content_type for hint in _TEXTUAL_HINTS)
        encoding = "utf-8"
        if "charset=" in content_type:
            encoding = content_type.split("charset=")[-1].split(";")[0].strip()

        if is_text:
            preview = snippet.decode(encoding or "utf-8", errors="replace")
        else:
            preview = base64.b64encode(snippet).decode("ascii")

        if truncated:
            suffix = " …(truncated)"
            preview = f"{preview}{suffix}"

        return BodyPreview(
            size_bytes=size,
            preview=preview,
            truncated=truncated,
            is_text=is_text,
            encoding=encoding or "utf-8",
        )

    def _headers(self, headers) -> List[Dict[str, str]]:
        return [{"name": k, "value": v} for k, v in headers.items(multi=True)]

    def _emit(self, entry: Dict[str, object]) -> None:
        line = json.dumps(entry, ensure_ascii=False)
        if self.stdout_only or not self.log_path:
            print(line)
            return

        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


addons = [PadRestInspector()]


def _print_usage() -> None:
    print(__doc__)
    print(
        "\nExample:\n"
        "    mitmdump -s tools/pad_api_inspector.py --listen-port 8899 \
        "
        "        --set rest_log=~/pad_calls.ndjson\n"
        "\nUse --set host_filter=api.example.com to focus on a single backend, or \n"
        "--set capture_methods=GET,POST,PATCH to widen the scope."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Show addon usage help")
    parser.add_argument(
        "--show-usage",
        action="store_true",
        help="Print usage instructions for running inside mitmproxy",
    )
    args = parser.parse_args()
    if args.show_usage:
        _print_usage()
    else:
        parser.print_help()


if __name__ == "__main__":
    if ctx is None:
        main()
