#!/usr/bin/env python3
"""A lightweight MITM proxy to inspect PAD REST calls.

This tool spins up a local HTTP/HTTPS proxy (powered by mitmproxy) and logs
all GET/POST requests/responses into a JSONL file so you can diff executions
between PowerShell and Power Automate Desktop.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import platform
import re
import signal
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional

try:
    from mitmproxy import certs, http, options
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
        "--confdir",
        default=str((Path.home() / ".mitmproxy").resolve()),
        help="Where to store mitmproxy certificates (default: ~/.mitmproxy)",
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
    parser.add_argument(
        "--no-auto-config",
        action="store_true",
        help="Skip automatic Windows proxy/certificate setup",
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
    asyncio.run(_run_proxy(args))


async def _run_proxy(args: argparse.Namespace) -> None:
    opts = options.Options(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        mode=["regular"],
        http2=True,
        confdir=str(Path(args.confdir).expanduser()),
    )
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    addon = PadRestLogger(Path(args.log_file), args.methods, args.body_bytes, args.verbose)
    master.addons.add(addon)

    confdir = Path(master.options.confdir or Path.home() / ".mitmproxy")
    cert_path = ensure_ca_certificate(confdir)

    auto_ctx = (
        configure_system_proxy(args.listen_host, args.listen_port, cert_path)
        if not args.no_auto_config
        else contextlib.nullcontext()
    )

    loop = asyncio.get_running_loop()

    def _shutdown(*_sig) -> None:
        logging.info("Stopping proxy...")
        master.shutdown()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except NotImplementedError:  # Windows event loop limitation
            signal.signal(sig, _shutdown)

    logging.info("Proxy listening on http://%s:%s", args.listen_host, args.listen_port)
    with auto_ctx:
        await master.run()


def ensure_ca_certificate(confdir: Path) -> Path:
    confdir = confdir.expanduser()
    confdir.mkdir(parents=True, exist_ok=True)
    cert_path = confdir / "mitmproxy-ca-cert.cer"
    if cert_path.exists():
        return cert_path

    logging.info("Generating mitmproxy root CA under %s", confdir)
    certs.CertStore.from_store(path=confdir, basename="mitmproxy", key_size=2048)

    deadline = time.time() + 15
    while time.time() < deadline:
        if cert_path.exists():
            return cert_path
        time.sleep(0.2)
    raise RuntimeError(f"Unable to create mitmproxy CA certificate at {cert_path}")


def configure_system_proxy(host: str, port: int, cert_path: Path):
    system = platform.system()
    if system != "Windows":
        logging.warning(
            "Automatic proxy & certificate installation is currently only supported on Windows."
        )
        return contextlib.nullcontext()
    return WindowsAutoConfigurator(host, port, cert_path)


class WindowsAutoConfigurator(contextlib.AbstractContextManager["WindowsAutoConfigurator"]):
    """Configure WinINET proxy + trust the mitmproxy CA while the proxy runs."""

    REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def __init__(self, host: str, port: int, cert_path: Path) -> None:
        self.proxy_endpoint = f"{host}:{port}"
        self.cert_path = cert_path
        self._env_backup: dict[str, Optional[str]] = {}
        self._orig_enable: Optional[int] = None
        self._orig_server: Optional[str] = None
        self._orig_override: Optional[str] = None
        self._thumbprint: Optional[str] = None
        self._winhttp_backup: Optional[dict[str, Optional[str]]] = None

    def __enter__(self):
        import winreg  # type: ignore

        self._env_backup = {k: os.environ.get(k) for k in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY")}
        self._orig_enable = self._query_dword(winreg, "ProxyEnable")
        self._orig_server = self._query_string(winreg, "ProxyServer")
        self._orig_override = self._query_string(winreg, "ProxyOverride")
        self._winhttp_backup = _read_winhttp_proxy()

        self._apply_proxy(winreg)
        self._apply_winhttp_proxy()
        self._thumbprint = install_windows_root_cert(self.cert_path)
        self._apply_env()

        logging.info("Windows proxy temporarily set to http://%s", self.proxy_endpoint)
        return self

    def __exit__(self, exc_type, exc, tb):
        import winreg  # type: ignore

        self._restore_proxy(winreg)
        self._restore_winhttp_proxy()
        self._restore_env()
        if self._thumbprint:
            uninstall_windows_root_cert(self._thumbprint)
        return False

    def _apply_proxy(self, winreg) -> None:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.REG_PATH) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, self.proxy_endpoint)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
        broadcast_proxy_change()

    def _restore_proxy(self, winreg) -> None:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.REG_PATH) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(self._orig_enable or 0))
            if self._orig_server is None:
                self._delete_value(winreg, key, "ProxyServer")
            else:
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, self._orig_server)

            if self._orig_override is None:
                self._delete_value(winreg, key, "ProxyOverride")
            else:
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, self._orig_override)
        broadcast_proxy_change()

    def _apply_env(self) -> None:
        proxy = f"http://{self.proxy_endpoint}"
        os.environ["HTTP_PROXY"] = proxy
        os.environ["HTTPS_PROXY"] = proxy
        os.environ.setdefault("NO_PROXY", "localhost,127.0.0.1")

    def _restore_env(self) -> None:
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _query_string(self, winreg, name: str) -> Optional[str]:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.REG_PATH, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return str(value)
        except FileNotFoundError:
            return None
        except OSError:
            return None

    def _query_dword(self, winreg, name: str) -> Optional[int]:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.REG_PATH, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return int(value)
        except FileNotFoundError:
            return None
        except OSError:
            return None

    def _delete_value(self, winreg, key, name: str) -> None:
        try:
            winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def _apply_winhttp_proxy(self) -> None:
        cmd = [
            "netsh",
            "winhttp",
            "set",
            "proxy",
            f'proxy-server="{self.proxy_endpoint}"',
            'bypass-list="<local>"',
        ]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            logging.info("Configured WinHTTP proxy to %s", self.proxy_endpoint)
        except (OSError, subprocess.CalledProcessError) as exc:
            logging.warning("Unable to set WinHTTP proxy (requires admin?): %s", exc)

    def _restore_winhttp_proxy(self) -> None:
        backup = self._winhttp_backup
        if not backup:
            return
        try:
            if backup.get("mode") == "direct":
                subprocess.run(
                    ["netsh", "winhttp", "reset", "proxy"],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            elif backup.get("mode") == "proxy":
                args = [
                    "netsh",
                    "winhttp",
                    "set",
                    "proxy",
                    f'proxy-server="{backup.get("server", "")}"',
                ]
                bypass = backup.get("bypass")
                if bypass:
                    args.append(f'bypass-list="{bypass}"')
                subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            logging.warning("Unable to restore WinHTTP proxy: %s", exc)


def install_windows_root_cert(cert_path: Path) -> str:
    thumbprint = compute_thumbprint(cert_path)
    cmd = ["certutil", "-user", "-addstore", "Root", str(cert_path)]
    logging.info("Importing mitmproxy CA into the current user's Root store")
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return thumbprint


def uninstall_windows_root_cert(thumbprint: str) -> None:
    ps_script = (
        "$thumb='{thumb}';"
        "Get-ChildItem -Path Cert:\\CurrentUser\\Root | "
        "Where-Object { $_.Thumbprint -eq $thumb } | "
        "Remove-Item -ErrorAction SilentlyContinue"
    ).format(thumb=thumbprint)
    subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_script],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def broadcast_proxy_change() -> None:
    try:
        import ctypes

        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        wininet = ctypes.windll.Wininet  # type: ignore[attr-defined]
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception as exc:  # pragma: no cover - platform specific
        logging.debug("Unable to broadcast proxy change: %s", exc)


def compute_thumbprint(cert_path: Path) -> str:
    pem = cert_path.read_text(encoding="utf-8")
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha1(der).hexdigest().upper()


def _read_winhttp_proxy() -> Optional[dict[str, Optional[str]]]:
    try:
        result = subprocess.run(
            ["netsh", "winhttp", "show", "proxy"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None

    output = result.stdout
    if "Direct access (no proxy server)" in output:
        return {"mode": "direct"}

    server_match = re.search(r"Proxy Server\(s\)\s*:\s*(.+)", output)
    bypass_match = re.search(r"Bypass List\s*:\s*(.+)", output)
    if not server_match:
        return {"mode": "direct"}
    server = server_match.group(1).strip()
    bypass = bypass_match.group(1).strip() if bypass_match else ""
    if bypass.lower() == "(none)":
        bypass = ""
    return {"mode": "proxy", "server": server, "bypass": bypass}


if __name__ == "__main__":
    cli_args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run_proxy(cli_args)
