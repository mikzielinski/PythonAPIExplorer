#!/usr/bin/env python3
"""Trace every WinHTTP request PAD generates using Frida.

This script injects a Frida agent into PAD.Desktop.exe (or any process name you
pass in), hooks WinHTTP entry points, and streams every request/response body
and header into JSON files under the chosen log directory. No proxying or TLS
interception is required because we capture traffic directly inside the
application before encryption.
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

try:
    import frida  # type: ignore
except ModuleNotFoundError as exc:  # pragma: no cover - tool depends on frida at runtime
    raise SystemExit(
        "Frida is required. Install it with `pip install frida`.\n"
        f"Original error: {exc}"
    )

DEFAULT_PROCESS_CANDIDATES = [
    "PAD.Desktop.exe",
    "PAD.Designer.exe",
    "PAD.AutomationServer.exe",
    "PAD.Robot.exe",
    "pad.exe",
]

FRIDA_AGENT = r"""
'use strict';

const WINHTTP_FLAG_SECURE = 0x00800000;
let callCounter = 0;
const connectionMeta = {};
const requestMeta = {};
const activeRequests = {};

function nextCallId() {
    callCounter += 1;
    return `CALL_${callCounter}`;
}

function nowISO() {
    return new Date().toISOString();
}

function safeReadUtf16(ptr) {
    if (ptr.isNull()) {
        return null;
    }
    try {
        return Memory.readUtf16String(ptr);
    } catch (err) {
        send({ event: 'error', info: 'UTF16 read failed: ' + err });
        return null;
    }
}

function ensureCall(handle) {
    if (activeRequests[handle]) {
        return activeRequests[handle];
    }
    const meta = requestMeta[handle] || {};
    const id = nextCallId();
    activeRequests[handle] = { id: id, handle: handle };
    send({
        event: 'request_start',
        id: id,
        handle: handle,
        timestamp: nowISO(),
        method: meta.method || 'UNKNOWN',
        host: meta.host || '',
        port: meta.port || 0,
        path: meta.path || '/',
        secure: !!meta.secure,
    });
    return activeRequests[handle];
}

function finishCall(handle, reason) {
    if (!activeRequests[handle]) {
        return;
    }
    send({ event: 'request_end', handle: handle, reason: reason || 'WinHttpCloseHandle' });
    delete activeRequests[handle];
    delete requestMeta[handle];
}

Interceptor.attach(Module.getExportByName('winhttp.dll', 'WinHttpConnect'), {
    onEnter(args) {
        this.serverName = safeReadUtf16(args[1]) || '';
        this.port = args[2].toInt32();
    },
    onLeave(retval) {
        if (retval.isNull()) {
            return;
        }
        connectionMeta[retval.toString()] = {
            host: this.serverName,
            port: this.port,
        };
    },
});

Interceptor.attach(Module.getExportByName('winhttp.dll', 'WinHttpOpenRequest'), {
    onEnter(args) {
        this.hConnect = args[0].toString();
        this.method = safeReadUtf16(args[1]) || 'GET';
        this.path = safeReadUtf16(args[2]) || '/';
        this.flags = args[6] ? args[6].toInt32() : 0;
    },
    onLeave(retval) {
        if (retval.isNull()) {
            return;
        }
        const requestHandle = retval.toString();
        const conn = connectionMeta[this.hConnect] || {};
        requestMeta[requestHandle] = {
            method: this.method,
            path: this.path,
            host: conn.host || '',
            port: conn.port || 0,
            secure: (this.flags & WINHTTP_FLAG_SECURE) !== 0,
        };
    },
});

Interceptor.attach(Module.getExportByName('winhttp.dll', 'WinHttpSendRequest'), {
    onEnter(args) {
        const handle = args[0].toString();
        ensureCall(handle);

        const lpOptional = args[4];
        const optionalLen = args[5].toInt32();
        if (!lpOptional.isNull() && optionalLen > 0) {
            const chunk = Memory.readByteArray(lpOptional, optionalLen);
            send({ event: 'request_body', handle: handle }, chunk);
        }
    },
    onLeave(retval) {
        if (retval.toInt32() === 0) {
            send({ event: 'request_error', stage: 'WinHttpSendRequest' });
        }
    },
});

Interceptor.attach(Module.getExportByName('winhttp.dll', 'WinHttpAddRequestHeadersW'), {
    onEnter(args) {
        const handle = args[0].toString();
        ensureCall(handle);
        const header = safeReadUtf16(args[1]);
        if (header) {
            send({ event: 'header', handle: handle, header: header });
        }
    },
});

Interceptor.attach(Module.getExportByName('winhttp.dll', 'WinHttpWriteData'), {
    onEnter(args) {
        this.handle = args[0].toString();
        this.buffer = args[1];
        this.lenRequested = args[2].toInt32();
        this.lenPtr = args[3];
    },
    onLeave(retval) {
        if (retval.toInt32() === 0) {
            return;
        }
        if (!this.buffer || this.buffer.isNull()) {
            return;
        }
        let size = this.lenRequested;
        if (this.lenPtr && !this.lenPtr.isNull()) {
            try {
                size = Memory.readU32(this.lenPtr);
            } catch (_) {}
        }
        if (size <= 0) {
            return;
        }
        ensureCall(this.handle);
        const chunk = Memory.readByteArray(this.buffer, size);
        send({ event: 'request_body', handle: this.handle }, chunk);
    },
});

Interceptor.attach(Module.getExportByName('winhttp.dll', 'WinHttpReceiveResponse'), {
    onEnter(args) {
        this.handle = args[0].toString();
    },
    onLeave(retval) {
        if (retval.toInt32() === 0) {
            return;
        }
        ensureCall(this.handle);
        send({ event: 'response_start', handle: this.handle });
    },
});

Interceptor.attach(Module.getExportByName('winhttp.dll', 'WinHttpReadData'), {
    onEnter(args) {
        this.handle = args[0].toString();
        this.buffer = args[1];
        this.readPtr = args[3];
    },
    onLeave(retval) {
        if (retval.toInt32() === 0) {
            return;
        }
        if (!this.buffer || this.buffer.isNull() || !this.readPtr || this.readPtr.isNull()) {
            return;
        }
        let size = 0;
        try {
            size = Memory.readU32(this.readPtr);
        } catch (e) {
            send({ event: 'error', info: 'ReadData length failed: ' + e });
            return;
        }
        if (size <= 0) {
            return;
        }
        const chunk = Memory.readByteArray(this.buffer, size);
        send({ event: 'response_body', handle: this.handle }, chunk);
    },
});

Interceptor.attach(Module.getExportByName('winhttp.dll', 'WinHttpCloseHandle'), {
    onEnter(args) {
        this.handle = args[0].toString();
    },
    onLeave(retval) {
        if (retval.toInt32() === 0) {
            return; // close failed, skip cleanup
        }
        finishCall(this.handle, 'WinHttpCloseHandle');
        delete connectionMeta[this.handle];
    },
});
"""


@dataclass
class BodyCapture:
    chunks: List[bytes] = field(default_factory=list)

    def append(self, chunk: bytes) -> None:
        if chunk:
            self.chunks.append(bytes(chunk))

    def as_bytes(self) -> bytes:
        return b"".join(self.chunks)

    def as_dict(self) -> Dict[str, Optional[str]]:
        payload = self.as_bytes()
        if not payload:
            return {"text": "", "base64": "", "size_bytes": 0, "encoding": "utf-8"}

        try:
            text = payload.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            try:
                text = payload.decode("latin-1")
                encoding = "latin-1"
            except UnicodeDecodeError:
                text = None
                encoding = "binary"

        return {
            "text": text,
            "base64": base64.b64encode(payload).decode("ascii"),
            "size_bytes": len(payload),
            "encoding": encoding,
        }


@dataclass
class CallRecord:
    identifier: str
    handle: str
    timestamp: str
    method: str
    host: str
    port: int
    path: str
    secure: bool
    headers: List[str] = field(default_factory=list)
    request_body: BodyCapture = field(default_factory=BodyCapture)
    response_body: BodyCapture = field(default_factory=BodyCapture)

    def url(self) -> str:
        scheme = "https" if self.secure else "http"
        port_suffix = "" if (self.port == 0 or (self.secure and self.port == 443) or (not self.secure and self.port == 80)) else f":{self.port}"
        return f"{scheme}://{self.host}{port_suffix}{self.path}" if self.host else self.path

    def to_json(self) -> Dict[str, object]:
        return {
            "id": self.identifier,
            "timestamp": self.timestamp,
            "url": self.url(),
            "method": self.method,
            "handle": self.handle,
            "headers": self.headers,
            "request_body": self.request_body.as_dict(),
            "response_body": self.response_body.as_dict(),
        }


def resolve_process_target(process_spec: str) -> Union[int, str]:
    spec = (process_spec or "").strip()
    if spec.lower() != "auto":
        try:
            return int(spec)
        except ValueError:
            return spec

    device = frida.get_local_device()
    running = {proc.name.lower(): proc for proc in device.enumerate_processes()}
    for candidate in DEFAULT_PROCESS_CANDIDATES:
        proc = running.get(candidate.lower())
        if proc:
            logging.info("Auto-detected PAD process: %s (pid %s)", proc.name, proc.pid)
            return proc.pid

    checked = ", ".join(DEFAULT_PROCESS_CANDIDATES)
    raise SystemExit(
        "Could not auto-detect a running PAD process. Start Power Automate Desktop "
        f"or pass --process <name-or-pid>. Checked: {checked}"
    )


class PadHttpTracer:
    def __init__(self, process_spec: str, log_dir: Path) -> None:
        self.process_spec = process_spec
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.calls: Dict[str, CallRecord] = {}
        self.session: Optional[frida.core.Session] = None
        self.script = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        target = resolve_process_target(self.process_spec)
        human = f"PID {target}" if isinstance(target, int) else target
        logging.info("Attaching to %s", human)
        try:
            self.session = frida.attach(target)
        except frida.ProcessNotFoundError:
            raise SystemExit(f"Process '{human}' not found. Is PAD running?")

        self.script = self.session.create_script(FRIDA_AGENT)
        self.script.on("message", self._on_message)
        self.script.load()

        logging.info("Hook active. Press Ctrl+C to stop.")
        self._stop_event.wait()
        self._cleanup()

    def stop(self) -> None:
        self._stop_event.set()

    def _cleanup(self) -> None:
        if self.script is not None:
            try:
                self.script.unload()
            except frida.InvalidOperationError:
                pass
            self.script = None
        if self.session is not None:
            try:
                self.session.detach()
            except frida.InvalidOperationError:
                pass
            self.session = None
        self._flush_open_calls()

    def _flush_open_calls(self) -> None:
        for handle, record in list(self.calls.items()):
            logging.info("Flushing incomplete call %s (%s)", record.identifier, handle)
            self._save_call(record, reason="forced_shutdown")
            del self.calls[handle]

    def _on_message(self, message, data) -> None:
        if message["type"] != "send":
            logging.error("FRIDA: %s", message)
            return

        payload = message["payload"]
        event = payload.get("event")
        handle = payload.get("handle")

        if event == "request_start":
            record = CallRecord(
                identifier=payload["id"],
                handle=handle,
                timestamp=payload.get("timestamp", ""),
                method=payload.get("method", "UNKNOWN"),
                host=payload.get("host", ""),
                port=int(payload.get("port", 0)),
                path=payload.get("path", "/"),
                secure=bool(payload.get("secure", False)),
            )
            self.calls[handle] = record
            logging.info("[%s] %s %s", record.identifier, record.method, record.url())
        elif event == "header":
            record = self.calls.get(handle)
            if record:
                record.headers.append(payload.get("header", ""))
                logging.debug("[%s] Header: %s", record.identifier, payload.get("header"))
        elif event == "request_body":
            record = self.calls.get(handle)
            if record and data:
                record.request_body.append(data)
                logging.debug("[%s] Request chunk %d bytes", record.identifier, len(data))
        elif event == "response_body":
            record = self.calls.get(handle)
            if record and data:
                record.response_body.append(data)
                logging.debug("[%s] Response chunk %d bytes", record.identifier, len(data))
        elif event == "response_start":
            record = self.calls.get(handle)
            if record:
                logging.debug("[%s] Response started", record.identifier)
        elif event == "request_end":
            record = self.calls.pop(handle, None)
            if record:
                self._save_call(record, reason=payload.get("reason"))
        elif event == "request_error":
            logging.warning("Request error: %s", payload.get("stage"))
        elif event == "error":
            logging.warning("Agent error: %s", payload.get("info"))
        else:
            logging.debug("Unhandled event: %s", payload)

    def _save_call(self, record: CallRecord, reason: Optional[str] = None) -> None:
        doc = record.to_json()
        if reason:
            doc["completed_by"] = reason
        path = self.log_dir / f"{record.identifier}.json"
        with path.open("w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
        logging.info(
            "Saved %s (%d req bytes -> %d resp bytes) -> %s",
            record.identifier,
            doc["request_body"]["size_bytes"],
            doc["response_body"]["size_bytes"],
            path,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Trace PAD HTTP calls via Frida")
    parser.add_argument(
        "--process",
        default="auto",
        help="Process name or PID to attach. Use 'auto' (default) to scan for PAD processes.",
    )
    parser.add_argument(
        "--log-dir",
        default="pad_full_http_logs",
        type=Path,
        help="Directory where call JSON files will be written",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    return parser.parse_args()


def install_signal_handlers(tracer: PadHttpTracer) -> None:
    def _handler(signum, _frame):
        logging.info("Signal %s received, stopping...", signum)
        tracer.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _handler)


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    tracer = PadHttpTracer(str(args.process), Path(args.log_dir))
    install_signal_handlers(tracer)
    try:
        tracer.start()
    except KeyboardInterrupt:
        tracer.stop()
    except frida.TransportError as exc:
        logging.error("Frida transport error: %s", exc)
    finally:
        tracer.stop()


if __name__ == "__main__":
    main()
