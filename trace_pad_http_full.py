#!/usr/bin/env python3
"""Trace every WinHTTP/WinINet request PAD (and spawned tools) issue using Frida.

This tool can attach to multiple processes at once, continually rescans for new
Power Automate Desktop workers, and captures complete request/response payloads
without forcing TLS interception.
"""
from __future__ import annotations

import argparse
import base64
import functools
import json
import logging
import signal
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

try:
    import frida  # type: ignore
except ModuleNotFoundError as exc:  # pragma: no cover - runtime dependency
    raise SystemExit(
        "Frida is required. Install it with `pip install frida`.\n"
        f"Original error: {exc}"
    )

DEFAULT_PROCESS_PATTERNS = [
    "pad.desktop.exe",
    "pad.designer.exe",
    "pad.automationserver.exe",
    "pad.automationservice.exe",
    "pad.robot.exe",
    "pad.robotservice.exe",
    "pad.*",
]

FRIDA_AGENT = r"""
'use strict';

const SECURE_FLAG = 0x00800000;
const WINHTTP_FLAG_SECURE = SECURE_FLAG;
const WININET_FLAG_SECURE = SECURE_FLAG;
let callCounter = 0;
const connectionMeta = {};
const requestMeta = {};
const activeRequests = {};

function sendEvent(payload, data) {
    payload.pid = Process.id;
    send(payload, data);
}

function attachExport(moduleName, symbols, callbacks) {
    const names = Array.isArray(symbols) ? symbols : [symbols];
    for (const name of names) {
        const addr = Module.findExportByName(moduleName, name);
        if (addr) {
            Interceptor.attach(addr, callbacks);
            return true;
        }
    }
    sendEvent({
        event: 'hook_warning',
        info: `${moduleName}: unable to find export(s): ${names.join(', ')}`,
    });
    return false;
}

function attachWinHttp(symbols, callbacks) {
    return attachExport('winhttp.dll', symbols, callbacks);
}

function attachWinInet(symbols, callbacks) {
    return attachExport('wininet.dll', symbols, callbacks);
}

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
        sendEvent({ event: 'error', info: 'UTF16 read failed: ' + err });
        return null;
    }
}

function safeReadAnsi(ptr) {
    if (ptr.isNull()) {
        return null;
    }
    try {
        return Memory.readCString(ptr);
    } catch (err) {
        sendEvent({ event: 'error', info: 'ANSI read failed: ' + err });
        return null;
    }
}

function readPointerString(ptr, byteLength, isWide) {
    if (ptr.isNull()) {
        return null;
    }
    try {
        if (byteLength > 0 && byteLength !== 0xFFFFFFFF) {
            const units = isWide ? Math.floor(byteLength / 2) : byteLength;
            return isWide ? Memory.readUtf16String(ptr, units) : Memory.readCString(ptr, units);
        }
        return isWide ? Memory.readUtf16String(ptr) : Memory.readCString(ptr);
    } catch (err) {
        sendEvent({ event: 'error', info: 'String read failed: ' + err });
        return null;
    }
}

function emitHeaderLines(handle, headerBlock) {
    if (!headerBlock) {
        return;
    }
    headerBlock
        .split(/\r?\n/)
        .map(h => h.trim())
        .filter(Boolean)
        .forEach(line => {
            sendEvent({ event: 'header', handle: handle, header: line });
        });
}

function ensureCall(handle) {
    if (activeRequests[handle]) {
        return activeRequests[handle];
    }
    const meta = requestMeta[handle] || {};
    const id = nextCallId();
    activeRequests[handle] = { id: id, handle: handle };
    sendEvent({
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
    sendEvent({ event: 'request_end', handle: handle, reason: reason || 'CloseHandle' });
    delete activeRequests[handle];
    delete requestMeta[handle];
}

attachWinHttp('WinHttpConnect', {
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

attachWinHttp('WinHttpOpenRequest', {
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

attachWinHttp('WinHttpSendRequest', {
    onEnter(args) {
        const handle = args[0].toString();
        ensureCall(handle);

        const lpOptional = args[4];
        const optionalLen = args[5].toInt32();
        if (!lpOptional.isNull() && optionalLen > 0) {
            const chunk = Memory.readByteArray(lpOptional, optionalLen);
            sendEvent({ event: 'request_body', handle: handle }, chunk);
        }
    },
    onLeave(retval) {
        if (retval.toInt32() === 0) {
            sendEvent({ event: 'request_error', stage: 'WinHttpSendRequest' });
        }
    },
});

attachWinHttp(['WinHttpAddRequestHeadersW', 'WinHttpAddRequestHeaders'], {
    onEnter(args) {
        const handle = args[0].toString();
        ensureCall(handle);
        const header = safeReadUtf16(args[1]);
        if (header) {
            sendEvent({ event: 'header', handle: handle, header: header });
        }
    },
});

attachWinHttp('WinHttpWriteData', {
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
        sendEvent({ event: 'request_body', handle: this.handle }, chunk);
    },
});

attachWinHttp('WinHttpReceiveResponse', {
    onEnter(args) {
        this.handle = args[0].toString();
    },
    onLeave(retval) {
        if (retval.toInt32() === 0) {
            return;
        }
        ensureCall(this.handle);
        sendEvent({ event: 'response_start', handle: this.handle });
    },
});

attachWinHttp('WinHttpReadData', {
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
            sendEvent({ event: 'error', info: 'WinHttpReadData length failed: ' + e });
            return;
        }
        if (size <= 0) {
            return;
        }
        const chunk = Memory.readByteArray(this.buffer, size);
        sendEvent({ event: 'response_body', handle: this.handle }, chunk);
    },
});

attachWinHttp('WinHttpCloseHandle', {
    onEnter(args) {
        this.handle = args[0].toString();
    },
    onLeave(retval) {
        if (retval.toInt32() === 0) {
            return;
        }
        finishCall(this.handle, 'WinHttpCloseHandle');
        delete connectionMeta[this.handle];
    },
});

/* WinINet coverage for cmd.exe / powershell.exe REST helpers */
attachWinInet('InternetConnectW', {
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

attachWinInet('InternetConnectA', {
    onEnter(args) {
        this.serverName = safeReadAnsi(args[1]) || '';
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

function hookHttpOpenRequest(isWide) {
    return {
        onEnter(args) {
            this.hConnect = args[0].toString();
            this.method = isWide ? safeReadUtf16(args[1]) : safeReadAnsi(args[1]);
            this.path = isWide ? safeReadUtf16(args[2]) : safeReadAnsi(args[2]);
            this.flags = args[6] ? args[6].toInt32() : 0;
        },
        onLeave(retval) {
            if (retval.isNull()) {
                return;
            }
            const requestHandle = retval.toString();
            const conn = connectionMeta[this.hConnect] || {};
            requestMeta[requestHandle] = {
                method: this.method || 'GET',
                path: this.path || '/',
                host: conn.host || '',
                port: conn.port || 0,
                secure: (this.flags & WININET_FLAG_SECURE) !== 0,
            };
        },
    };
}

attachWinInet('HttpOpenRequestW', hookHttpOpenRequest(true));
attachWinInet('HttpOpenRequestA', hookHttpOpenRequest(false));

function hookHttpSendRequest(isWide) {
    return {
        onEnter(args) {
            const handle = args[0].toString();
            ensureCall(handle);

            const headerPtr = args[1];
            const headerLen = args[2].toInt32();
            const headerStr = readPointerString(headerPtr, headerLen, isWide);
            emitHeaderLines(handle, headerStr);

            const optionalPtr = args[3];
            const optionalLen = args[4].toInt32();
            if (!optionalPtr.isNull() && optionalLen > 0) {
                const chunk = Memory.readByteArray(optionalPtr, optionalLen);
                sendEvent({ event: 'request_body', handle: handle }, chunk);
            }
        },
        onLeave(retval) {
            if (retval.toInt32() === 0) {
                sendEvent({ event: 'request_error', stage: 'HttpSendRequest' });
            }
        },
    };
}

attachWinInet('HttpSendRequestW', hookHttpSendRequest(true));
attachWinInet('HttpSendRequestA', hookHttpSendRequest(false));

function hookHttpAddHeaders(isWide) {
    return {
        onEnter(args) {
            const handle = args[0].toString();
            ensureCall(handle);
            const headerStr = readPointerString(args[1], args[2].toInt32(), isWide);
            emitHeaderLines(handle, headerStr);
        },
    };
}

attachWinInet('HttpAddRequestHeadersW', hookHttpAddHeaders(true));
attachWinInet('HttpAddRequestHeadersA', hookHttpAddHeaders(false));

attachWinInet('InternetWriteFile', {
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
        sendEvent({ event: 'request_body', handle: this.handle }, chunk);
    },
});

attachWinInet('InternetReadFile', {
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
            sendEvent({ event: 'error', info: 'InternetReadFile length failed: ' + e });
            return;
        }
        if (size <= 0) {
            return;
        }
        const chunk = Memory.readByteArray(this.buffer, size);
        sendEvent({ event: 'response_body', handle: this.handle }, chunk);
    },
});

attachWinInet('InternetCloseHandle', {
    onEnter(args) {
        this.handle = args[0].toString();
    },
    onLeave(retval) {
        if (retval.toInt32() === 0) {
            return;
        }
        finishCall(this.handle, 'InternetCloseHandle');
        delete connectionMeta[this.handle];
    },
});
"""


@dataclass(frozen=True)
class TargetProcess:
    pid: int
    name: str


@dataclass
class TracerSession:
    target: TargetProcess
    session: frida.core.Session  # type: ignore[name-defined]
    script: frida.core.Script  # type: ignore[name-defined]


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
    pid: int
    process_name: str
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
        default_port = 443 if self.secure else 80
        port_suffix = "" if (self.port in (0, default_port)) else f":{self.port}"
        return f"{scheme}://{self.host}{port_suffix}{self.path}" if self.host else self.path

    def to_json(self) -> Dict[str, object]:
        return {
            "id": self.identifier,
            "pid": self.pid,
            "process": self.process_name,
            "timestamp": self.timestamp,
            "url": self.url(),
            "method": self.method,
            "handle": self.handle,
            "headers": self.headers,
            "request_body": self.request_body.as_dict(),
            "response_body": self.response_body.as_dict(),
        }


def sanitize_filename(name: str) -> str:
    safe = [c if c.isalnum() or c in ("-", "_") else "_" for c in name]
    return "".join(safe) or "process"


def parse_process_tokens(spec: str) -> List[str]:
    raw = spec or "auto"
    tokens = [token.strip().lower() for token in raw.split(",") if token.strip()]
    return tokens or ["auto"]


def matches_name(token: str, candidate: str) -> bool:
    if token == "*":
        return True
    if token.endswith("*"):
        return candidate.startswith(token[:-1])
    return candidate == token


def find_matching_processes(device: frida.core.Device, tokens: List[str]) -> List[TargetProcess]:  # type: ignore[name-defined]
    running = device.enumerate_processes()
    by_name: Dict[str, List[frida.core.Process]] = {}  # type: ignore[name-defined]
    for proc in running:
        by_name.setdefault(proc.name.lower(), []).append(proc)

    matches: Dict[int, TargetProcess] = {}
    for token in tokens:
        if token == "auto":
            for pattern in DEFAULT_PROCESS_PATTERNS:
                _collect_matches(pattern, by_name, matches)
            continue
        if token.isdigit():
            pid = int(token)
            proc = next((p for p in running if p.pid == pid), None)
            name = proc.name if proc else f"pid:{pid}"
            matches.setdefault(pid, TargetProcess(pid=pid, name=name))
            continue
        _collect_matches(token, by_name, matches)

    return list(matches.values())


def _collect_matches(pattern: str, by_name: Dict[str, List[frida.core.Process]], matches: Dict[int, TargetProcess]) -> None:  # type: ignore[name-defined]
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        for name, procs in by_name.items():
            if name.startswith(prefix):
                for proc in procs:
                    matches.setdefault(proc.pid, TargetProcess(pid=proc.pid, name=proc.name))
        return

    for proc in by_name.get(pattern, []):
        matches.setdefault(proc.pid, TargetProcess(pid=proc.pid, name=proc.name))


class PadHttpTracer:
    def __init__(self, process_spec: str, log_dir: Path, rescan_seconds: float) -> None:
        self.process_tokens = parse_process_tokens(process_spec)
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.rescan_seconds = max(0.5, rescan_seconds)
        self.calls: Dict[str, CallRecord] = {}
        self.device = frida.get_local_device()
        self.sessions: Dict[int, TracerSession] = {}
        self._stop_event = threading.Event()
        self._watch_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._attach_new_targets(initial=True)
        if not self.sessions:
            logging.warning("No matching processes yet. Waiting for them to start ...")
        self._watch_thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._watch_thread.start()
        logging.info("Hook active. Press Ctrl+C to stop.")
        self._stop_event.wait()
        self._cleanup()

    def stop(self) -> None:
        self._stop_event.set()

    def _watch_loop(self) -> None:
        while not self._stop_event.wait(self.rescan_seconds):
            self._attach_new_targets()

    def _attach_new_targets(self, initial: bool = False) -> None:
        targets = find_matching_processes(self.device, self.process_tokens)
        new_targets = [t for t in targets if t.pid not in self.sessions]
        if initial and not new_targets:
            logging.debug("No initial process matches for %s", self.process_tokens)
        for target in new_targets:
            self._attach_to_target(target)

    def _attach_to_target(self, target: TargetProcess) -> None:
        try:
            session = self.device.attach(target.pid)
        except frida.ProcessNotFoundError:
            logging.warning("Process %s (pid %s) disappeared before attach", target.name, target.pid)
            return

        script = session.create_script(FRIDA_AGENT)
        script.on("message", functools.partial(self._on_message, target))
        script.load()

        self.sessions[target.pid] = TracerSession(target=target, session=session, script=script)
        logging.info("Attached to %s (pid %s)", target.name, target.pid)

    def _cleanup(self) -> None:
        for session in list(self.sessions.values()):
            try:
                session.script.unload()
            except frida.InvalidOperationError:
                pass
            try:
                session.session.detach()
            except frida.InvalidOperationError:
                pass
        self.sessions.clear()
        if self._watch_thread:
            self._watch_thread.join(timeout=1)
        self._flush_open_calls()

    def _flush_open_calls(self) -> None:
        for key, record in list(self.calls.items()):
            logging.info("Flushing incomplete call %s from %s", record.identifier, record.process_name)
            self._save_call(record, reason="forced_shutdown")
            del self.calls[key]

    def _on_message(self, target: TargetProcess, message, data) -> None:
        if message["type"] != "send":
            logging.error("FRIDA (%s:%s): %s", target.name, target.pid, message)
            return

        payload = message["payload"]
        event = payload.get("event")
        handle = payload.get("handle")
        pid = int(payload.get("pid", target.pid))
        key = f"{pid}:{handle}" if handle else None

        if event == "request_start" and key:
            record = CallRecord(
                identifier=payload["id"],
                handle=handle,
                pid=pid,
                process_name=target.name,
                timestamp=payload.get("timestamp", ""),
                method=payload.get("method", "UNKNOWN"),
                host=payload.get("host", ""),
                port=int(payload.get("port", 0)),
                path=payload.get("path", "/"),
                secure=bool(payload.get("secure", False)),
            )
            self.calls[key] = record
            logging.info("[%s:%s] %s %s", target.name, pid, record.method, record.url())
        elif event == "header" and key:
            record = self.calls.get(key)
            if record:
                record.headers.append(payload.get("header", ""))
        elif event == "request_body" and key:
            record = self.calls.get(key)
            if record and data:
                record.request_body.append(data)
        elif event == "response_body" and key:
            record = self.calls.get(key)
            if record and data:
                record.response_body.append(data)
        elif event == "response_start" and key:
            record = self.calls.get(key)
            if record:
                logging.debug("[%s:%s] Response started", record.process_name, record.pid)
        elif event == "request_end" and key:
            record = self.calls.pop(key, None)
            if record:
                self._save_call(record, reason=payload.get("reason"))
        elif event == "request_error":
            logging.warning("Request error (%s:%s): %s", target.name, pid, payload.get("stage"))
        elif event == "error":
            logging.warning("Agent error (%s:%s): %s", target.name, pid, payload.get("info"))
        elif event == "hook_warning":
            logging.debug("(%s:%s) %s", target.name, pid, payload.get("info"))
        else:
            logging.debug("Unhandled event from %s:%s -> %s", target.name, pid, payload)

    def _save_call(self, record: CallRecord, reason: Optional[str] = None) -> None:
        doc = record.to_json()
        if reason:
            doc["completed_by"] = reason
        safe_name = sanitize_filename(record.process_name)
        filename = f"{safe_name}_pid{record.pid}_{record.identifier}.json"
        path = self.log_dir / filename
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
        help=(
            "Comma-separated list of process names/pids. Use 'auto' to watch common "
            "PAD executables (default). Examples: --process auto,powershell.exe"
        ),
    )
    parser.add_argument(
        "--log-dir",
        default="pad_full_http_logs",
        type=Path,
        help="Directory where call JSON files will be written",
    )
    parser.add_argument(
        "--rescan-seconds",
        type=float,
        default=3.0,
        help="How often to rescan for new matching processes (default: 3.0 seconds)",
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

    tracer = PadHttpTracer(str(args.process), Path(args.log_dir), args.rescan_seconds)
    install_signal_handlers(tracer)
    try:
        tracer.start()
    except KeyboardInterrupt:
            tracer.stop()
    except frida.TransportError as exc:
        logging.error("Frida transport error: %s", exc)
        tracer.stop()


if __name__ == "__main__":
    main()
