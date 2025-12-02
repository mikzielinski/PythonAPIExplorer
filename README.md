# PAD HTTP Tracing Toolkit

Trace every outbound call Power Automate Desktop (PAD) issues without touching proxies or TLS interception. This repository ships two complementary approaches:

1. **Frida-based inline tracer** (`trace_pad_http_full.py`) — hooks WinHTTP inside `PAD.Desktop.exe`, records headers + full request/response bodies, and writes each call to `pad_full_http_logs/CALL_<n>.json`.
2. **Mitmproxy-based proxy** (`pad_rest_inspector.py`) — stand up a local intercepting proxy, auto-configure Windows proxy & certificates, and log traffic at the socket boundary. Useful when you need to capture other tools besides PAD.

## Quick Start (recommended Frida tracer)

1. **Install dependencies**
   ```bat
   install_pad_trace.bat
   ```
   - Creates `.pad-trace-venv` next to the scripts.
   - Upgrades `pip` and installs packages from `requirements.txt` (`frida`, `mitmproxy`).
   - Re-run anytime to update dependencies.

2. **Run the tracer**
   ```bat
   start_pad_trace.bat
   ```
   - Automatically uses `.pad-trace-venv` if it exists, otherwise falls back to `%PYTHON%` or the system `python`.
   - Hooks into `PAD.Desktop.exe` (change with `--process <name-or-pid>` if needed).
   - Captured calls are written under `pad_full_http_logs/` with complete metadata.

3. **Inspect logs**
   Each JSON file contains:
   ```json
   {
     "id": "CALL_1",
     "timestamp": "2025-12-01T10:22:54.911Z",
     "url": "https://api.example.com/invoice",
     "method": "POST",
     "headers": ["Content-Type: application/json", "Authorization: Bearer ..."],
     "request_body": {"text": "{...}", "base64": "...", "size_bytes": 512, "encoding": "utf-8"},
     "response_body": {...}
   }
   ```
   Compare these files directly against your PowerShell calls to spot PAD rewrites.

### Tracer CLI options

```text
python trace_pad_http_full.py --help
  --process PAD.Desktop.exe   Process name or PID to attach to.
  --log-dir pad_full_http_logs  Directory for JSON output.
  --verbose                   Enable DEBUG logging.
```

## Optional: Mitmproxy capture

If you prefer a network proxy, run:

```bash
python pad_rest_inspector.py --listen-port 8899 --verbose
```

The script will:
- Generate/ensure a mitmproxy root CA in `~/.mitmproxy`.
- Temporarily configure Windows proxy settings & trust store (disable with `--no-auto-config`).
- Log every GET/POST (configurable via `--methods`) to `pad_http_log.jsonl`.

Point PAD (or system-wide `HTTP[S]_PROXY`) to `http://127.0.0.1:8899` and re-run the failing flow.

## Requirements

- Windows 10/11 machine running Power Automate Desktop.
- Python 3.9+ installed and on `PATH` (for the installer script).
- [Frida](https://frida.re) installed automatically via `requirements.txt`.
- Admin rights are not required unless corporate policies restrict certificate installation.

## Troubleshooting

- **`Process 'PAD.Desktop.exe' not found`**: Start PAD first or pass `--process <pid>` to the tracer.
- **Frida errors about driver/service**: Ensure your antivirus isn’t blocking Frida; updating to the latest release usually helps.
- **Binary payloads**: When UTF-8 decoding fails, bodies are stored base64-encoded with `"encoding": "binary"`.
- **Proxy conflicts**: Use `pad_rest_inspector.py --no-auto-config` or skip the proxy tool entirely (the Frida tracer doesn’t touch system settings).

## Repository Layout

```
trace_pad_http_full.py   # Main Frida tracer
start_pad_trace.bat      # Launch helper (prefers .pad-trace-venv)
install_pad_trace.bat    # Creates venv + installs deps
pad_rest_inspector.py    # Mitmproxy-based proxy logger
requirements.txt         # Python dependencies (frida, mitmproxy)
README.md                # This guide
```

Feel free to adapt the scripts to trace other WinHTTP clients by changing the process name or expanding the Frida hooks.
