# PAD HTTP Tracing Toolkit

Trace every outbound call Power Automate Desktop (PAD) issues without touching proxies or TLS interception. This repository ships two complementary approaches:

1. **Frida-based inline tracer** (`trace_pad_http_full.py`) — hooks WinHTTP/WinINet inside every matching PAD worker (auto-rescans for child processes), records headers + full request/response bodies, and writes each call to `pad_full_http_logs/<process>_pid###_CALL_<n>.json`.
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
   - Default `--process auto` scans for the common PAD binaries **plus** helper processes such as `powershell.exe`, `pwsh.exe`, `cmd.exe`, `PAD.Console.Host.exe`, and `msedgewebview2.exe`, and keeps rescanning every few seconds. Add extra names if your flows launch other executables that perform HTTP calls.
   - Hooks both `winhttp.dll` and `wininet.dll` (wide + ANSI exports) inside every attached process so you capture PAD, CMD, PowerShell, or any helper without TLS proxying.
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
    "request_body": {
      "text": "{\"invoice\":123,...}",
      "base64": "eyJpbnZvaWNlIjoxMjMsLi4ufQ==",
      "size_bytes": 265,
      "encoding": "utf-8",
      "truncated": false
    },
    "response_body": {
      "text": "{\"status\":\"OK\",\"id\":\"9876\"}",
      "base64": "eyJzdGF0dXMiOiJPSyIsImlkIjoiOTg3NiJ9",
      "size_bytes": 64,
      "encoding": "utf-8",
      "truncated": false
    }
   }
   ```
   Compare these files directly against your PowerShell calls to spot PAD rewrites.

### Tracer CLI options

```text
python trace_pad_http_full.py --help
  --process auto,powershell.exe   Comma-separated names/PIDs ('auto' scans common PAD binaries).
  --log-dir pad_full_http_logs    Directory for JSON output.
  --rescan-seconds 3.0            How often to look for new matching processes.
  --verbose                       Enable DEBUG logging.
```

## Optional: Mitmproxy capture

If you prefer a network proxy, run:

```bash
start_pad_proxy.bat --listen-port 8899 --verbose
```

While it runs (preferably from an elevated terminal so the WinHTTP step succeeds), the script will:
- Generate/ensure a mitmproxy root CA in `~/.mitmproxy`.
- Install that CA into the current user’s Trusted Root store.
- Force both WinINET **and WinHTTP** to proxy through `127.0.0.1:8899` (restored automatically when you stop the script).
- Set `HTTP_PROXY` / `HTTPS_PROXY` environment variables so newly launched consoles inherit the proxy.
- Log every GET/POST (configurable via `--methods`) to `pad_http_log.jsonl`.

No manual proxy tweaking is required—every HTTP(S) client (PAD, CMD, PowerShell, services) is routed through mitmproxy until you stop the script. When the batch file exits it also runs a best-effort cleanup (`netsh winhttp reset proxy`, disable WinINET proxy, clear `HTTP[S]_PROXY`) to guarantee proxies are off even if the Python process was interrupted. All captured details (headers + bodies up to `--body-bytes`) are appended to `pad_http_log.jsonl`.

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
