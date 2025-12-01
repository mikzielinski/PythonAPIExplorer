# REST API Call Interceptor

A Python tool to intercept and log all REST API calls (POST/GET) from your computer. Useful for debugging API calls from applications like Power Automate Desktop (PAD) that might be modifying or redirecting requests.

## Features

- Intercepts HTTP/HTTPS GET and POST requests
- Logs request details: URL, headers, query parameters, body
- Supports both HTTP and HTTPS (with certificate setup)
- Two versions available:
  - **Basic version**: Uses only Python standard library
  - **Enhanced version**: Uses mitmproxy for full HTTPS interception

## Installation

### Basic Version (Standard Library Only)
No additional dependencies required! Just Python 3.6+.

### Enhanced Version (Recommended for HTTPS)
```bash
pip install -r requirements.txt
# or
pip install mitmproxy
```

## Usage

### Basic Version (`api_interceptor.py`)

```bash
# Start interceptor on default port 8888
python api_interceptor.py

# Use custom port
python api_interceptor.py --port 8080

# Save logs to file
python api_interceptor.py --log-file api_calls.log

# Save results to JSON on exit
python api_interceptor.py --output results.json
```

### Enhanced Version (`api_interceptor_mitm.py`) - Recommended

```bash
# Start interceptor on default port 8080
python api_interceptor_mitm.py

# Use custom port
python api_interceptor_mitm.py --port 8888

# Save logs and results
python api_interceptor_mitm.py --log-file api_calls.log --output results.json
```

## Setting Up Proxy in Your Application

### For Power Automate Desktop (PAD)

1. **System Proxy Settings** (affects all applications):
   - Windows: Settings → Network & Internet → Proxy
   - Set Manual proxy: `127.0.0.1` port `8888` (or your chosen port)

2. **Application-Specific Proxy**:
   - Some applications allow setting proxy in their configuration
   - Check PAD settings/preferences for proxy configuration

3. **Environment Variables** (if application respects them):
   ```bash
   set HTTP_PROXY=http://127.0.0.1:8888
   set HTTPS_PROXY=http://127.0.0.1:8888
   ```

### For PowerShell/Other Applications

PowerShell respects system proxy settings, so if you set the system proxy, PowerShell will use it automatically.

## HTTPS Interception (Enhanced Version)

For HTTPS interception to work properly with the enhanced version:

1. **Generate mitmproxy certificate** (first run):
   ```bash
   mitmdump --set confdir=~/.mitmproxy
   ```

2. **Install the certificate**:
   - Certificate location: `~/.mitmproxy/mitmproxy-ca-cert.pem` (Linux/Mac)
   - Or `%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.pem` (Windows)
   
3. **Install in system trust store**:
   - **Windows**: Double-click the `.pem` file → Install Certificate → Local Machine → Trusted Root Certification Authorities
   - **Linux**: Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates`
   - **macOS**: Keychain Access → Import → Trust

4. **Alternative**: Some applications allow you to specify a custom CA certificate

## Output Format

The tool logs intercepted requests in a readable format:

```
================================================================================
Intercepted POST Request
URL: https://api.example.com/v1/endpoint
Host: api.example.com:443
Path: /v1/endpoint
Query Parameters: {
  "param1": "value1"
}
Headers:
  content-type: application/json
  authorization: Bearer token123
Body (JSON): {
  "key": "value",
  "data": "example"
}
================================================================================
```

When using `--output`, requests are saved as JSON:

```json
[
  {
    "timestamp": "2024-01-15T10:30:45.123456",
    "method": "POST",
    "url": "https://api.example.com/v1/endpoint",
    "headers": {...},
    "body": "...",
    "content_json": {...}
  }
]
```

## Troubleshooting

### Port Already in Use
If you get "Address already in use" error:
- Use a different port: `--port 9999`
- Or stop the application using that port

### HTTPS Not Intercepted
- Make sure you've installed the mitmproxy CA certificate
- Use the enhanced version (`api_interceptor_mitm.py`)
- Check that your application is using the proxy

### No Requests Showing
- Verify your application is configured to use the proxy
- Check firewall settings
- Ensure the interceptor is running before making API calls
- Try with a simple HTTP request first (not HTTPS)

### Power Automate Desktop Not Using Proxy
- PAD might have its own proxy settings
- Check PAD documentation for proxy configuration
- Try setting system-wide proxy settings
- Some applications bypass system proxy - check PAD settings

## Example Workflow

1. Start the interceptor:
   ```bash
   python api_interceptor_mitm.py --port 8888 --log-file pad_calls.log --output pad_calls.json
   ```

2. Configure PAD to use proxy `127.0.0.1:8888`

3. Run your PAD flow that makes API calls

4. Watch the console for intercepted requests

5. Press Ctrl+C to stop and save results to JSON

6. Compare the intercepted calls with your PowerShell calls to see differences

## License

This tool is provided as-is for debugging and development purposes.
