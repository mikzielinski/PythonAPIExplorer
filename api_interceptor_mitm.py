#!/usr/bin/env python3
"""
REST API Call Interceptor using mitmproxy
Enhanced version with full HTTPS interception support.
Requires: pip install mitmproxy
"""

import json
import argparse
from datetime import datetime
from typing import Dict, Any, Optional
import sys

try:
    from mitmproxy import http
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.options import Options
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False
    print("ERROR: mitmproxy is not installed. Install it with: pip install mitmproxy")
    sys.exit(1)


class APIInterceptorAddon:
    def __init__(self, log_file: Optional[str] = None, verbose: bool = True):
        self.log_file = log_file
        self.verbose = verbose
        self.intercepted_requests = []
    
    def log(self, message: str, level: str = "INFO"):
        """Log messages to console and optionally to file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}"
        
        if self.verbose:
            print(log_message)
        
        if self.log_file:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_message + '\n')
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Called when a request is intercepted"""
        request = flow.request
        method = request.method
        url = request.pretty_url
        
        # Only log GET and POST (and other common REST methods)
        if method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
            self.log_intercepted_request(flow)
            
            # Store request info
            request_info = {
                'timestamp': datetime.now().isoformat(),
                'method': method,
                'url': url,
                'scheme': request.scheme,
                'host': request.host,
                'port': request.port,
                'path': request.path,
                'query': dict(request.query),
                'headers': dict(request.headers),
                'content': request.content.decode('utf-8', errors='ignore') if request.content else '',
            }
            
            # Try to parse as JSON
            if request.content:
                try:
                    request_info['content_json'] = json.loads(request.content.decode('utf-8'))
                except:
                    pass
            
            self.intercepted_requests.append(request_info)
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Called when a response is received"""
        # Optionally log responses too
        if self.verbose and flow.request.method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
            status_code = flow.response.status_code
            self.log(f"Response for {flow.request.method} {flow.request.pretty_url}: {status_code}")
    
    def log_intercepted_request(self, flow: http.HTTPFlow):
        """Log intercepted request in a readable format"""
        request = flow.request
        method = request.method
        url = request.pretty_url
        
        self.log("=" * 80)
        self.log(f"Intercepted {method} Request")
        self.log(f"URL: {url}")
        self.log(f"Host: {request.host}:{request.port}")
        self.log(f"Path: {request.path}")
        
        if request.query:
            self.log(f"Query Parameters: {json.dumps(dict(request.query), indent=2)}")
        
        self.log("Headers:")
        for key, value in request.headers.items():
            display_value = value if len(str(value)) < 200 else str(value)[:200] + "..."
            self.log(f"  {key}: {display_value}")
        
        if request.content:
            content_str = request.content.decode('utf-8', errors='ignore')
            try:
                content_json = json.loads(content_str)
                self.log(f"Body (JSON): {json.dumps(content_json, indent=2)}")
            except:
                display_body = content_str if len(content_str) < 500 else content_str[:500] + "..."
                self.log(f"Body: {display_body}")
        
        self.log("=" * 80)
    
    def save_results(self, filename: str):
        """Save intercepted requests to JSON file"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.intercepted_requests, f, indent=2)
        self.log(f"Saved {len(self.intercepted_requests)} intercepted requests to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description='Intercept and log REST API calls using mitmproxy (supports HTTPS)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start interceptor on default port 8080
  python api_interceptor_mitm.py

  # Use custom port
  python api_interceptor_mitm.py --port 8888

  # Save logs to file
  python api_interceptor_mitm.py --log-file api_calls.log

  # Save results to JSON on exit
  python api_interceptor_mitm.py --output results.json

IMPORTANT: For HTTPS interception to work:
  1. Install mitmproxy certificate: mitmdump --set confdir=~/.mitmproxy
  2. Export certificate: mitmproxy --set confdir=~/.mitmproxy
  3. Install certificate in your system/browser trust store
  4. Or use the certificate from ~/.mitmproxy/mitmproxy-ca-cert.pem
        """
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=8080,
        help='Port to listen on (default: 8080)'
    )
    
    parser.add_argument(
        '--log-file', '-l',
        type=str,
        default=None,
        help='File to write log messages to'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default=None,
        help='JSON file to save intercepted requests (saved on exit with Ctrl+C)'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress console output'
    )
    
    args = parser.parse_args()
    
    if not MITMPROXY_AVAILABLE:
        print("ERROR: mitmproxy is required. Install with: pip install mitmproxy")
        sys.exit(1)
    
    addon = APIInterceptorAddon(
        log_file=args.log_file,
        verbose=not args.quiet
    )
    
    # Create mitmproxy options
    opts = Options(listen_port=args.port)
    
    # Create master with our addon
    master = DumpMaster(opts)
    master.addons.add(addon)
    
    print("=" * 80)
    print(f"API Interceptor (mitmproxy) started on port {args.port}")
    print("=" * 80)
    print("To use this proxy:")
    print(f"  1. Configure your application to use HTTP proxy: 127.0.0.1:{args.port}")
    print(f"  2. For Power Automate Desktop, set proxy in system settings")
    print(f"  3. For HTTPS to work, install mitmproxy CA certificate")
    print(f"  4. All GET/POST requests will be logged here")
    print("=" * 80)
    print("Press Ctrl+C to stop and save results")
    print("=" * 80)
    
    try:
        master.run()
    except KeyboardInterrupt:
        print("\n")
        if args.output:
            addon.save_results(args.output)
        print(f"Total requests intercepted: {len(addon.intercepted_requests)}")
        sys.exit(0)


if __name__ == '__main__':
    main()
