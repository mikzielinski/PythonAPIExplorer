#!/usr/bin/env python3
"""
REST API Call Interceptor
Intercepts and logs all HTTP/HTTPS POST/GET requests from your computer.
Useful for debugging API calls from applications like Power Automate Desktop.
"""

import socket
import ssl
import threading
import json
import argparse
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import sys
from typing import Optional, Dict, Any


class APIInterceptor:
    def __init__(self, port: int = 8888, log_file: Optional[str] = None, verbose: bool = True):
        self.port = port
        self.log_file = log_file
        self.verbose = verbose
        self.running = False
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
    
    def parse_http_request(self, data: bytes) -> Dict[str, Any]:
        """Parse HTTP request from raw bytes"""
        try:
            request_str = data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            
            if not lines:
                return {}
            
            # Parse request line
            request_line = lines[0].split()
            if len(request_line) < 2:
                return {}
            
            method = request_line[0]
            full_path = request_line[1]
            
            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if not line:
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Parse body
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
            
            # Parse URL
            parsed_url = urlparse(full_path)
            query_params = parse_qs(parsed_url.query)
            
            return {
                'method': method,
                'path': full_path,
                'url': parsed_url.path,
                'query_params': {k: v[0] if len(v) == 1 else v for k, v in query_params.items()},
                'headers': headers,
                'body': body,
                'raw_request': request_str
            }
        except Exception as e:
            self.log(f"Error parsing request: {e}", "ERROR")
            return {}
    
    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle individual client connection"""
        try:
            # Receive request
            request_data = client_socket.recv(4096)
            
            if not request_data:
                return
            
            # Parse request
            request_info = self.parse_http_request(request_data)
            
            if not request_info or 'method' not in request_info:
                # Not an HTTP request, might be CONNECT for HTTPS
                if b'CONNECT' in request_data:
                    self.handle_https_connect(client_socket, request_data, address)
                return
            
            method = request_info['method']
            url = request_info.get('path', '')
            
            # Only log GET and POST requests
            if method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                self.log_intercepted_request(request_info, address)
                self.intercepted_requests.append({
                    'timestamp': datetime.now().isoformat(),
                    'client': f"{address[0]}:{address[1]}",
                    **request_info
                })
            
            # Forward request to actual server (if needed)
            # For now, we'll just log and close
            
        except Exception as e:
            self.log(f"Error handling client {address}: {e}", "ERROR")
        finally:
            client_socket.close()
    
    def handle_https_connect(self, client_socket: socket.socket, request_data: bytes, address: tuple):
        """Handle HTTPS CONNECT request"""
        try:
            request_str = request_data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            connect_line = lines[0]
            
            if 'CONNECT' in connect_line:
                parts = connect_line.split()
                if len(parts) >= 2:
                    target = parts[1]
                    host, port = target.split(':') if ':' in target else (target, '443')
                    
                    self.log(f"HTTPS CONNECT request to {target} from {address[0]}:{address[1]}", "HTTPS")
                    
                    # Store HTTPS connection info
                    self.intercepted_requests.append({
                        'timestamp': datetime.now().isoformat(),
                        'client': f"{address[0]}:{address[1]}",
                        'method': 'CONNECT',
                        'target': target,
                        'host': host,
                        'port': port,
                        'protocol': 'HTTPS'
                    })
                    
                    # Send 200 Connection established
                    response = b'HTTP/1.1 200 Connection Established\r\n\r\n'
                    client_socket.send(response)
                    
                    # Now tunnel the connection
                    self.tunnel_https_connection(client_socket, host, int(port))
        except Exception as e:
            self.log(f"Error handling HTTPS CONNECT: {e}", "ERROR")
    
    def tunnel_https_connection(self, client_socket: socket.socket, host: str, port: int):
        """Tunnel HTTPS connection and try to intercept"""
        try:
            # Connect to target server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)
            server_socket.connect((host, port))
            
            # Wrap in SSL
            context = ssl.create_default_context()
            server_ssl = context.wrap_socket(server_socket, server_hostname=host)
            
            # Log the HTTPS connection
            self.log(f"Tunneling HTTPS connection to {host}:{port}", "HTTPS")
            
            # For now, just tunnel without deep inspection
            # (Deep HTTPS inspection would require certificate management)
            threading.Thread(
                target=self._tunnel_data,
                args=(client_socket, server_ssl),
                daemon=True
            ).start()
            
            threading.Thread(
                target=self._tunnel_data,
                args=(server_ssl, client_socket),
                daemon=True
            ).start()
            
        except Exception as e:
            self.log(f"Error tunneling HTTPS: {e}", "ERROR")
            client_socket.close()
    
    def _tunnel_data(self, source: socket.socket, destination: socket.socket):
        """Tunnel data between two sockets"""
        try:
            while True:
                data = source.recv(4096)
                if not data:
                    break
                destination.send(data)
        except:
            pass
        finally:
            try:
                source.close()
                destination.close()
            except:
                pass
    
    def log_intercepted_request(self, request_info: Dict[str, Any], address: tuple):
        """Log intercepted request in a readable format"""
        method = request_info.get('method', 'UNKNOWN')
        url = request_info.get('path', '')
        headers = request_info.get('headers', {})
        body = request_info.get('body', '')
        query_params = request_info.get('query_params', {})
        
        self.log("=" * 80)
        self.log(f"Intercepted {method} Request from {address[0]}:{address[1]}")
        self.log(f"URL: {url}")
        
        if query_params:
            self.log(f"Query Parameters: {json.dumps(query_params, indent=2)}")
        
        self.log("Headers:")
        for key, value in headers.items():
            # Truncate very long header values
            display_value = value if len(str(value)) < 200 else str(value)[:200] + "..."
            self.log(f"  {key}: {display_value}")
        
        if body:
            # Try to parse as JSON for better display
            try:
                body_json = json.loads(body)
                self.log(f"Body (JSON): {json.dumps(body_json, indent=2)}")
            except:
                # Not JSON, display as-is (truncate if too long)
                display_body = body if len(body) < 500 else body[:500] + "..."
                self.log(f"Body: {display_body}")
        
        self.log("=" * 80)
    
    def start(self):
        """Start the proxy server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind(('0.0.0.0', self.port))
            server_socket.listen(5)
            self.running = True
            
            self.log(f"API Interceptor started on port {self.port}")
            self.log("=" * 80)
            self.log("To use this proxy:")
            self.log(f"  1. Configure your application to use HTTP proxy: 127.0.0.1:{self.port}")
            self.log(f"  2. For Power Automate Desktop, set proxy in system settings or app config")
            self.log(f"  3. All GET/POST requests will be logged here")
            self.log("=" * 80)
            
            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    thread.start()
                except Exception as e:
                    if self.running:
                        self.log(f"Error accepting connection: {e}", "ERROR")
        
        except OSError as e:
            if "Address already in use" in str(e):
                self.log(f"ERROR: Port {self.port} is already in use. Try a different port.", "ERROR")
            else:
                self.log(f"ERROR: {e}", "ERROR")
            sys.exit(1)
        except KeyboardInterrupt:
            self.log("\nShutting down...")
        finally:
            server_socket.close()
            self.running = False
    
    def save_results(self, filename: str):
        """Save intercepted requests to JSON file"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.intercepted_requests, f, indent=2)
        self.log(f"Saved {len(self.intercepted_requests)} intercepted requests to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description='Intercept and log REST API calls (POST/GET) from your computer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start interceptor on default port 8888
  python api_interceptor.py

  # Use custom port
  python api_interceptor.py --port 8080

  # Save logs to file
  python api_interceptor.py --log-file api_calls.log

  # Save results to JSON
  python api_interceptor.py --output results.json
        """
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=8888,
        help='Port to listen on (default: 8888)'
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
        help='Suppress console output (only log to file if --log-file is set)'
    )
    
    args = parser.parse_args()
    
    interceptor = APIInterceptor(
        port=args.port,
        log_file=args.log_file,
        verbose=not args.quiet
    )
    
    try:
        interceptor.start()
    except KeyboardInterrupt:
        print("\n")
        if args.output:
            interceptor.save_results(args.output)
        print(f"Total requests intercepted: {len(interceptor.intercepted_requests)}")
        sys.exit(0)


if __name__ == '__main__':
    main()
