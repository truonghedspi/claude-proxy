#!/usr/bin/env python3
"""Small authenticated HTTP/HTTPS forward proxy demo.

The proxy only permits the configured identity in HTTP Basic proxy auth.
For HTTPS it tunnels CONNECT traffic; it does not decrypt or inspect TLS.
"""

from __future__ import annotations

import base64
import http.server
import os
import select
import socket
import socketserver
import sys
from urllib.parse import urlsplit


ALLOWED_EMAIL = os.environ.get("PROXY_ALLOWED_EMAIL", "truong.hn.1994@gmail.com")
PROXY_PASSWORD = os.environ.get("PROXY_PASSWORD")
LISTEN_HOST = os.environ.get("PROXY_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("PROXY_PORT", "8080"))


def authorized(value: str | None) -> bool:
    """Validate proxy credentials without logging the secret."""
    if not value or not value.lower().startswith("basic "):
        return False
    try:
        decoded = base64.b64decode(value[6:].strip(), validate=True).decode("utf-8")
        email, separator, password = decoded.partition(":")
    except (ValueError, UnicodeDecodeError):
        return False
    return (
        bool(separator)
        and email == ALLOWED_EMAIL
        and PROXY_PASSWORD is not None
        and password == PROXY_PASSWORD
    )


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        # Do not print Proxy-Authorization or request bodies.
        sys.stderr.write(f"{self.client_address[0]} - {fmt % args}\n")

    def reject(self) -> None:
        self.send_response(407, "Proxy Authentication Required")
        self.send_header("Proxy-Authenticate", 'Basic realm="demo-proxy"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def handle_one_request(self) -> None:
        if not authorized(self.headers.get("Proxy-Authorization")):
            self.reject()
            self.close_connection = True
            return
        super().handle_one_request()

    def do_CONNECT(self) -> None:
        host, separator, port_text = self.path.rpartition(":")
        if not separator or not host:
            self.send_error(400, "CONNECT must use host:port")
            return
        try:
            port = int(port_text)
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            self.send_error(400, "Invalid port")
            return

        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            self.send_error(502, "Unable to connect upstream")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()
        self.connection.setblocking(False)
        upstream.setblocking(False)
        sockets = [self.connection, upstream]
        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 60)
                if exceptional or not readable:
                    break
                for source in readable:
                    target = upstream if source is self.connection else self.connection
                    data = source.recv(65536)
                    if not data:
                        return
                    target.sendall(data)
        finally:
            upstream.close()

    def do_GET(self) -> None:
        self.forward_http()

    def do_POST(self) -> None:
        self.forward_http()

    def do_PUT(self) -> None:
        self.forward_http()

    def do_DELETE(self) -> None:
        self.forward_http()

    def forward_http(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            self.send_error(400, "Use an absolute HTTP URL")
            return
        if parsed.scheme == "https":
            self.send_error(501, "Use CONNECT for HTTPS")
            return

        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            with socket.create_connection((parsed.hostname, port), timeout=10) as upstream:
                headers = [
                    f"{self.command} {path} HTTP/1.1",
                    f"Host: {parsed.hostname}:{port}" if port != 80 else f"Host: {parsed.hostname}",
                    "Connection: close",
                ]
                for key, value in self.headers.items():
                    if key.lower() not in {"proxy-authorization", "proxy-connection", "connection", "host"}:
                        headers.append(f"{key}: {value}")
                upstream.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if body:
                    upstream.sendall(body)
                while chunk := upstream.recv(65536):
                    self.wfile.write(chunk)
        except OSError:
            self.send_error(502, "Unable to reach upstream")


class ThreadingProxy(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    if not PROXY_PASSWORD:
        raise SystemExit("Set PROXY_PASSWORD before starting the proxy")
    with ThreadingProxy((LISTEN_HOST, LISTEN_PORT), ProxyHandler) as server:
        print(f"Proxy listening on http://{LISTEN_HOST}:{LISTEN_PORT}")
        print(f"Allowed identity: {ALLOWED_EMAIL}")
        server.serve_forever()


if __name__ == "__main__":
    main()
