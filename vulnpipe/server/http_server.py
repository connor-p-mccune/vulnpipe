"""Standard-library socket adapter for the read-only findings dashboard / API.

A thin :mod:`http.server` wrapper around the pure router in
:mod:`vulnpipe.server.routes`: it owns an immutable snapshot of the findings and
turns each ``GET`` / ``HEAD`` into a :class:`~vulnpipe.server.routes.Response`. All
request semantics live in the router, so this module only handles sockets, response
headers, and the process lifecycle -- there is no web-framework dependency.

Bound to loopback (``127.0.0.1``) by default; binding to a non-loopback address
publishes the report on the network and is warned about. The server is strictly
read-only (it never scans and reads no request body), so mutating verbs get a
``405`` and the whole surface runs outside the authorization gate, like ``report``.
"""

import ipaddress
import logging
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from vulnpipe import __version__
from vulnpipe.core.logging import get_logger, log_event
from vulnpipe.core.models import Finding
from vulnpipe.server.routes import Response, render_route

_log = get_logger(__name__)

#: Verbs the read-only dashboard answers; everything else gets a 405 with this Allow.
_ALLOWED_METHODS = "GET, HEAD"


def _is_loopback(host: str) -> bool:
    """Whether ``host`` refers to the loopback interface (so binding stays private)."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.strip().lower() in {"localhost", ""}


def build_handler(findings: Sequence[Finding]) -> type[BaseHTTPRequestHandler]:
    """Build a request-handler class serving an immutable snapshot of ``findings``.

    The snapshot is captured once at build time, so concurrent requests always see a
    consistent, read-only view; the handler delegates every route decision to
    :func:`~vulnpipe.server.routes.render_route`.
    """
    snapshot: tuple[Finding, ...] = tuple(findings)

    class _DashboardHandler(BaseHTTPRequestHandler):
        server_version = f"vulnpipe/{__version__}"
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            self._respond(render_route(self.path, snapshot))

        def do_HEAD(self) -> None:
            self._respond(render_route(self.path, snapshot), head=True)

        def _respond(self, response: Response, *, head: bool = False) -> None:
            body = response.body.encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(body)))
            # Defensive headers: the payload is not markup to be sniffed, and a
            # findings snapshot should never be cached by an intermediary.
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def _method_not_allowed(self) -> None:
            self.send_response(405)
            self.send_header("Allow", _ALLOWED_METHODS)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_POST = _method_not_allowed
        do_PUT = _method_not_allowed
        do_DELETE = _method_not_allowed
        do_PATCH = _method_not_allowed

        def log_message(self, format: str, *args: Any) -> None:
            # Route the stdlib access log through vulnpipe's logger at debug level
            # instead of writing to stderr directly.
            message = format % args if args else format
            log_event(_log, logging.DEBUG, "dashboard request", request=message)

    return _DashboardHandler


def create_server(
    findings: Sequence[Finding], *, host: str = "127.0.0.1", port: int = 8000
) -> HTTPServer:
    """Create (but do not start) an :class:`HTTPServer` serving ``findings``.

    Exposed separately from :func:`serve_findings` so tests can bind an ephemeral
    port (``port=0``) and drive the server without blocking on ``serve_forever``.
    """
    return HTTPServer((host, port), build_handler(findings))


def _serve_forever(server: HTTPServer) -> None:
    """Run ``server`` until interrupted, then close its socket cleanly."""
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log_event(_log, logging.INFO, "shutting down findings dashboard")
    finally:
        server.server_close()


def serve_findings(
    findings: Sequence[Finding], *, host: str = "127.0.0.1", port: int = 8000
) -> None:
    """Serve ``findings`` over HTTP until interrupted (Ctrl-C).

    Binds ``host``/``port`` (loopback by default), logs the URL, and blocks. A
    non-loopback bind is honored but warned about, since it publishes the report to
    anything that can reach the address.
    """
    server = create_server(findings, host=host, port=port)
    address = server.server_address
    bound_port = address[1] if isinstance(address, tuple) else port
    display_host = host or "127.0.0.1"
    if not _is_loopback(host):
        log_event(
            _log,
            logging.WARNING,
            "binding to a non-loopback address; the findings report will be reachable "
            "on the network",
            host=host,
        )
    log_event(
        _log,
        logging.INFO,
        "serving findings dashboard (Ctrl-C to stop)",
        url=f"http://{display_host}:{bound_port}",
        findings=len(findings),
    )
    _serve_forever(server)


__all__ = [
    "build_handler",
    "create_server",
    "serve_findings",
]
