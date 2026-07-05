"""A dependency-free, read-only HTTP view over a findings report.

``vulnpipe serve`` exposes an already-computed findings JSON as a small local web
service -- an interactive HTML dashboard at ``/``, a JSON REST API under ``/api``,
Prometheus metrics at ``/metrics``, and a ``/healthz`` probe -- built entirely on
the standard-library :mod:`http.server` (no web framework dependency).

The package splits cleanly for testing: :mod:`vulnpipe.server.routes` is the pure
``path -> Response`` router (socket-free, exhaustively unit-testable), and
:mod:`vulnpipe.server.http_server` is the thin socket adapter that owns the process
lifecycle. It is read-only -- it renders an existing report and never scans, mutates
state, or reads a request body -- so, like ``report`` and ``stats``, it runs outside
the authorization/scope gate.
"""

from vulnpipe.server.http_server import build_handler, create_server, serve_findings
from vulnpipe.server.routes import ROUTES, Response, render_route

__all__ = [
    "ROUTES",
    "Response",
    "build_handler",
    "create_server",
    "render_route",
    "serve_findings",
]
