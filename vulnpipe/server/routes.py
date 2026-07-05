"""Pure request routing for the read-only findings dashboard / API.

Maps a request path onto a :class:`Response` (status, content type, body) using the
existing reporters, so the HTTP layer in :mod:`vulnpipe.server.http_server` stays a
thin, socket-only adapter and every route is unit-testable without opening a socket.

Read-only by design: a route renders an already-computed findings snapshot and
never scans, mutates state, or consumes a request body -- so, like ``report`` /
``stats``, the surface needs no authorization or scope. Deterministic for fixed
findings, since it renders through the same deterministic reporters.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from vulnpipe import __version__
from vulnpipe.core.models import Finding
from vulnpipe.reporting import (
    get_reporter,
    remediation_to_payload,
    render_prometheus,
    stats_to_payload,
)

#: Content types the dashboard serves. The Prometheus one carries the exposition
#: format version node_exporter / a Pushgateway expect.
CONTENT_TYPE_HTML = "text/html; charset=utf-8"
CONTENT_TYPE_JSON = "application/json; charset=utf-8"
CONTENT_TYPE_PROMETHEUS = "text/plain; version=0.0.4; charset=utf-8"


@dataclass(frozen=True)
class Response:
    """An HTTP response the router produced: status code, content type, and body."""

    status: int
    content_type: str
    body: str


#: Every route the dashboard serves, mapped to a one-line description. Drives the
#: ``/api`` index and the 404 body, and documents the surface for tests.
ROUTES: dict[str, str] = {
    "/": "Interactive HTML findings report.",
    "/api": "This route index (JSON).",
    "/api/findings": "Canonical findings report envelope (JSON).",
    "/api/summary": "Dashboard summary: severity, OWASP, top risks, worst hosts (JSON).",
    "/api/remediation": "Ranked remediation plan -- fix these first (JSON).",
    "/metrics": "Prometheus text-exposition metrics.",
    "/healthz": "Liveness / readiness probe (JSON).",
}


def _json(payload: Any, *, status: int = 200) -> Response:
    """A JSON :class:`Response` with the payload rendered deterministically."""
    body = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    return Response(status=status, content_type=CONTENT_TYPE_JSON, body=body)


def _not_found(path: str) -> Response:
    """A 404 JSON body that names the path and lists the known routes."""
    return _json({"error": "not found", "path": path, "routes": sorted(ROUTES)}, status=404)


def render_route(path: str, findings: Sequence[Finding]) -> Response:
    """Render the :class:`Response` for request ``path`` over a findings snapshot.

    The query string is ignored and a trailing slash is tolerated (``/api/`` and
    ``/api`` are the same route), so the mapping stays a pure function of the route.
    An unknown path yields a 404 whose body lists the available routes.
    """
    route = urlsplit(path).path.rstrip("/") or "/"
    items = list(findings)
    if route == "/":
        return Response(200, CONTENT_TYPE_HTML, get_reporter("html").render(items))
    if route == "/api":
        return _json({"routes": ROUTES})
    if route == "/api/findings":
        return Response(200, CONTENT_TYPE_JSON, get_reporter("json").render(items))
    if route == "/api/summary":
        return _json(stats_to_payload(items))
    if route == "/api/remediation":
        return _json(remediation_to_payload(items))
    if route == "/metrics":
        return Response(200, CONTENT_TYPE_PROMETHEUS, render_prometheus(items))
    if route == "/healthz":
        return _json({"status": "ok", "version": __version__, "findings": len(items)})
    return _not_found(route)


__all__ = [
    "CONTENT_TYPE_HTML",
    "CONTENT_TYPE_JSON",
    "CONTENT_TYPE_PROMETHEUS",
    "ROUTES",
    "Response",
    "render_route",
]
