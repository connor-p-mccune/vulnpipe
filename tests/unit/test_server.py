"""Unit tests for the read-only findings dashboard / API server.

The pure router (:func:`render_route`) is tested directly, socket-free. The socket
adapter is exercised over an ephemeral **loopback** port (no external network, no
scanning) so the header/verb handling is covered end to end, and the CLI wiring is
driven in-process with the blocking server stubbed out.
"""

import http.client
import json
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vulnpipe.cli import main as cli_main
from vulnpipe.cli.main import app
from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.json_reporter import JsonReporter
from vulnpipe.server import http_server
from vulnpipe.server.http_server import _is_loopback, _serve_forever, create_server, serve_findings
from vulnpipe.server.routes import (
    CONTENT_TYPE_HTML,
    CONTENT_TYPE_JSON,
    CONTENT_TYPE_PROMETHEUS,
    ROUTES,
    render_route,
)

runner = CliRunner()


def _findings() -> list[Finding]:
    return [
        make_finding(
            source="nmap",
            host="10.0.0.5",
            port=80,
            title="Apache httpd 2.4.49 path traversal",
            severity=Severity.CRITICAL,
            plugin_id="vulners",
            cve_ids=["CVE-2021-42013"],
            cvss_score=9.8,
            kev=True,
            solution="Upgrade Apache httpd to 2.4.51 or later.",
        ),
        make_finding(
            source="zap",
            host="app.lab.example.com",
            port=443,
            title="Cross Site Scripting (Reflected)",
            severity=Severity.HIGH,
            plugin_id="40012",
            cwe_ids=["CWE-79"],
        ),
    ]


# --------------------------------------------------------------------------- #
# Pure router
# --------------------------------------------------------------------------- #
def test_index_serves_the_html_report() -> None:
    response = render_route("/", _findings())
    assert response.status == 200
    assert response.content_type == CONTENT_TYPE_HTML
    assert "<html" in response.body.lower()


def test_api_index_lists_the_routes() -> None:
    response = render_route("/api", _findings())
    assert response.status == 200
    assert response.content_type == CONTENT_TYPE_JSON
    assert json.loads(response.body)["routes"] == ROUTES


def test_findings_endpoint_returns_the_canonical_envelope() -> None:
    response = render_route("/api/findings", _findings())
    payload = json.loads(response.body)
    assert payload["schema_version"] == "1.0"
    assert payload["summary"]["total"] == 2
    assert len(payload["findings"]) == 2


def test_summary_endpoint_returns_the_dashboard_payload() -> None:
    payload = json.loads(render_route("/api/summary", _findings()).body)
    assert payload["total"] == 2
    assert payload["kev"] == 1
    assert payload["by_severity"]["critical"] == 1


def test_remediation_endpoint_returns_the_ranked_plan() -> None:
    payload = json.loads(render_route("/api/remediation", _findings()).body)
    assert payload["actions"]
    assert payload["summary"]["findings"] == 2


def test_metrics_endpoint_returns_prometheus_text() -> None:
    response = render_route("/metrics", _findings())
    assert response.content_type == CONTENT_TYPE_PROMETHEUS
    assert "vulnpipe_findings_total" in response.body
    assert "vulnpipe_known_exploited_total 1" in response.body


def test_healthz_reports_ok_and_the_finding_count() -> None:
    payload = json.loads(render_route("/healthz", _findings()).body)
    assert payload["status"] == "ok"
    assert payload["findings"] == 2
    assert "version" in payload


def test_trailing_slash_and_query_string_are_ignored() -> None:
    assert render_route("/api/findings/", _findings()).status == 200
    assert render_route("/healthz?probe=1", _findings()).status == 200
    # An empty path normalizes to the index.
    assert render_route("", _findings()).content_type == CONTENT_TYPE_HTML


def test_unknown_route_is_a_404_listing_the_routes() -> None:
    response = render_route("/nope", _findings())
    assert response.status == 404
    payload = json.loads(response.body)
    assert payload["error"] == "not found"
    assert payload["path"] == "/nope"
    assert "/api/findings" in payload["routes"]


def test_router_is_deterministic() -> None:
    findings = _findings()
    assert render_route("/api/findings", findings) == render_route("/api/findings", findings)


# --------------------------------------------------------------------------- #
# Socket adapter (loopback only)
# --------------------------------------------------------------------------- #
@pytest.fixture
def live_server() -> Iterator[tuple[str, int]]:
    """Run the dashboard on an ephemeral loopback port for the duration of a test."""
    server = create_server(_findings(), host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[0], server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(
    address: tuple[str, int], method: str, path: str
) -> tuple[int, http.client.HTTPMessage, bytes]:
    conn = http.client.HTTPConnection(address[0], address[1], timeout=5)
    try:
        conn.request(method, path)
        response = conn.getresponse()
        return response.status, response.headers, response.read()
    finally:
        conn.close()


def test_live_get_serves_findings(live_server: tuple[str, int]) -> None:
    status, headers, body = _request(live_server, "GET", "/api/findings")
    assert status == 200
    assert headers["Content-Type"] == CONTENT_TYPE_JSON
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "no-store"
    assert json.loads(body)["summary"]["total"] == 2


def test_live_head_returns_headers_without_a_body(live_server: tuple[str, int]) -> None:
    status, headers, body = _request(live_server, "HEAD", "/healthz")
    assert status == 200
    assert int(headers["Content-Length"]) > 0
    assert body == b""


def test_live_unknown_route_is_404(live_server: tuple[str, int]) -> None:
    status, _headers, body = _request(live_server, "GET", "/missing")
    assert status == 404
    assert json.loads(body)["error"] == "not found"


def test_live_mutating_verb_is_405(live_server: tuple[str, int]) -> None:
    status, headers, _body = _request(live_server, "POST", "/api/findings")
    assert status == 405
    assert headers["Allow"] == "GET, HEAD"


# --------------------------------------------------------------------------- #
# Lifecycle helpers
# --------------------------------------------------------------------------- #
class _FakeServer:
    def __init__(self, *, interrupt: bool = False) -> None:
        self.server_address = ("0.0.0.0", 8000)
        self.closed = False
        self.served = False
        self._interrupt = interrupt

    def serve_forever(self) -> None:
        self.served = True
        if self._interrupt:
            raise KeyboardInterrupt

    def server_close(self) -> None:
        self.closed = True


def test_serve_forever_closes_the_socket_on_keyboard_interrupt() -> None:
    server = _FakeServer(interrupt=True)
    _serve_forever(server)  # type: ignore[arg-type]
    assert server.served is True
    assert server.closed is True


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("::1", True),
        ("localhost", True),
        ("", True),
        ("0.0.0.0", False),
        ("10.0.0.5", False),
        ("example.com", False),
    ],
)
def test_is_loopback(host: str, expected: bool) -> None:
    assert _is_loopback(host) is expected


def test_serve_findings_warns_on_non_loopback_bind(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeServer()
    events: list[tuple[int, str]] = []
    monkeypatch.setattr(http_server, "create_server", lambda *a, **k: fake)
    monkeypatch.setattr(http_server, "_serve_forever", lambda server: None)
    monkeypatch.setattr(
        http_server, "log_event", lambda _log, level, event, **k: events.append((level, event))
    )
    serve_findings([], host="0.0.0.0", port=8000)
    assert any("non-loopback" in event for _level, event in events)


def test_serve_findings_runs_the_created_server(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeServer()
    ran: list[object] = []
    monkeypatch.setattr(http_server, "create_server", lambda *a, **k: fake)
    monkeypatch.setattr(http_server, "_serve_forever", lambda server: ran.append(server))
    serve_findings([], host="127.0.0.1", port=8000)
    assert ran == [fake]


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #
def _write_findings(tmp_path: Path) -> Path:
    path = tmp_path / "findings.json"
    path.write_text(JsonReporter().render(_findings()), encoding="utf-8")
    return path


def test_serve_command_loads_findings_and_starts_the_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[int, str, int]] = []

    def fake_serve(findings: list[Finding], *, host: str, port: int) -> None:
        calls.append((len(findings), host, port))

    monkeypatch.setattr(cli_main, "serve_findings", fake_serve)
    result = runner.invoke(
        app, ["serve", "--input", str(_write_findings(tmp_path)), "--port", "9101"]
    )
    assert result.exit_code == 0
    assert calls == [(2, "127.0.0.1", 9101)]


def test_serve_command_reports_a_bind_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(findings: list[Finding], *, host: str, port: int) -> None:
        raise OSError("address already in use")

    monkeypatch.setattr(cli_main, "serve_findings", boom)
    result = runner.invoke(app, ["serve", "--input", str(_write_findings(tmp_path))])
    assert result.exit_code == 1


def test_serve_command_rejects_unreadable_findings(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["serve", "--input", str(bad)])
    assert result.exit_code == 2
