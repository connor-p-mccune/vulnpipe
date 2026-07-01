"""Unit tests for webhook notifications (respx-mocked; no real network)."""

import httpx
import pytest
import respx

from vulnpipe.core.models import Finding, Severity
from vulnpipe.notify.webhook import (
    NotifyError,
    build_webhook_payload,
    build_webhook_text,
    post_webhook,
)
from vulnpipe.processing.normalizer import make_finding

WEBHOOK = "https://hooks.example.com/services/T000/B000/XXXX"


def _findings() -> list[Finding]:
    return [
        make_finding(
            source="nmap",
            host="10.0.0.5",
            title="CVE-2021-42013",
            severity=Severity.CRITICAL,
            port=80,
            cve_ids=["CVE-2021-42013"],
            cvss_score=9.8,
            kev=True,
        ),
        make_finding(
            source="zap", host="app.lab.example.com", title="SQL Injection", severity=Severity.HIGH
        ),
    ]


# --------------------------------------------------------------------------- #
# Message building (pure)
# --------------------------------------------------------------------------- #
def test_text_summary_and_kev_line() -> None:
    text = build_webhook_text(_findings())
    assert "*vulnpipe security report* — 2 findings across 2 hosts" in text
    assert "1 known-exploited (KEV)" in text
    assert "*Top findings:*" in text
    assert "[98] critical 10.0.0.5:80 — CVE-2021-42013 (KEV)" in text


def test_text_escapes_slack_special_characters() -> None:
    finding = make_finding(source="zap", host="h", title="A <b> & c", severity=Severity.LOW)
    text = build_webhook_text([finding])
    assert "A &lt;b&gt; &amp; c" in text


def test_no_kev_line_when_none_flagged() -> None:
    finding = make_finding(source="zap", host="h", title="X", severity=Severity.LOW)
    assert "known-exploited" not in build_webhook_text([finding])


def test_payload_wraps_text() -> None:
    payload = build_webhook_payload(_findings())
    assert set(payload) == {"text"}
    assert payload["text"] == build_webhook_text(_findings())


def test_empty_findings_text() -> None:
    text = build_webhook_text([])
    assert "0 findings across 0 hosts" in text
    assert "Top findings" not in text  # no list when there is nothing to show


# --------------------------------------------------------------------------- #
# Posting (respx-mocked)
# --------------------------------------------------------------------------- #
@respx.mock
def test_post_webhook_success_returns_status() -> None:
    route = respx.post(WEBHOOK).mock(return_value=httpx.Response(200, text="ok"))
    status = post_webhook(WEBHOOK, _findings())
    assert status == 200
    sent = route.calls.last.request
    assert b'"text"' in sent.content  # the JSON payload was posted


@respx.mock
def test_post_webhook_non_2xx_raises() -> None:
    respx.post(WEBHOOK).mock(return_value=httpx.Response(500))
    with pytest.raises(NotifyError, match="HTTP 500"):
        post_webhook(WEBHOOK, _findings())


@respx.mock
def test_post_webhook_transport_error_raises() -> None:
    respx.post(WEBHOOK).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(NotifyError, match="failed to post"):
        post_webhook(WEBHOOK, _findings())


@respx.mock
def test_post_webhook_uses_injected_client_without_closing() -> None:
    respx.post(WEBHOOK).mock(return_value=httpx.Response(204))
    with httpx.Client() as client:
        assert post_webhook(WEBHOOK, _findings(), client=client) == 204
        assert not client.is_closed  # an injected client is left open for reuse
