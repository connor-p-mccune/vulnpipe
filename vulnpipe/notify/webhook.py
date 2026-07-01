"""Post a findings summary to a Slack-compatible incoming webhook.

The message builder is pure (findings in, a ``{"text": ...}`` payload out) and the
poster performs one HTTP POST. Message text uses Slack ``mrkdwn`` conventions and
escapes the characters Slack treats specially (``&``, ``<``, ``>``), so a finding
title can never distort the message. The webhook URL is treated as a secret: the
caller resolves it from the environment and it is never logged.
"""

import logging
from collections.abc import Iterable
from typing import Any

import httpx

from vulnpipe.core.logging import get_logger, log_event
from vulnpipe.core.models import Finding
from vulnpipe.reporting.summary import SEVERITY_DISPLAY_ORDER, summarize

_log = get_logger(__name__)

DEFAULT_TIMEOUT = 10.0
#: How many findings the message lists under "Top findings".
_TOP_N = 5


class NotifyError(Exception):
    """Raised when a webhook notification cannot be delivered."""


def _escape(text: str) -> str:
    """Escape the characters Slack mrkdwn treats specially."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _host_label(finding: Finding) -> str:
    return finding.host if finding.port is None else f"{finding.host}:{finding.port}"


def build_webhook_text(findings: Iterable[Finding]) -> str:
    """Build the Slack ``mrkdwn`` message body summarizing ``findings``."""
    items = list(findings)
    summary = summarize(items)
    kev_count = sum(1 for finding in items if finding.kev)

    hosts = "host" if summary.host_count == 1 else "hosts"
    lines = [
        f"*vulnpipe security report* — {summary.total} findings across "
        f"{summary.host_count} {hosts}"
    ]
    if kev_count:
        lines.append(f":rotating_light: *{kev_count} known-exploited (KEV)*")
    lines.append(
        " · ".join(
            f"{summary.by_severity[severity]} {severity.value}"
            for severity in SEVERITY_DISPLAY_ORDER
        )
    )

    top = sorted(items, key=lambda finding: (-finding.risk_score, finding.fingerprint))[:_TOP_N]
    if top:
        lines.append("")
        lines.append("*Top findings:*")
        for index, finding in enumerate(top, start=1):
            marker = " (KEV)" if finding.kev else ""
            lines.append(
                f"{index}. [{finding.risk_score}] {finding.severity.value} "
                f"{_escape(_host_label(finding))} — {_escape(finding.title)}{marker}"
            )
    return "\n".join(lines)


def build_webhook_payload(findings: Iterable[Finding]) -> dict[str, Any]:
    """Build the JSON payload posted to the webhook (Slack-compatible ``text``)."""
    return {"text": build_webhook_text(findings)}


def post_webhook(
    url: str,
    findings: Iterable[Finding],
    *,
    client: httpx.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> int:
    """POST a findings summary to ``url``; return the HTTP status on success.

    Raises :class:`NotifyError` on a transport failure or a >= 400 response. The URL
    is never logged (it is a secret). An injected ``client`` is used as-is and left
    open; otherwise a client is created and closed here.
    """
    payload = build_webhook_payload(findings)
    owns_client = client is None
    http = client if client is not None else httpx.Client(timeout=timeout)
    try:
        response = http.post(url, json=payload)
    except httpx.HTTPError as exc:
        raise NotifyError(f"failed to post to webhook: {exc}") from exc
    finally:
        if owns_client:
            http.close()
    if response.status_code >= 400:
        raise NotifyError(f"webhook returned HTTP {response.status_code}")
    log_event(_log, logging.INFO, "webhook notification sent", status=response.status_code)
    return response.status_code


__all__ = [
    "DEFAULT_TIMEOUT",
    "NotifyError",
    "build_webhook_payload",
    "build_webhook_text",
    "post_webhook",
]
