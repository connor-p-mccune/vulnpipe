"""Outbound notifications: post a findings summary to a chat webhook.

Turns a set of findings into a short, human-readable message and posts it to a
Slack-compatible incoming webhook (Slack / Mattermost and similar). This is a
reporting side channel -- it summarizes and notifies, it never scans -- so it lives
apart from the pipeline and is opt-in via the ``vulnpipe notify`` command.

The message builder (:func:`build_webhook_text` / :func:`build_webhook_payload`) is a
pure function and unit-testable without network access; :func:`post_webhook` performs
the single HTTP POST. The webhook URL is a secret (it carries a token) and is resolved
from the environment by the caller, never stored in config or logged.
"""

from vulnpipe.notify.webhook import (
    NotifyError,
    build_webhook_payload,
    build_webhook_text,
    post_webhook,
)

__all__ = [
    "NotifyError",
    "build_webhook_payload",
    "build_webhook_text",
    "post_webhook",
]
