"""Unit tests for the rich-backed structured logger."""

import logging
from io import StringIO

from rich.console import Console

from vulnpipe.core.logging import configure_logging, get_logger, log_event


class _Capture(logging.Handler):
    """Minimal handler that records formatted messages for assertions."""

    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def test_get_logger_namespacing() -> None:
    assert get_logger().name == "vulnpipe"
    assert get_logger("vulnpipe").name == "vulnpipe"
    assert get_logger("vulnpipe.core.config").name == "vulnpipe.core.config"
    assert get_logger("scanners.nmap").name == "vulnpipe.scanners.nmap"


def test_configure_logging_is_idempotent() -> None:
    logger = configure_logging()
    configure_logging()
    assert len(logger.handlers) == 1


def test_configure_logging_writes_message() -> None:
    buffer = StringIO()
    logger = configure_logging(logging.INFO, console=Console(file=buffer, width=100))
    logger.info("hello world")
    assert "hello world" in buffer.getvalue()


def test_log_event_appends_sorted_fields() -> None:
    logger = logging.getLogger("vulnpipe.tests.event")
    logger.propagate = False
    capture = _Capture()
    logger.addHandler(capture)
    logger.setLevel(logging.INFO)

    log_event(logger, logging.INFO, "scan started", port=443, host="10.0.0.5")
    log_event(logger, logging.INFO, "no fields")

    assert capture.messages == ["scan started host='10.0.0.5' port=443", "no fields"]
