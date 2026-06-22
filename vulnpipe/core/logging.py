"""Rich-backed structured logging for vulnpipe.

Every module logs through :func:`get_logger` instead of using ``print`` so that
output is consistent, leveled, and routed through a single Rich handler. The
:func:`log_event` helper provides lightweight structured (key/value) logging.
"""

import logging
from typing import Any

from rich.console import Console
from rich.logging import RichHandler

_LOGGER_NAME = "vulnpipe"
_MESSAGE_FORMAT = "%(message)s"
_DATE_FORMAT = "[%X]"
_configured = False


def configure_logging(
    level: int | str = logging.INFO,
    *,
    console: Console | None = None,
    show_path: bool = False,
) -> logging.Logger:
    """Configure the base ``vulnpipe`` logger with a single Rich handler.

    Idempotent: repeated calls replace the handler and level rather than stacking
    handlers. Returns the configured base logger.
    """
    global _configured

    logger = logging.getLogger(_LOGGER_NAME)
    handler = RichHandler(
        console=console if console is not None else Console(stderr=True),
        rich_tracebacks=True,
        markup=False,
        show_time=True,
        show_level=True,
        show_path=show_path,
    )
    handler.setFormatter(logging.Formatter(_MESSAGE_FORMAT, datefmt=_DATE_FORMAT))
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    _configured = True
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger within the ``vulnpipe`` namespace, configuring on first use.

    Passing ``__name__`` (e.g. ``vulnpipe.core.config``) returns that module
    logger as a child of the base logger; any other ``name`` is nested beneath
    ``vulnpipe`` so it inherits the shared handler.
    """
    if not _configured:
        configure_logging()
    if not name or name == _LOGGER_NAME:
        return logging.getLogger(_LOGGER_NAME)
    if name.startswith(f"{_LOGGER_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{_LOGGER_NAME}.{name}")


def log_event(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    """Emit a structured log line of the form ``event key=value ...``.

    The event name stays human readable while contextual key/value pairs are
    appended in sorted order so log lines are deterministic and greppable.
    """
    if not fields:
        logger.log(level, "%s", event)
        return
    detail = " ".join(f"{key}={value!r}" for key, value in sorted(fields.items()))
    logger.log(level, "%s %s", event, detail)
