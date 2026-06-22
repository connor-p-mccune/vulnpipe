"""Unit tests for the scanner registry."""

import pytest

from vulnpipe.core.models import Finding
from vulnpipe.scanners.base import BaseScanner
from vulnpipe.scanners.registry import available_scanners, get_scanner, register


def test_register_and_lookup() -> None:
    @register
    class _DummyScanner(BaseScanner):
        name = "dummy-test"

        def scan(self) -> list[Finding]:
            return []

    assert get_scanner("dummy-test") is _DummyScanner
    assert "dummy-test" in available_scanners()


def test_get_scanner_unknown_raises() -> None:
    with pytest.raises(KeyError):
        get_scanner("does-not-exist")
