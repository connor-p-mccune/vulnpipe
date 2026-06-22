"""Integration smoke tests (skipped unless run with `-m integration`)."""

import shutil

import pytest

pytestmark = pytest.mark.integration


def test_nmap_binary_available() -> None:
    assert shutil.which("nmap") is not None, "nmap binary not found on PATH"
