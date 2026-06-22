"""Pytest configuration: skip integration tests unless explicitly selected.

Integration tests carry ``@pytest.mark.integration`` and need real scanners or
network access. They are skipped during a plain ``pytest`` run and execute only
when a marker expression is given (e.g. ``pytest -m integration``).
"""

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("markexpr"):
        return  # the user gave -m <expr>; respect their selection
    skip_integration = pytest.mark.skip(reason="integration test (run with: pytest -m integration)")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)
