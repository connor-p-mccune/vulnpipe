"""Unit tests for entry-point plugin discovery (scanners and reporters)."""

from dataclasses import dataclass, field

import pytest

import vulnpipe.plugins as plugins
import vulnpipe.reporting as reporting
from vulnpipe.core.models import Finding
from vulnpipe.plugins import REPORTER_GROUP, SCANNER_GROUP, LoadedPlugin, load_plugins
from vulnpipe.reporting import available_formats, get_reporter
from vulnpipe.reporting.base import BaseReporter
from vulnpipe.scanners import registry
from vulnpipe.scanners.base import BaseScanner
from vulnpipe.scanners.nmap_scanner import NmapScanner
from vulnpipe.scanners.registry import available_scanners, get_scanner


class EchoScanner(BaseScanner):
    """A minimal plugin scanner used as the happy-path fixture."""

    name = "echo"

    def scan(self) -> list[Finding]:
        return []


class NullReporter(BaseReporter):
    """A minimal plugin reporter used as the happy-path fixture."""

    name = "null"

    def render(self, findings: list[Finding]) -> str:
        return ""


class NamelessScanner(BaseScanner):
    """A scanner class that never sets the ``name`` ClassVar."""

    def scan(self) -> list[Finding]:
        return []


def _not_a_class() -> None:
    """An entry point can resolve to anything; a function is not a plugin."""


@dataclass
class _FakeEntryPoint:
    """Stands in for ``importlib.metadata.EntryPoint`` (name/value/load)."""

    name: str
    value: str
    obj: object = None
    error: Exception | None = None

    def load(self) -> object:
        if self.error is not None:
            raise self.error
        return self.obj


@dataclass
class _FakeDistribution:
    """Routes ``entry_points(group=...)`` to per-group fake entry points."""

    scanners: list[_FakeEntryPoint] = field(default_factory=list)
    reporters: list[_FakeEntryPoint] = field(default_factory=list)

    def __call__(self, *, group: str) -> list[_FakeEntryPoint]:
        if group == SCANNER_GROUP:
            return self.scanners
        if group == REPORTER_GROUP:
            return self.reporters
        raise AssertionError(f"unexpected entry-point group {group!r}")


@pytest.fixture(autouse=True)
def _isolated_registries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Snapshot both registries and the loaded-plugin log around every test."""
    monkeypatch.setattr(registry, "_REGISTRY", dict(registry._REGISTRY))
    monkeypatch.setattr(reporting, "_REPORTERS", dict(reporting._REPORTERS))
    monkeypatch.setattr(plugins, "_LOADED", [])


def _install(monkeypatch: pytest.MonkeyPatch, dist: _FakeDistribution) -> None:
    monkeypatch.setattr(plugins, "entry_points", dist)


def test_loads_and_registers_scanner_and_reporter(monkeypatch: pytest.MonkeyPatch) -> None:
    dist = _FakeDistribution(
        scanners=[_FakeEntryPoint("echo", "acme.echo:EchoScanner", obj=EchoScanner)],
        reporters=[_FakeEntryPoint("null", "acme.null:NullReporter", obj=NullReporter)],
    )
    _install(monkeypatch, dist)
    loaded = load_plugins()
    assert loaded == (
        LoadedPlugin(kind="scanner", name="echo", entry_point="acme.echo:EchoScanner"),
        LoadedPlugin(kind="reporter", name="null", entry_point="acme.null:NullReporter"),
    )
    assert get_scanner("echo") is EchoScanner
    assert "echo" in available_scanners()
    assert isinstance(get_reporter("null"), NullReporter)
    assert "null" in available_formats()


def test_broken_plugin_degrades_to_a_warning_and_others_still_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _FakeDistribution(
        scanners=[
            _FakeEntryPoint("broken", "gone.mod:Scanner", error=ImportError("No module 'gone'")),
            _FakeEntryPoint("echo", "acme.echo:EchoScanner", obj=EchoScanner),
        ]
    )
    _install(monkeypatch, dist)
    loaded = load_plugins()
    assert [plugin.name for plugin in loaded] == ["echo"]
    assert "broken" not in available_scanners()


def test_rejects_non_class_wrong_base_and_nameless_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dist = _FakeDistribution(
        scanners=[
            _FakeEntryPoint("a-function", "acme.mod:helper", obj=_not_a_class),
            _FakeEntryPoint("base-itself", "vulnpipe.scanners.base:BaseScanner", obj=BaseScanner),
            _FakeEntryPoint("nameless", "acme.mod:NamelessScanner", obj=NamelessScanner),
            _FakeEntryPoint("wrong-base", "acme.mod:NullReporter", obj=NullReporter),
        ]
    )
    _install(monkeypatch, dist)
    assert load_plugins() == ()


def test_refuses_to_shadow_a_built_in(monkeypatch: pytest.MonkeyPatch) -> None:
    class ImposterScanner(BaseScanner):
        name = "nmap"  # collides with the built-in

        def scan(self) -> list[Finding]:
            return []

    dist = _FakeDistribution(
        scanners=[_FakeEntryPoint("nmap", "acme.imposter:ImposterScanner", obj=ImposterScanner)]
    )
    _install(monkeypatch, dist)
    assert load_plugins() == ()
    assert get_scanner("nmap") is NmapScanner  # the built-in survives


def test_loading_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    dist = _FakeDistribution(
        scanners=[_FakeEntryPoint("echo", "acme.echo:EchoScanner", obj=EchoScanner)]
    )
    _install(monkeypatch, dist)
    first = load_plugins()
    assert [plugin.name for plugin in first] == ["echo"]
    assert load_plugins() == ()  # same class, same name: quietly skipped
    assert [plugin.name for plugin in plugins.loaded_plugins()] == ["echo"]


def test_entry_points_are_processed_in_sorted_name_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ZuluScanner(BaseScanner):
        name = "zulu"

        def scan(self) -> list[Finding]:
            return []

    dist = _FakeDistribution(
        scanners=[
            _FakeEntryPoint("zulu", "acme.z:ZuluScanner", obj=ZuluScanner),
            _FakeEntryPoint("echo", "acme.echo:EchoScanner", obj=EchoScanner),
        ]
    )
    _install(monkeypatch, dist)
    assert [plugin.name for plugin in load_plugins()] == ["echo", "zulu"]


def test_loaded_plugin_label_is_human_readable() -> None:
    plugin = LoadedPlugin(kind="scanner", name="echo", entry_point="acme.echo:EchoScanner")
    assert plugin.label == "scanner 'echo' from acme.echo:EchoScanner"
