"""Unit tests for the ZAP scanner.

Fixture-driven normalization (a captured ``core.alerts`` payload -> findings) and
the value-helper tests run with no network; the ``scan()`` flow tests drive a
mocked ZAP client (no real daemon). No test in this module talks to ZAP.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from vulnpipe.core.config import Config, OutOfScopeError, Scope, Target, ZapConfig
from vulnpipe.core.models import Confidence, Finding, Severity
from vulnpipe.scanners import zap_scanner
from vulnpipe.scanners.zap_scanner import (
    SOURCE,
    ZapScanner,
    _alert_host_port,
    _clean_cwe,
    _confidence_from_zap,
    _harvest_cves,
    _parse_percent,
    _severity_from_risk,
    _split_references,
    alert_to_finding,
    normalize_alerts,
    select_web_targets,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _load_alerts(name: str) -> list[dict[str, Any]]:
    data = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    alerts = data["alerts"]
    assert isinstance(alerts, list)
    return alerts


def _by_plugin(findings: list[Finding]) -> dict[str, Finding]:
    return {f.plugin_id: f for f in findings if f.plugin_id is not None}


def _config(
    *,
    scope: Scope | None = None,
    targets: list[Target] | None = None,
    zap: ZapConfig | None = None,
) -> Config:
    return Config(
        scope=scope or Scope(urls=["https://app.lab.example.com"]),
        targets=targets or [Target(urls=["https://app.lab.example.com"])],
        zap=zap or ZapConfig(),
    )


# --------------------------------------------------------------------------- #
# Parsing the captured fixture into findings
# --------------------------------------------------------------------------- #
def test_normalize_fixture_shape_and_ordering() -> None:
    findings = normalize_alerts(_load_alerts("sample_zap_alerts.json"))
    assert len(findings) == 6
    # Deterministic ordering: host, then port, then plugin id.
    assert [(f.host, f.port, f.plugin_id) for f in findings] == [
        ("app.lab.example.com", 80, "90022"),
        ("app.lab.example.com", 443, "10003"),
        ("app.lab.example.com", 443, "10096"),
        ("app.lab.example.com", 443, "40012"),
        ("app.lab.example.com", 8443, "40018"),
        ("vpn.corp.example.net", 443, "10054"),
    ]
    assert {f.source for f in findings} == {"zap"}
    # Fingerprints are unique and stable across re-parses.
    assert len({f.fingerprint for f in findings}) == len(findings)
    again = normalize_alerts(_load_alerts("sample_zap_alerts.json"))
    assert [f.fingerprint for f in findings] == [f.fingerprint for f in again]


def test_normalize_scope_filters_out_of_scope_url() -> None:
    scoped = normalize_alerts(
        _load_alerts("sample_zap_alerts.json"), scope=Scope(hosts=["*.lab.example.com"])
    )
    assert len(scoped) == 5
    assert {f.host for f in scoped} == {"app.lab.example.com"}


def test_xss_finding_mapping() -> None:
    xss = _by_plugin(normalize_alerts(_load_alerts("sample_zap_alerts.json")))["40012"]
    assert xss.severity is Severity.HIGH
    assert xss.confidence is Confidence.MEDIUM
    assert xss.port == 443 and xss.protocol == "tcp"
    assert xss.cwe_ids == ("CWE-79",)
    assert xss.cve_ids == ()
    # CVSS is left unknown for the enrichment stage; ZAP does not supply it.
    assert xss.cvss_score is None and xss.cvss_vector is None
    assert xss.evidence == "<script>alert(1)</script>"  # scanner proof retained
    assert xss.references == ("https://owasp.org/www-community/attacks/xss/",)
    assert xss.metadata["url"] == "https://app.lab.example.com/search?q=test"
    assert xss.metadata["param"] == "q"
    assert xss.metadata["method"] == "GET"
    # Detection-only: the raw attack payload ZAP injected is not carried.
    assert "attack" not in xss.metadata


def test_sqli_finding_explicit_port_and_multiline_refs() -> None:
    sqli = _by_plugin(normalize_alerts(_load_alerts("sample_zap_alerts.json")))["40018"]
    assert sqli.severity is Severity.HIGH
    assert sqli.confidence is Confidence.HIGH
    assert sqli.port == 8443  # explicit port from the URL
    assert sqli.cwe_ids == ("CWE-89",)
    assert sqli.references == (
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    )
    assert sqli.evidence is None  # empty evidence -> None


def test_js_library_harvests_cves_and_drops_missing_cwe() -> None:
    js = _by_plugin(normalize_alerts(_load_alerts("sample_zap_alerts.json")))["10003"]
    assert js.severity is Severity.MEDIUM
    assert js.confidence is Confidence.HIGH
    assert js.cwe_ids == ()  # cweid "-1" -> no CWE
    # CVE ids harvested from tag keys; the non-CVE OWASP tag is ignored.
    assert js.cve_ids == ("CVE-2019-11358", "CVE-2020-11022")


def test_http_alert_defaults_to_port_80() -> None:
    err = _by_plugin(normalize_alerts(_load_alerts("sample_zap_alerts.json")))["90022"]
    assert err.port == 80 and err.protocol == "tcp"
    assert err.severity is Severity.LOW


def test_informational_alert_with_empty_reference() -> None:
    ts = _by_plugin(normalize_alerts(_load_alerts("sample_zap_alerts.json")))["10096"]
    assert ts.severity is Severity.INFORMATIONAL
    assert ts.confidence is Confidence.LOW
    assert ts.cwe_ids == ("CWE-200",)
    assert ts.references == ()


def test_source_constant() -> None:
    assert SOURCE == "zap"
    assert ZapScanner.name == "zap"


# --------------------------------------------------------------------------- #
# Value helpers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("alert", "expected"),
    [
        ({"risk": "High"}, Severity.HIGH),
        ({"risk": "Medium"}, Severity.MEDIUM),
        ({"risk": "Low"}, Severity.LOW),
        ({"risk": "Informational"}, Severity.INFORMATIONAL),
        ({"risk": "informational"}, Severity.INFORMATIONAL),
        ({"riskcode": "3"}, Severity.HIGH),  # numeric fallback
        ({"riskcode": "0"}, Severity.INFORMATIONAL),
        ({"risk": "bogus", "riskcode": "2"}, Severity.MEDIUM),  # bad label -> code
        ({"risk": "nonsense"}, Severity.INFORMATIONAL),  # unknown -> lowest
        ({"riskcode": "9"}, Severity.INFORMATIONAL),  # unmapped code -> lowest
        ({}, Severity.INFORMATIONAL),
    ],
)
def test_severity_from_risk(alert: dict[str, Any], expected: Severity) -> None:
    assert _severity_from_risk(alert) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("False Positive", Confidence.FALSE_POSITIVE),
        ("Low", Confidence.LOW),
        ("Medium", Confidence.MEDIUM),
        ("High", Confidence.HIGH),
        ("Confirmed", Confidence.CONFIRMED),
        ("User Confirmed", Confidence.CONFIRMED),
        ("0", Confidence.FALSE_POSITIVE),
        ("1", Confidence.LOW),
        ("2", Confidence.MEDIUM),
        ("3", Confidence.HIGH),
        ("4", Confidence.CONFIRMED),
        ("bogus", None),
        ("", None),
        (None, None),
    ],
)
def test_confidence_from_zap(value: Any, expected: Confidence | None) -> None:
    assert _confidence_from_zap(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("79", "CWE-79"),
        (79, "CWE-79"),
        ("1275", "CWE-1275"),
        ("-1", None),  # ZAP's "no CWE" sentinel
        ("0", None),
        ("abc", None),
        ("", None),
        (None, None),
    ],
)
def test_clean_cwe(value: Any, expected: str | None) -> None:
    assert _clean_cwe(value) == expected


def test_split_references() -> None:
    assert _split_references("a\nb\n\n c ") == ["a", "b", "c"]
    assert _split_references("solo") == ["solo"]
    assert _split_references("") == []
    assert _split_references(None) == []


def test_harvest_cves_from_tags_ignores_non_cve() -> None:
    alert = {"tags": {"CVE-2020-11022": "u", "OWASP_2021_A06": "u"}}
    assert _harvest_cves(alert) == ("CVE-2020-11022",)


def test_harvest_cves_from_reference_text_and_dedupes() -> None:
    alert = {"reference": "see https://x/CVE-2014-6271 and CVE-2014-6271 again"}
    assert _harvest_cves(alert) == ("CVE-2014-6271",)


def test_harvest_cves_explicit_field_normalizes_case() -> None:
    assert _harvest_cves({"cveid": "cve-2021-44228"}) == ("CVE-2021-44228",)


def test_harvest_cves_handles_missing_and_wrong_types() -> None:
    assert _harvest_cves({}) == ()
    assert _harvest_cves({"tags": "not-a-map", "reference": 123}) == ()


def test_harvest_cves_ignores_non_string_tag_entries() -> None:
    alert = {"tags": {"CVE-2020-11022": ["not", "a", "string"], 123: "x"}}
    assert _harvest_cves(alert) == ("CVE-2020-11022",)


@pytest.mark.parametrize(
    ("url", "host", "port"),
    [
        ("https://h.example.com/p", "h.example.com", 443),
        ("http://h.example.com/p", "h.example.com", 80),
        ("https://h.example.com:8443/x", "h.example.com", 8443),
        ("http://h.example.com:8080", "h.example.com", 8080),
        ("ftp://h.example.com/x", "h.example.com", None),  # unknown scheme -> no default
        ("not-a-url", None, None),
        ("", None, None),
        (None, None, None),
    ],
)
def test_alert_host_port(url: str | None, host: str | None, port: int | None) -> None:
    assert _alert_host_port(url) == (host, port)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("100", 100),
        ("0", 0),
        ("55", 55),
        (100, 100),
        ("  100 ", 100),
        (None, 0),
        ("", 0),
        ("abc", 0),
    ],
)
def test_parse_percent(value: Any, expected: int) -> None:
    assert _parse_percent(value) == expected


def test_alert_to_finding_missing_url_returns_none() -> None:
    assert alert_to_finding({"name": "x"}) is None
    assert alert_to_finding({"name": "x", "url": ""}) is None


def test_alert_to_finding_missing_title_returns_none() -> None:
    assert alert_to_finding({"url": "https://app.lab.example.com/"}) is None


def test_alert_to_finding_out_of_scope_returns_none() -> None:
    scope = Scope(hosts=["10.0.0.0/24"])
    alert = {"url": "https://app.lab.example.com/", "name": "x"}
    assert alert_to_finding(alert, scope=scope) is None


def test_alert_to_finding_falls_back_to_alert_label() -> None:
    finding = alert_to_finding({"url": "https://app.lab.example.com/", "alert": "Legacy Name"})
    assert finding is not None
    assert finding.title == "Legacy Name"


# --------------------------------------------------------------------------- #
# Target selection
# --------------------------------------------------------------------------- #
def test_select_web_targets_dedupes_and_skips_host_only() -> None:
    cfg = Config(
        scope=Scope(hosts=["10.0.0.0/24"], urls=["https://app.lab.example.com"]),
        targets=[
            Target(name="net", host="10.0.0.5"),
            Target(name="web", urls=["https://app.lab.example.com/a"]),
            Target(name="dup", urls=["https://app.lab.example.com/a"]),
        ],
    )
    assert select_web_targets(cfg) == ["https://app.lab.example.com/a"]


def test_select_web_targets_rejects_out_of_scope_url() -> None:
    cfg = Config(
        scope=Scope(urls=["https://app.lab.example.com"]),
        targets=[Target(urls=["https://evil.example.com/x"])],
    )
    with pytest.raises(OutOfScopeError):
        select_web_targets(cfg)


# --------------------------------------------------------------------------- #
# Polling helper
# --------------------------------------------------------------------------- #
def test_poll_completes_immediately() -> None:
    assert zap_scanner._poll_until_complete(lambda: "100", timeout=10, label="spider") is True


def test_poll_times_out_without_sleeping(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_sleep(_seconds: float) -> None:
        raise AssertionError("poll should not sleep when already past the deadline")

    monkeypatch.setattr(zap_scanner.time, "sleep", _no_sleep)
    assert zap_scanner._poll_until_complete(lambda: "10", timeout=0, label="active scan") is False


def test_poll_sleeps_then_completes(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(zap_scanner.time, "sleep", slept.append)
    statuses = iter(["0", "50", "100"])
    done = zap_scanner._poll_until_complete(lambda: next(statuses), timeout=100, label="spider")
    assert done is True
    assert slept == [zap_scanner._POLL_INTERVAL_SECONDS, zap_scanner._POLL_INTERVAL_SECONDS]


# --------------------------------------------------------------------------- #
# ZapScanner.scan() with the ZAP client mocked (no real daemon)
# --------------------------------------------------------------------------- #
class _FakeComponent:
    """Stand-in for ``zap.spider`` / ``zap.ascan`` (``scan`` + ``status``)."""

    def __init__(self, parent: "_FakeZap", label: str, status: str = "100") -> None:
        self._parent = parent
        self._label = label
        self._status = status

    def scan(self, *args: Any, **kwargs: Any) -> str:
        self._parent.calls.append((f"{self._label}.scan", args, kwargs))
        return "0"

    def status(self, scanid: Any = None) -> str:
        return self._status


class _FakeZap:
    """Minimal stand-in for the ``zapv2.ZAPv2`` client used to drive ``scan()``."""

    def __init__(
        self,
        *,
        apikey: str | None = None,
        proxies: Any = None,
        alerts: list[dict[str, Any]] | None = None,
        alerts_error: Exception | None = None,
        context_error: Exception | None = None,
    ) -> None:
        self.apikey = apikey
        self.proxies = proxies
        self._alerts = alerts if alerts is not None else []
        self._alerts_error = alerts_error
        self._context_error = context_error
        self.calls: list[tuple[Any, ...]] = []
        self.spider = _FakeComponent(self, "spider")
        self.ascan = _FakeComponent(self, "ascan")
        self.core = self
        self.context = self

    def alerts(self, baseurl: Any = None, **_kwargs: Any) -> list[dict[str, Any]]:
        self.calls.append(("alerts", baseurl))
        if self._alerts_error is not None:
            raise self._alerts_error
        return list(self._alerts)

    def new_context(self, contextname: Any, apikey: str = "") -> str:
        self.calls.append(("new_context", contextname))
        if self._context_error is not None:
            raise self._context_error
        return "1"

    def include_in_context(self, contextname: Any, regex: Any, apikey: str = "") -> str:
        self.calls.append(("include_in_context", contextname, regex))
        return "OK"


def _patch_zap(monkeypatch: pytest.MonkeyPatch, **fake_kwargs: Any) -> dict[str, _FakeZap]:
    created: dict[str, _FakeZap] = {}

    def ctor(apikey: str | None = None, proxies: Any = None) -> _FakeZap:
        zap = _FakeZap(apikey=apikey, proxies=proxies, **fake_kwargs)
        created["zap"] = zap
        return zap

    monkeypatch.setattr(zap_scanner, "ZAPv2", ctor)
    return created


def _forbid_zap(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("ZAPv2 must not be constructed in this scenario")

    monkeypatch.setattr(zap_scanner, "ZAPv2", boom)


def _web_config(zap: ZapConfig | None = None) -> Config:
    return _config(
        scope=Scope(hosts=["*.lab.example.com"]),
        targets=[Target(urls=["https://app.lab.example.com"])],
        zap=zap,
    )


def test_scan_drives_zap_and_normalizes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZAP_API_KEY", "secret-key")
    created = _patch_zap(monkeypatch, alerts=_load_alerts("sample_zap_alerts.json"))
    findings = ZapScanner(_web_config()).scan()
    # The out-of-scope corp.example.net alert is filtered; the rest normalize.
    assert len(findings) == 5
    assert {f.source for f in findings} == {"zap"}
    zap = created["zap"]
    assert zap.apikey == "secret-key"  # key resolved from the environment
    kinds = [call[0] for call in zap.calls]
    assert "spider.scan" in kinds
    assert "ascan.scan" in kinds
    assert ("alerts", "https://app.lab.example.com") in zap.calls


def test_scan_disabled_skips_client(monkeypatch: pytest.MonkeyPatch) -> None:
    _forbid_zap(monkeypatch)
    assert ZapScanner(_web_config(zap=ZapConfig(enabled=False))).scan() == []


def test_scan_no_web_targets_skips_client(monkeypatch: pytest.MonkeyPatch) -> None:
    _forbid_zap(monkeypatch)
    cfg = Config(scope=Scope(hosts=["10.0.0.0/24"]), targets=[Target(host="10.0.0.5")])
    assert ZapScanner(cfg).scan() == []


def test_scan_out_of_scope_url_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _forbid_zap(monkeypatch)
    cfg = Config(
        scope=Scope(urls=["https://app.lab.example.com"]),
        targets=[Target(urls=["https://evil.example.com/x"])],
    )
    with pytest.raises(OutOfScopeError):
        ZapScanner(cfg).scan()


def test_scan_url_failure_degrades_to_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_zap(monkeypatch, alerts_error=RuntimeError("alert pull failed"))
    assert ZapScanner(_web_config()).scan() == []


def test_scan_context_failure_still_scans(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_zap(
        monkeypatch,
        alerts=_load_alerts("sample_zap_alerts.json"),
        context_error=RuntimeError("context exists"),
    )
    # Context setup failing must not abort the scan.
    assert len(ZapScanner(_web_config()).scan()) == 5


def test_scan_client_init_failure_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def ctor(apikey: str | None = None, proxies: Any = None) -> Any:
        raise RuntimeError("daemon unreachable")

    monkeypatch.setattr(zap_scanner, "ZAPv2", ctor)
    assert ZapScanner(_web_config()).scan() == []


def test_scan_with_spider_disabled_skips_spider(monkeypatch: pytest.MonkeyPatch) -> None:
    created = _patch_zap(monkeypatch, alerts=_load_alerts("sample_zap_alerts.json"))
    findings = ZapScanner(_web_config(zap=ZapConfig(spider_max_duration_minutes=0))).scan()
    assert len(findings) == 5
    kinds = [call[0] for call in created["zap"].calls]
    assert "spider.scan" not in kinds  # spider skipped
    assert "ascan.scan" in kinds  # active scan still runs


class _CoreOnly:
    """A client exposing only ``core.alerts``, returning a canned value."""

    def __init__(self, value: Any) -> None:
        self.core = self
        self._value = value

    def alerts(self, baseurl: Any = None, **_kwargs: Any) -> Any:
        return self._value


def test_collect_alerts_tolerates_malformed_responses() -> None:
    scanner = ZapScanner(_web_config())
    url = "https://app.lab.example.com"
    # A non-list response (e.g. a ZAP error string) yields no alerts.
    assert scanner._collect_alerts(_CoreOnly("ZAP error"), url) == []
    # Non-dict entries within the list are skipped.
    assert scanner._collect_alerts(_CoreOnly([{"a": 1}, "garbage"]), url) == [{"a": 1}]
