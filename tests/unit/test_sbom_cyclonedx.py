"""Unit tests for CycloneDX SBOM parsing.

Parsing is pure, so these run against the captured fixture and inline documents:
component extraction, subject resolution, purl-derived ecosystem, de-duplication,
and the load/error paths.
"""

import json
from pathlib import Path

import pytest

from vulnpipe.sbom.cyclonedx import Component, SbomError, load_sbom, parse_cyclonedx

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _fixture() -> dict[str, object]:
    data: dict[str, object] = json.loads(
        (FIXTURES / "sample_cyclonedx.json").read_text(encoding="utf-8")
    )
    return data


def test_parse_fixture_components_and_subject() -> None:
    sbom = parse_cyclonedx(_fixture())
    assert sbom.subject == "acme-webapp"  # metadata.component.name, no version
    # The unnamed component is skipped; the duplicate requests entry is collapsed.
    names = [component.name for component in sbom.components]
    assert names == ["requests", "lodash", "left-pad", "vendored-blob"]


def test_component_ecosystem_and_label() -> None:
    sbom = parse_cyclonedx(_fixture())
    requests = sbom.components[0]
    assert requests.ecosystem == "pypi"
    assert requests.label == "requests 2.19.0"
    # A component with no purl has no ecosystem.
    blob = sbom.components[-1]
    assert blob.purl is None and blob.ecosystem is None
    assert blob.label == "vendored-blob"


def test_ecosystem_none_for_non_purl() -> None:
    assert Component(name="x", purl="not-a-purl").ecosystem is None
    assert Component(name="x").ecosystem is None


def test_subject_falls_back_to_default_without_metadata() -> None:
    sbom = parse_cyclonedx({"components": []}, default_subject="myapp")
    assert sbom.subject == "myapp"
    assert sbom.components == ()


def test_rejects_non_cyclonedx_format() -> None:
    with pytest.raises(SbomError, match="Unsupported SBOM format"):
        parse_cyclonedx({"bomFormat": "SPDX", "components": []})


def test_missing_components_key_is_empty() -> None:
    assert parse_cyclonedx({"bomFormat": "CycloneDX"}).components == ()


def test_dedup_keeps_first_by_purl_then_name_version() -> None:
    payload = {
        "components": [
            {"name": "a", "version": "1.0", "purl": "pkg:pypi/a@1.0"},
            {"name": "a-alias", "version": "1.0", "purl": "pkg:pypi/a@1.0"},  # same purl
            {"name": "b", "version": "1.0"},
            {"name": "b", "version": "1.0"},  # same name+version, no purl
            {"name": "b", "version": "2.0"},  # different version -> kept
        ]
    }
    components = parse_cyclonedx(payload).components
    assert [(c.name, c.version) for c in components] == [("a", "1.0"), ("b", "1.0"), ("b", "2.0")]


def test_load_sbom_reads_file_and_uses_stem_subject(tmp_path: Path) -> None:
    path = tmp_path / "myproject.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}), encoding="utf-8")
    sbom = load_sbom(path)
    assert sbom.subject == "myproject"  # no metadata.component -> file stem


def test_load_sbom_missing_file_raises() -> None:
    with pytest.raises(SbomError, match="not found"):
        load_sbom("does/not/exist.json")


def test_load_sbom_invalid_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(SbomError, match="Failed to read"):
        load_sbom(path)


def test_load_sbom_non_object_root_raises(tmp_path: Path) -> None:
    path = tmp_path / "list.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(SbomError, match="must be a JSON object"):
        load_sbom(path)
