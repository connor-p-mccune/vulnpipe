# Example reports

These are sample vulnpipe reports so you can see the output shape before running a
scan of your own.

They are rendered from the project's committed **test fixtures** — a captured Nmap
`vulners` XML scan and a sample ZAP `core.alerts` payload — so they are fully
deterministic and contain only **synthetic lab data** (RFC 1918 addresses and
`example.com` / `example.net` hosts). They are not the output of a real scan
against a real system.

| File | What it is |
| --- | --- |
| [`sample-report.json`](sample-report.json) | The canonical, lossless JSON report — exactly what `vulnpipe scan` writes to `results/latest.json` and what `report` / `diff` / `baseline` read back. |
| [`sample-report.html`](sample-report.html) | The human-readable HTML report (summary, inline SVG severity chart, per-host breakdown, and a sortable findings table). Open it in a browser. |

The sample contains 15 findings across 4 hosts (1 critical, 5 high, 2 medium,
2 low, 5 informational), shown in vulnpipe's prioritized order.

## Regenerating

From a checkout with the dev dependencies installed:

```python
import json
from pathlib import Path

from vulnpipe.scanners.nmap_scanner import parse_nmap_xml
from vulnpipe.scanners.zap_scanner import normalize_alerts
from vulnpipe.processing import deduplicate, prioritize
from vulnpipe.reporting import get_reporter

fix = Path("tests/fixtures")
nmap = parse_nmap_xml(fix.joinpath("nmap_vulners.xml").read_text(encoding="utf-8"))
zap = normalize_alerts(
    json.loads(fix.joinpath("sample_zap_alerts.json").read_text(encoding="utf-8"))["alerts"]
)
findings = prioritize(deduplicate([*nmap, *zap]))

out = Path("examples")
out.joinpath("sample-report.json").write_text(get_reporter("json").render(findings), encoding="utf-8")
out.joinpath("sample-report.html").write_text(get_reporter("html").render(findings), encoding="utf-8")
```
