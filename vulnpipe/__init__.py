"""vulnpipe — modular network + web vulnerability scanning pipeline.

Detection and reporting only: vulnpipe orchestrates existing scanners (Nmap and
OWASP ZAP), normalizes their output into a single :class:`~vulnpipe.core.models.Finding`
model, enriches it with CVSS/CVE/EPSS data, filters false positives, and emits
prioritized reports with a CI gate. It contains no exploit code.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
