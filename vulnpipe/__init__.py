"""vulnpipe — modular network + web vulnerability scanning pipeline.

Detection and reporting only: vulnpipe orchestrates existing scanners (Nmap, OWASP
ZAP, and Nuclei), normalizes their output into a single
:class:`~vulnpipe.core.models.Finding` model, enriches it with CVSS/CVE/EPSS data,
filters false positives, and emits prioritized reports (with a ranked remediation
plan) and a CI gate. It contains no exploit code.
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
