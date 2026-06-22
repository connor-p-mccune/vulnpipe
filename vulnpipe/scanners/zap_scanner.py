"""OWASP ZAP scanner integration (web layer).

Connects to a running ZAP daemon over its API (``from zapv2 import ZAPv2``) and
drives the spider + active scan only -- it never launches exploits. Flow per URL:
select/create a context, spider, wait, active scan, poll ``ascan.status`` to 100,
then pull ``core.alerts`` and map them to findings (ZAP risk -> Severity, plus
confidence and CWE references). Only scans in-scope web services.

Implemented in a later phase; see ``docs/ARCHITECTURE.md``.
"""
