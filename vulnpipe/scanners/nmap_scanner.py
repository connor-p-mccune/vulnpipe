"""Nmap scanner integration (network layer).

Invokes the ``nmap`` binary via ``subprocess.run`` with an argument list and XML
to stdout (``-oX -``), then parses it with ``python-libnmap``. Extracts per host:
open ports, service name, product/version, and OS guess, and parses
``vulners``/``vuln`` NSE output into CVE-tagged findings. Subprocess calls always
pass an argument list -- never ``shell=True`` with interpolated target input.

Implemented in a later phase; see ``docs/ARCHITECTURE.md``.
"""
