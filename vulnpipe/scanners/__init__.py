"""Scanner integrations (Nmap, ZAP) and the scanner registry.

Importing this package imports the concrete scanner modules so their
``@register`` decorators run and they become discoverable via the registry.
"""

from vulnpipe.scanners import nmap_scanner  # noqa: F401  (registers NmapScanner)
