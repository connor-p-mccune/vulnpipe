"""Scanner integrations (Nmap, ZAP, Nuclei) and the scanner registry.

Importing this package imports the concrete scanner modules so their
``@register`` decorators run and they become discoverable via the registry.
"""

from vulnpipe.scanners import (  # noqa: F401  (register scanners)
    nmap_scanner,
    nuclei_scanner,
    zap_scanner,
)
