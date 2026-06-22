"""CVSS parsing and scoring helpers.

Parses CVSS vectors and computes base scores using the ``cvss`` library
(``from cvss import CVSS3``), mapping the result onto
:meth:`vulnpipe.core.models.Severity.from_cvss_score`. Never fabricates a vector
or score: if none is available the field stays unknown.

Implemented in a later phase.
"""
