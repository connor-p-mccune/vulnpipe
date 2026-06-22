"""False-positive filtering.

Drops findings matching an allowlist (by fingerprint / plugin / host) or below a
configured confidence threshold (using ``Finding.confidence``). Pure function.

Implemented in a later phase.
"""
