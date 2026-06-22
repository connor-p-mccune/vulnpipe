"""ZAP authentication contexts.

Builds ZAP context configurations for form-based, header/JWT (bearer token), and
script-based auth, with logged-in/logged-out indicators and session management so
the active scan stays authenticated. Credentials resolve from the environment via
:func:`vulnpipe.core.config.resolve_secret` -- never inline.

Implemented in a later phase.
"""
