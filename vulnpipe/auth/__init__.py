"""Authenticated-scanning contexts for ZAP (form / header-JWT / script).

:func:`build_auth_context` resolves a target's auth config (with credentials from
the environment) into a ready-to-apply context; :func:`apply_auth_context` attaches
it to a ZAP context. The ZAP scanner calls both when a target defines an ``auth``
block.
"""

from vulnpipe.auth.auth_contexts import (
    FormAuthContext,
    HeaderAuthContext,
    ScriptAuthContext,
    ZapAuthContext,
    apply_auth_context,
    build_auth_context,
)

__all__ = [
    "FormAuthContext",
    "HeaderAuthContext",
    "ScriptAuthContext",
    "ZapAuthContext",
    "apply_auth_context",
    "build_auth_context",
]
