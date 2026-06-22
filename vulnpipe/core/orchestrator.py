"""Pipeline orchestrator.

Drives the stages in order -- intake -> nmap scan -> zap scan -> enrich ->
normalize -> dedup -> false-positive filter -> prioritize -> report -> CI diff ->
gate -- using a bounded thread pool (ZAP scans are heavier, so their concurrency
is capped separately). Refuses to start unless authorization and scope checks in
:mod:`vulnpipe.core.config` pass first.

Implemented in a later phase; see ``docs/ARCHITECTURE.md``.
"""
