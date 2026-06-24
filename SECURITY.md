# Security policy

## Authorized use only

vulnpipe drives real network and web vulnerability scanners. Active scanning is
intrusive and, run against systems you do not own or are not permitted to test,
is very likely illegal.

**Only scan systems you own or have explicit, written permission to test.**

The tool is built to enforce this rather than rely on good intentions:

- every scan requires the operator to pass `--authorized`, acknowledging they are
  permitted to test every in-scope target;
- nothing outside the configured `scope` allowlist is ever scanned — an
  out-of-scope target is a hard error, not a warning;
- vulnpipe is **detection and reporting only**. It orchestrates existing scanners
  and normalizes their findings for remediation. It does not contain, generate, or
  emit exploit payloads, code-execution chains, or malware, and the ZAP integration
  intentionally does not carry raw attack vectors onto findings.

These guardrails are non-negotiable; please do not file requests or pull requests
that weaken or bypass them.

## Reporting a vulnerability in vulnpipe

If you discover a security issue in vulnpipe itself (for example, a way to make it
scan outside its configured scope, or to leak a credential resolved from the
environment), please report it privately rather than opening a public issue.

- Use the repository's **"Report a vulnerability"** workflow under the *Security*
  tab (GitHub private vulnerability reporting), or contact the maintainers
  privately.
- Include the version or commit, a description of the issue, and the minimal steps
  or configuration needed to reproduce it.
- Please give the maintainers a reasonable window to investigate and ship a fix
  before any public disclosure.

We aim to acknowledge a report within a few business days and to keep you updated
as we work toward a fix.

## Supported versions

vulnpipe is pre-1.0 (`0.x`); security fixes are applied to the latest released
version on the default branch. Pin a specific version for reproducible runs and
upgrade to pick up fixes.

## Handling secrets

vulnpipe never reads credentials or API keys from committed files. Secrets
(`ZAP_API_KEY`, `NVD_API_KEY`, and any authenticated-scan credentials) are
referenced by environment-variable *name* from the config and resolved at scan
time. Keep them in the environment or a gitignored `.env`, never in the repository.
If you believe a secret has been committed, rotate it immediately.
