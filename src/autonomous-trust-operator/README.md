# AutonomousTrust Operator

A PIV (CAC/PIV smartcard) + MFA terminal console (TUI) for a human operator to
**activate/connect** a local AutonomousTrust (AT) node, **discover resources**
on the AT network, and **issue requests** to it.

This is the operator-facing frontend. It runs an AT node in a background thread
and talks to it **only** through the existing `external_control` /
`external_feedback` queues plus a resource-directory feed — it never imports AT
core internals (the Inspector "node-in-a-thread, drain a queue into the
frontend" pattern). The node-side core lives in
`autonomous_trust.core.operator` (in the `autonomous-trust` package).

- **Framework:** [Textual](https://textual.textualize.io/) (async TUI).
- **Second factor:** TOTP (RFC 6238) by default; OIDC / FIDO2 as configured
  alternatives.

## Dependencies

Managed with **conda** (project convention; not pip/venv). The operator's
runtime deps are declared in [`config/cfg/environment.yml`](../../config/cfg/environment.yml):
`pykcs11` (PIV/CAC PKCS#11 binding), `textual` (TUI), `pyotp` (TOTP). The
PKCS#11 test middleware (`softhsm2`, `opensc`) is in
[`config/cfg/devel_environ.yml`](../../config/cfg/devel_environ.yml). The
`pyproject.toml` here mirrors the runtime deps for packaging only.

See `doc/NV059/work/PIV_MFA_OPERATOR_ACCESS_PLAN.md` for the full design and
phasing. This package is scaffolding at P0; screens land in P4/P5.
