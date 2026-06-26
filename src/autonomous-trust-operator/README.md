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

## Running

Use the launcher (sets `PYTHONPATH` + `AUTONOMOUS_TRUST_BACKEND=python` for you);
needs an interactive terminal:

```sh
scripts/run-operator.sh --demo     # mock node + software-token PIV, no card/cohort
scripts/run-operator.sh            # real node bridge
# or: python -m autonomous_trust.operator [--demo]
```

Tabs: **a**ctivate · **d**irectory · request (**b**uild) · acti**v**ity · **s**tatus ·
**r**efresh · **q**uit.

### Demo credentials (`--demo`)

**There is no PIN/MFA to look up — in `--demo` both fields are ignored.** The demo
mints a throwaway software token (no card, so no PIN) and enrolls **no** TOTP
secret, so activation runs single-factor. On the **Activate** tab just press
**Activate** (the PIN and MFA boxes can hold anything or be left blank); it runs a
real PIV challenge-response against the self-minted CA and returns **VERIFIED**.
Then submit a request from the **Request** tab and watch the **Activity** tab —
the mock `DemoNode` answers it with a result. (Proof badges show `— none` unless
the ZK-STARK backend is available.)

### Dev activation with files / real 2FA

To exercise the real activation path without the demo node, point the console at a
software token on disk (e.g. the leaf files `--demo` writes to its temp dir, or
any test PKI):

```sh
python -m autonomous_trust.operator \
  --software-cert leaf.crt --software-key leaf.key --ca-bundle ca_bundle.pem \
  [--totp-secret <base32>]
```

With `--totp-secret`, MFA is **enforced**: enter the **current TOTP code** in the
MFA box (the PIN box is still ignored for a software token; a real PyKCS11 card
uses the PIN to unlock the key). Without it, activation is single-factor PIV.

See `doc/NV059/work/PIV_MFA_OPERATOR_ACCESS_PLAN.md` for the full design and
phasing (TUI core = P4, request/results = P5; software-token mock = §7.1).
