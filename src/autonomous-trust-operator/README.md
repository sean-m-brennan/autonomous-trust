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

### Activating a live PIV card

```sh
scripts/run-operator.sh --ca-bundle CA.p7b
```

A `--ca-bundle` with no software cert/key means **the card in the reader is the
token**. The PIN you enter opens a PKCS#11 session (`PyKcs11Token`), the card signs
the server-issued challenge, and its certificate chain is verified against the
bundle. The session is closed as soon as activation returns — the PIN is held only
for the login and never persisted, and no session outlives the call (which also
keeps the status line's `probe_token` safe, since its process-global `C_Finalize`
would otherwise tear a live session down).

The bundle must be the chain that **actually issued that card's cert**, or
activation returns `REJECTED` with a chain error. `--pkcs11-module` / `--slot`
override the autodetected module; `--crl-path` (PEM or DER) adds a revocation
check; `--totp-secret` enforces a second factor.

### "UNAVAILABLE — no PIV token configured" (the `--ca-bundle` option)

Pressing **Activate** with **no** token flags at all returns
`UNAVAILABLE — no PIV token configured`, whatever PIN you type: `build_app` wires
the stub activator, because verifying a PIV credential requires the **issuing-CA
chain** to verify it against. Either pass `--ca-bundle` for the live card above, or
all three of these for a software token:

| Flag | What it is |
| --- | --- |
| `--software-cert C.pem` | the operator leaf certificate |
| `--software-key K.pem` | its private key |
| `--ca-bundle CA.pem` | chain of the CA(s) that issued `C.pem` — concatenated PEM, a single DER cert, or a **PKCS#7 `.p7b`/`.p7c`** (DER or PEM-wrapped), the format agency PKI usually ships; no `openssl pkcs7 -print_certs` conversion needed |

A **CRL is not a CA bundle** — it lists revoked serials and carries no trust anchor. Pass it
as `--crl-path` (core CLI) instead, in **either PEM or DER**; hand one to `--ca-bundle` and the
reject reason now says so by name rather than reporting an unknown issuer. Same for a private
key or CSR, and for a certificate handed to `--crl-path`. A CRL that cannot be read reports
`UNAVAILABLE` naming the file, never "not revoked".

The software flags take precedence over the live card when all three are present.
For a throwaway set use `--demo` (it mints its own CA+leaf), or reuse the leaf files
`--demo` writes to its temp dir.

With a card inserted but **no** `--ca-bundle`, the Activate tab reads
`card detected, cannot activate` — not `token present` (which would imply activation
works) and not `no token detected` (which would send you chasing the reader).

### Live card presence

Run with no token flags and the **Activate** tab reports real card presence from a
**PIN-less** PKCS#11 probe (`probe_token()`), run when the view mounts and again
after each activation — no PIN is needed or requested to answer "is a card in the
reader?". The module is autodetected (`opensc-pkcs11.so` across the usual
Debian-multiarch / lib64 / Homebrew / macOS-OpenSC locations); set
`AUTONOMOUS_TRUST_PKCS11_MODULE` to override for vendor middleware or CACKey,
which a real CAC may require.

The status line names the reason in parentheses, so a card that reads as absent is
diagnosable: `PyKCS11 not installed` (the binding is missing — it is in
`environment.yml`, or `pip install pykcs11`), `no PKCS#11 module found` (no
middleware; install `opensc` or set the env var), `failed to load PKCS#11 module`
(bad path / wrong architecture), or `module loaded, no card in any slot` (the stack
works — check the reader and that `pcscd` is running). A software token instead
reports `software token (dev)`, so a dev run never looks like live hardware.

See `doc/NV059/work/PIV_MFA_OPERATOR_ACCESS_PLAN.md` for the full design and
phasing (TUI core = P4, request/results = P5; software-token mock = §7.1).
