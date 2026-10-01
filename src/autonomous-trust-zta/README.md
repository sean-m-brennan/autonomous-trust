# AutonomousTrust ZTA

Zero Trust credential integration, as a distribution separate from the core
(FEATURE_SPLIT_PLAN Phase 6):

| Module | What it is |
|---|---|
| `autonomous_trust.zta.zta_verifier` | the X.509 and OIDC verifiers, the `Verifier` interface, `ZtaStatus` |
| `autonomous_trust.zta.zta_policy` | `ZtaPolicy` (`zta_policy.cfg.json`), and the MFA factor registry |
| `autonomous_trust.zta.mfa`, `.totp` | the MFA chain and its TOTP factor |
| `autonomous_trust.zta.zta_binding`, `.operator_binding` | verifying a credential's binding to a node, and an operator-key binding |
| `autonomous_trust.zta.admission` | the admission gate, the join and gateway checks, background re-verification |

The core keeps what every identity carries: the credential fields and their
bounds, and the binding pre-image (`autonomous_trust.core.identity.zta_fields`).
It names nothing here. It finds this package through the
`autonomous_trust.extensions` entry point when installed, or through
`autonomous_trust/zta/_at_extension.py` in a source tree (put
`src/autonomous-trust-zta` on `PYTHONPATH` beside `src/autonomous-trust`), and
reaches it only through identity hooks.

Installing it changes nothing on its own. A node enforces ZTA only when its
`zta_policy.cfg.json` enables it. A node whose policy enables ZTA without this
package refuses to start, and so does one whose policy names a verifier type
or an MFA factor nothing provides: those used to fall back to a verifier that
admits everyone. PIV/CAC is not here: the `piv` factor comes from
`autonomous-trust-operator`, which registers it when present.

The C twin is `libat_zta` (`src/c/extensions/zta/`); see
`doc/architecture/extensions.md`.

## Tests

```
./run-tests.sh
```
