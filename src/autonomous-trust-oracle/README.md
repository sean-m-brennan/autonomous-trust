# AutonomousTrust Oracle

The verification layers of R+D.md §12, as a distribution separate from the
core (FEATURE_SPLIT_PLAN Phase 3):

| Package | Layer | Declared by |
|---|---|---|
| `autonomous_trust.oracle.physics` | physical consistency (§12.2) | `$AT_PHYSICS` |
| `autonomous_trust.oracle.certificates` | certificate-carrying interfaces (§12.3) | `$AT_CERTIFICATES` |
| `autonomous_trust.oracle.calibration` | coverage audit (§12.4) | `$AT_CALIBRATION` |
| `autonomous_trust.oracle.prequential` | prequential competence (§12.5) | `$AT_PREQUENTIAL` |
| `autonomous_trust.oracle.replication` | replicated execution (§12.6) | — |

Each registers its scorer arms with the core's oracle registry
(`autonomous_trust.core.oracles`) and speaks only once its declaration names a
model, so installing this package changes nothing on its own.

The core names no layer. It finds this package through the
`autonomous_trust.extensions` entry point when installed, or through
`autonomous_trust/oracle/_at_extension.py` in a source tree (put
`src/autonomous-trust-oracle` on `PYTHONPATH` beside `src/autonomous-trust`).
A node whose environment declares a layer this package does not supply refuses
to start.

The C twins are the `libat_<layer>` libraries under `src/c/extensions/`; see
`doc/architecture/extensions.md`.

## Tests

```
./run-tests.sh
```
