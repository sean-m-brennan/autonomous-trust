# AutonomousTrust Conformance Corpus

Language-agnostic test artifacts that pin AutonomousTrust protocol behavior across
implementations (Python, C, future Rust/Zig/MCU).

See `../../CONFORMANCE_PLAN.md` for the full design.

## Status (Phase A + Phase C + Phase D + Phase E + Phase F + C harness)

- [x] Schemas authored (`schema/`) — scenario, wire_vector, crypto_vector, negative, agreement_vector
- [x] Python loader (`harness/common/scenario_loader.py`)
- [x] Python runner with pytest entry (`harness/python/runner.py`)
- [x] Universal scenario engine (`harness/python/scenario_engine.py`)
- [x] Network adapter — wire and crypto vectors
- [x] Wire round-trip vectors and Ed25519 / NaCl crypto vectors
- [x] Identity adapter — scenario kind (real `IdentityProcess` + mocked subsystems)
- [x] Identity scenarios: amnesia-readmission, new-node-admission
- [x] Agreement adapter — agreement_vector kind (POA + POS)
- [x] Agreement vectors: leader approve/reject, no-votes, originator short-circuit, POS yea/nay/tie
- [x] Negotiation adapter — scenario kind (real `NegotiationProcess` + mocked subsystems)
- [x] Negotiation scenarios: invite-accept, invite-refuse-not-capable, invite-refuse-low-rep, status-poll
- [x] Reputation adapter — scenario kind (real `ReputationProcess` + synchronous_dispatch hook)
- [x] Reputation scenarios: request-granted, request-nacked-stale, request-backdated, transaction-accepted
- [x] C harness skeleton, loader, runner (`src/c/conformance/`)
- [x] C network adapter — crypto vectors via libsodium (Ed25519 + NaCl Box/SecretBox)
- [x] CI diff tool (`harness/common/diff_results.py`) — compares Python and C result JSONs
- [x] Build-time YAML→JSON precompiler (`tools/corpus_to_json.py`) so the C harness reads JSON via jansson
- [ ] C wire-vector round-trips (AgreementProof / Signature / Message envelope) — adapter currently emits `skip`
- [ ] C identity adapter — currently emits `skip`; needs `synchronous_dispatch`-equivalent test hook on `id_proc.c`
- [ ] PoW agreement vectors (deferred)
- [ ] Negotiation haggle scenario (the params.acceptable() == False / slot-conflict branch)
- [ ] Negative kind for identity (deferred)

## Building and running the C harness

The C harness is wired in via `src/c/CMakeLists.txt`'s `add_subdirectory(conformance)`. From `src/c/build/`:

```sh
cmake ..                   # regenerate (picks up the new subdirectory)
make conformance_runner    # builds the runner only
make conformance_c         # also runs it; writes results to <build>/conformance/results/c-latest.json
```

The build runs `python -m tools.corpus_to_json` as a custom command first,
producing JSON mirrors under `<build>/conformance/corpus-json/`. Inputs are
every YAML under `conformance/scenarios/` and `conformance/vectors/`; outputs
are byte-stable across re-runs.

`scripts/test-conformance.sh` drives the build, run, and diff in one shot:

```sh
scripts/test-conformance.sh                       # Python only (default)
scripts/test-conformance.sh --c                   # Python + C + diff
scripts/test-conformance.sh --c-only              # C only (skip Python)
scripts/test-conformance.sh --c --strict-coverage # also fail on coverage gaps
scripts/test-conformance.sh -k secretbox          # forward args to pytest
```

Direct diff (manual):

```sh
python -m conformance.harness.common.diff_results \
  conformance/results/python-<ts>.json \
  ../../src/c/build/conformance/results/c-latest.json
```

A `skip` on either side is allowed (one impl hasn't wired that case yet).
Only `pass` vs `fail` triggers a non-zero exit. Pass `--strict-coverage`
to fail on cases that exist on only one side.

The scenario schema gained a `no_propagate: true` step flag. When set on an
assertion step, the engine verifies the captured outbound exists in the
parent step's outbox but does not deliver it to the recipient. Used in
Phase F's `request-nacked-stale` for the retry step — alice's retry goes
to the group, and dispatching it to bob would re-enter handle_request with
state staging that is out of scope for that scenario.

The Identity scenarios depend on the `IdentityProcess.synchronous_dispatch`
class flag (`autonomous_trust/core/_python/identity/idprocess.py`). When set
to `True` (the harness flips it on per scenario), `_spawn` runs every
`Thread(target=...).start()` call as a direct, in-line invocation. This makes
welcoming_committee → vote_collection → finalize → peer_accepted execute
within a single `run_message_handlers` call, so scenarios remain deterministic
and synchronous. Production paths leave the flag at `False`.

Byte-pinning is deferred for v1: every scenario carries `byte_pinning: false`
and the harness only checks semantic equivalence on round-trips. Adopting a
canonicalizer (project-local sorted-keys or RFC 8785 JCS) is tracked under
`CONFORMANCE_PLAN.md` Open Questions.

## Layout

```
schema/                JSON Schemas, one per `kind`.
scenarios/<protocol>/  state-machine traces (kind: scenario)
vectors/wire/          wire-format vectors (kind: wire_vector)
vectors/crypto/        cryptographic primitive vectors (kind: crypto_vector)
vectors/agreement/     agreement-protocol vectors (kind: agreement_vector)
vectors/negative/      mutated scenarios that must reject (kind: negative)
testdata/              fixtures: keys, groups, nonces, payloads
harness/common/        loader shared between Python and (future) C harnesses
harness/python/        Python runner, pytest entry, per-protocol adapters
results/               per-run JSON output (gitignored)
```

## Run

From `src/autonomous-trust/`:

```
tox -e conformance
```

Or directly:

```
pytest conformance/harness/python -v
```

The runner emits `conformance/results/python-<timestamp>.json` for downstream
diffing against the C runner once that lands.

## Author a new case

1. Drop a YAML under `scenarios/<protocol>/` or `vectors/<kind>/`.
2. Pick the right `kind` and `protocol` for the schema header.
3. If the case needs new keys/groups/nonces, drop them under `testdata/` and
   reference them from the YAML (literal path, or `<ref:...>` for interior refs).
4. Run the harness; iterate until green.

The schemas under `schema/` are validated by the loader on every run, so a
malformed YAML fails before any adapter is invoked.
