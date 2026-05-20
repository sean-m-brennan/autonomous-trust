# AutonomousTrust Conformance Corpus

Language-agnostic test artifacts that pin AutonomousTrust protocol behavior
across implementations (Python, C, future Rust/Zig/MCU).

The corpus is the contract: an implementation conforms to AT v1 when both
its **and** the reference harness's run of the v1 corpus pass byte- and
outcome-identical against every case at the locked schema version.

See `../../CONFORMANCE_PLAN.md` for the original design and rationale.
See `../../BUGS.md` for production bugs surfaced and closed by the corpus.

## Status — corpus v1 (2026-05-14)

- 114 cases across 5 protocols (identity, reputation, negotiation,
  network, agreement). Each implementation (Python and C) runs every
  case end-to-end; `scripts/test-conformance.sh` diffs the two result
  reports and fails on any asymmetric outcome.
- Schema version pinned at `"1"`. Any breaking change to a schema or to
  a byte-pinned vector requires bumping to `"2"`.
- All P3–P7 production bugs surfaced by the corpus are FIXED with
  unit-level regressions in `tests/a_unit/`. POW digest format is
  cross-language byte-identical (BUGS.md §P5 CLOSED 2026-05-14).
- Past-threshold flood action is reconciled: both impls
  refuse-and-return at `flood_counts[uuid] > max_task_duplicates`
  (canonical AT v1 behavior). Pinned by
  `negotiation/invite-flood-past-threshold.yaml`.
- Per-scenario state reset in the C adapter (`negotiation_reset_state`,
  `identity_reset_state`, existing `reputation_reset_state`) so
  negative observables (`task_in_stack:false`, `has_my_task: {present:false}`)
  are not polluted by alphabetically earlier scenarios.

### What "conformance" asserts

For an AT implementation to claim conformance with v1 of the corpus, both
its native harness and the reference harness's `diff_results` must
report:

1. **Pass** on every `kind: scenario`, `kind: wire_vector`,
   `kind: crypto_vector`, `kind: agreement_vector`, and `kind: negative`
   case under `scenarios/` and `vectors/`.
2. **Byte-identical** emitted bytes for every vector marked
   `byte_pinning: true` (signature, agreement-proof, message-envelope,
   POW digest).
3. **Identical outcome** for every state-machine scenario — same
   accept/refuse decision per step, same `expected_state` observables,
   same emission types/recipients per step's outbox.
4. **Zero asymmetric** in the cross-language diff.

A `skip` from one implementation is acceptable in development (e.g. an
unimplemented adapter) but not in v1 claim: every case must run on every
side. `--strict-coverage` enforces this.

## Run

From `src/autonomous-trust/`:

```sh
# Python harness only (default)
tox -e conformance

# Or directly with pytest
pytest conformance/harness/python -v

# Full v1 gate: Python + C + cross-language diff with strict coverage
../../scripts/test-conformance.sh --c --strict-coverage
```

The driver writes:

- Python results: `conformance/results/python-<timestamp>.json`
- C results: `../../src/c/build/conformance/results/c-latest.json`
- Cross-language diff: stdout (`only-python`, `only-c`, `asymmetric`
  counts; non-zero exit on any asymmetric or, with
  `--strict-coverage`, on any only-* gap).

CI runs this gate via `.github/workflows/conformance.yml` on every push
and PR to the repo. The workflow uploads both result JSONs as artifacts
so a downstream meta-job can diff them against another impl's results
without re-running.

## Building the C harness

The C harness is wired in via `src/c/CMakeLists.txt`'s
`add_subdirectory(conformance)`. From `src/c/build/`:

```sh
cmake ..                # regenerate (picks up the subdirectory)
make conformance_runner # build the runner only
make conformance_c      # also runs it; writes c-latest.json
```

The build runs `python -m tools.corpus_to_json` as a custom command
first, producing JSON mirrors under `<build>/conformance/corpus-json/`.
Inputs are every YAML under `conformance/scenarios/` and
`conformance/vectors/`; outputs are byte-stable across re-runs.

## Authoring a new case

1. Drop a YAML under `scenarios/<protocol>/` or `vectors/<kind>/`.
2. Pick the right `kind` and `protocol` for the schema header.
3. If the case needs new keys/groups/nonces, drop them under
   `testdata/` and reference them from the YAML.
4. For byte-pinned vectors, generate `expected.json_wire` /
   `expected.protobuf_bin` / `expected_digest_hex` from the Python
   side first, then add a C-side adapter dispatch if the case kind
   needs new logic. Use lowercase hex for digest assertions.
5. Run `scripts/test-conformance.sh --c --strict-coverage` and iterate
   until green on both sides.

The schemas under `schema/` are validated by the loader on every run,
so a malformed YAML fails before any adapter is invoked.

## Layout

```
schema/                JSON Schemas (scenario, wire_vector, crypto_vector,
                       agreement_vector, negative).
scenarios/<protocol>/  state-machine traces (kind: scenario)
vectors/wire/          wire-format vectors (kind: wire_vector)
vectors/crypto/        crypto primitive vectors (kind: crypto_vector)
vectors/agreement/     agreement-protocol vectors (kind: agreement_vector)
vectors/negative/      mutated scenarios that must reject (kind: negative)
testdata/              fixtures: keys, groups, nonces, payloads
harness/common/        loader, JCS canonicalizer, diff_results
harness/python/        Python runner, pytest entry, per-protocol adapters
results/               per-run JSON output (gitignored)
```

## Notes on the harness

- The scenario engine schema gained `no_propagate: true` for assertion
  steps that verify a captured outbound exists in the parent step's
  outbox without delivering it. Used by replay and emission-pin cases.
- The Python adapters depend on `synchronous_dispatch` test hooks on
  `IdentityProcess`, `NegotiationProcess`, `ReputationProcess`. When
  enabled the protocols run handler cascades inline so scenarios stay
  deterministic. Production paths leave the flag off.
- Byte-pinning uses RFC 8785 JCS for JSON canonicalization. Python uses
  the `jcs` PyPI package via `harness/common/canonical.py`; C uses an
  in-tree implementation at `src/c/conformance/jcs.{c,h}` over a
  jansson tree with vendored Ryu d2s for ES6 number formatting.
- POW digests are raw 32-byte blake2b. `DIFFICULTY` = leading zero
  BYTES. Both impls iterate the nonce as ASCII-decimal starting at 1,
  so the same DIFFICULTY + designation produces the same digest and
  the same nonce.
