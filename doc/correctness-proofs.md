*Previous: [Machine-to-machine security](m2m_security.md)*

# Correctness Proofs: Current State and Limitations

## Current state

As of 2026-04-17 the full Frama-C/WP suite runs at **100 % proof coverage on the
goals it attempts** (4 262 / 4 262) but only **53.6 % function coverage** (351 /
655 functions verified, 304 skipped). All skips are deliberate and each one
carries an in-script comment naming the blocker category and a `/* Frama-C:
skipped, [category] reason */` comment at the definition. The skips are
deliberate, categorised, and commented.

The remaining 304 skipped functions are not uniformly hard. They cluster into a
small number of categorical blockers. This document records *why* pushing
coverage further is expensive, so that future work can target the right
choke-point instead of relitigating dead ends.

---

## Blocker categories

### 1. `\freeable` is unreliable in WP

The libc contract in WP for `free(p)` requires `\freeable(p)`. The memory model
only tracks freeable-ness from an immediate `malloc`/`calloc` site, so once a
pointer crosses a function parameter the information is lost and any `free(p)`
in a destroy-callback times out.

**Mitigation in place.** `src/c/frama-c/stubs/fc_stdlib_spec.h` macro-redirects
`free(p) → at_free(p)`, an extern with `assigns \nothing` and no precondition.
Wired via `-include` in `scripts/verify-contracts.sh`. Unblocked `null_destroy`,
`oidc_destroy`, `agreement_proof_free`, and several callers.

**Still blocks.** Any function that has an explicit `frees` *clause in its own
contract*, not just a call to `free`, since WP will still try to discharge
`\freeable`. Removing the `frees` clause from the header contract is an option
but weakens the documented postcondition.

### 2. Variadic `printf`/`scanf` family, broken plugin

The Variadic plugin in Frama-C rewrites `snprintf`/`sprintf`/`sscanf` to use a logic
function `format_length` that has no definition. WP falls back to "modifies
everything reachable through pointer args" → infinite range → plugin abort.

**Mitigation in place.** `src/c/frama-c/stubs/fc_stdio_spec.h` macro-redirects
the calls to non-variadic wrappers (`at_snprintf` etc.) with bounded ACSL
contracts. Because the wrappers are not variadic, the plugin ignores them and WP
uses our contracts directly.

**Still blocks.** Any format-sensitive code that cannot be reduced to a
`path_join` or similar bounded-output helper. Remaining cases are rare.

### 3. Typed-memory-model casts (`void*` / `char*` / `uint8_t*`)

The Typed memory model that WP uses in this project emits warnings of the form
*"Hide sub-term definition"* and *"Cast with incompatible pointers types"*
whenever a pointer round-trips between an opaque-`void*` argument and a typed
field. All three solvers, Alt-Ergo, Z3, and CVC5, then fail to discharge validity
obligations that reach across the cast. Three concrete appearances follow.

- `sodium_memzero(void *pnt, size_t)` cast chain `uint8* → sint8* → uint8*`
- `memcpy` of one struct field to a sibling of a different-but-compatible
 shape (e.g. `public_identity_t` across `config_proc.c`, `zta_process.c`,
 `rep_proc.c` handlers)
- The `\valid((char *)p)` precondition we originally put on `at_free`
 (dropped after confirming WP times out on even trivial casts)

**No general workaround exists.** Skip-fct the affected function, or restructure
the source to avoid the cast when that is cheap.

### 4. `frees` clauses cascade-invalidate WP state

`map_free` declares `frees map->items;`, and `array_free` declares `frees
a->array;`. After either is called WP treats pretty much everything reachable as
potentially invalidated, and subsequent `\valid` obligations on unrelated
pointers time out.

**Mitigation patterns.**

- In composite destroy functions, call `map_free` **last**, after any
 sibling `free`/`at_free`, `array_free` calls. (Proven on
 `agreement_protocol_free`.)
- Keep `frees map->items` but drop `frees map` from the header contract, because the map struct
 itself is usually embedded, not smrt-allocated, and the
 `frees map` clause was poisoning downstream state. (Already fixed in
 `map.h`/`array.h` 2026-04-16.)

**Still blocks.** Functions that must free several maps or arrays in a fixed
sequence (see category 5).

### 5. Loops over container arrays

Patterns like `peers_free` and `for (i=0; i<LEVELS; i++) map_free(&arr[i]);`
cannot currently be verified. Three dead ends were tried on 2026-04-17.

- **Loop invariants** (`\forall k; i <= k < LEVELS ==> arr[k].items != \null`
 + sliding `loop assigns arr[0..i-1]`): WP times out on
 `loop_invariant_*_preserved` because it cannot prove
 `\separated(&arr[i], &arr[k])` for `k > i` from typed memory alone, and
 broadening the `loop assigns` regresses the invariant.
- **ACSL `loop pragma UNROLL N;`** silently ignored by WP (this pragma is
 honored only by the Value / Eva plugins).
- **Global `-ulevel N`** would unroll *every* loop in every file and is
 very likely to regress the 50+ currently-PASSing files. Not attempted.

Tractable-but-ugly: hand-unroll for small fixed `N` (`LEVELS=3`, `VALUES=10`).
Rejected for now because the runtime readability cost is high and the win is
small (2, 3 functions).

### 6. `map_entries_for_each` macro iteration

Functions that walk the live entries of a map (`tx_history_free`, parts of
`reputations_free`) are blocked on the implicit loop inside the macro. Adding a
loop invariant for a macro-expanded body would require knowing the post-state of
the macro, which we do not have.

### 7. Recursive data-structure algorithms

`structures/redblack.c` (17 functions) and the recursive halves of
`structures/merkle.c` cannot be discharged without WP reasoning over rotations
and rebalancing. That would require one of two things.

- Axiomatic invariants for red-black / AVL properties (substantial ACSL
 engineering, easily a multi-week effort), or
- Switching to an iterative rewrite (large code change with no runtime
 benefit).

Not attempting either.

### 8. Serialization layers (JSON + protobuf)

~80 functions across `data.c`, `map.c`, `array.c`, `identity.c`, `reputation.c`,
`agreement.c` are skipped under `[serialization]`. The layers involved are JSON,
protobuf, and the stubs between them, and three blockers account for the skips.

- the `json_t` of `jansson` is an opaque type with no exposed invariants
- `protobuf-c` generated code uses function-pointer dispatch (`descriptor->
 c_name` string comparison) that WP cannot discharge (`valid_string` on a
 protobuf descriptor global is unprovable)
- Each encode/decode involves many state-transitioning stubs

Tightening the jansson and protobuf-c stub specs is the only way in. High
leverage (one stub change could unblock 20+ functions) but also high risk, since
loose stubs currently let many *other* proofs through, and tightening them can
regress those.

### 9. OpenSSL / libsodium stubs

`x509_verifier.c` (11 skipped functions) is blocked by OpenSSL stub
preconditions. `identity.c`/`encryptor.c`/`signature.c` are blocked on libsodium
stubs whose `\valid((unsigned char *)p + (0..N-1))` preconditions hit the
typed-memory cast problem (category 3).

### 10. State accumulation through 4+ consecutive stubs

Process-entry functions (`*_run`) and large handlers reliably time out on
preconditions for the fourth or later stub call, since the `assigns` clause of
each stub adds to the state model until SMT solvers give up. Affects `artifact_run`,
`identity_run`, `fleet_run`, `negotiation_run`, `zta_process_run`,
`reputation_run`, etc.

Fixing this would require tighter `ensures` on every touched stub, or contract
decomposition by hand per-function. The `*_proc.c` recipe in
`reference_framac_fail_file_recipe.md` captures the patterns that do work
(correct false `assigns \nothing`, replace `snprintf` with `path_join`, add
handler contracts, skip-fct the `*_run` itself). That recipe has already been
applied to the 9 `*_proc.c` files, and the residual skip-fct entries are
genuinely stuck.

### 11. File-level `[SKIP]`, missing generated headers

`history.c` and `net_message.c` crash Frama-C on parse (exit code 4), and the
root cause is unclear.

`net_proc.c`, `ip_mreq` struct not visible to the preprocessor under
`__FRAMAC__`.

`configuration.c`, `capabilities.c`, `process_tracker.c`, `logger.c` require
generated `*_table_priv.h` headers that only exist when the project is built.
Running verification on a fresh checkout cannot see them.

Unblocking (a) needs Frama-C upstream patches, (b) needs a stub for
`<netinet/in.h>`, (c) is the cheapest, a pre-verification step that runs the
code generator.

### 12. Combinatorial branch explosion

`_get_err_str` (err_str.c) returns pointers into ~50 static string tables via a
chain of if/else-if. The `ensures \valid_read(\result)` postcondition forces WP
to prove validity in every branch. Each branch is easy, but the combinatorial
explosion of reachable state times out the solvers.

Could be broken into 50 separate behaviors, one per table-range. Tedious but
tractable. Low priority.

### 13. String-walking loops

Functions that walk or copy strings character-by-character (`strncpy`, `strstr`
inside loops, hex encode/decode in `hexlify.c`) systematically time out on
`valid_nstring_src`/`valid_nstring_dest` loop-invariant preservation. Worked
around on a case-by-case basis (`path_join` replacing path snprintf sites).

### 14. The `lemma → axiomatic` pitfall

A `lemma` that WP cannot prove is **not** treated as an assumption; WP drops it
silently and dependent proofs fail. The only reliable way to express a
universally-quantified assumption is inside an `axiomatic {}` block. Documented
as `smrt_refs_positive` in `allocation.h` (fixed 2026-04-13).

### 15. The `\everything` trap

Writing `assigns \everything;` in an ACSL spec is **not valid ACSL**. WP
silently drops the ENTIRE specification and falls back to inference. Always grep
for `Ignoring logic specification` after an ACSL edit; an invalid keyword never
produces a parse error, only a warning that is easy to miss.

### 16. Skip-comment `*/` gotcha

`/* Frama-C: skipped, void*/uint8* cast issue */` closes the comment at `void*/`
(the slash after `void*` forms `*/`). The parse then fails with a cryptic
*"syntax error"* and the whole file is reported as `Goals: 0 [SKIP]`, a silent
PASS. Always write `void-ptr/uint8-ptr` or spell out "void pointer" in skip
comments.

---

## What would meaningfully raise coverage

Ranked by leverage per engineering hour, the candidates are these. The best of
them are cheap, isolated, and reversible.

1. **Tighter jansson + protobuf-c stub specs** (category 8). Could unblock
 30, 50 functions. Risk: regressing currently-PASS files that depend on
 the loose specs. Mitigation: incremental, one stub at a time, with
 baseline diff checks.

2. **Generated-header pre-step in verify-contracts.sh** (category 11c).
 Would unblock 4 files (configuration.c, capabilities.c,
 process_tracker.c, logger.c) → approximately 50 functions become
 reachable (of which maybe half verify once reachable).

3. **Axiomatic declaration of smrt_ptr lifecycle invariants**. Would let
 WP discharge allocation postconditions in the many `*_create` functions
 currently skipped under `[solver-timeout]`.

4. **`\freeable` workaround for `frees` clauses** (category 1 residual).
 Drop `frees` clauses from contracts that use our `at_free` path, trust
 `assigns \nothing` as the reported effect. Straightforward but requires
 a pass through every `_free`/`_destroy` header.

5. **Hand-unrolled `peers_free` + `reputations_free`** (category 5). Two
 functions, ugly but isolated.

## What NOT to try again

- `loop pragma UNROLL N;`, WP ignores it (Value/Eva only).
- Global `-ulevel N`, very high risk of regressing currently-verified
 files.
- `\valid((char *)p)` or `\valid((void *)p)` preconditions as shorthand, which
 triggers the cast-cascade problem (category 3).
- Large `memset(struct*, 0, sizeof(struct))` calls, which always trigger
 "Cast with incompatible pointers types", so replace with explicit field
 initialization when that function needs to verify.
- `memcpy(out, &arr[i], sizeof(struct))` struct-to-struct in WP, same
 root cause, so replace with `*out = arr[i]`.
- Loop invariants over `map_t arr[N]` with `map_free` in the body, where state
 is lost through `frees map->items`, so preservation cannot be discharged.
- Re-enabling `-wp-smoke-tests` without first tightening every libc /
 syscall stub, otherwise every function that touches a stub gets a
 "Doomed" verdict in milliseconds.

---

## References

- Plan: `docs/plans/2026-04-08-framac-full-pass.md`
- Progress: `docs/plans/2026-04-08-framac-progress.md`
- Stub headers: `src/c/frama-c/stubs/{fc_stdio_spec,fc_stdlib_spec}.h`
- Verification driver: `scripts/verify-contracts.sh`
- Smart-pointer contracts: `src/c/autonomous_trust/utilities/allocation.h`

---

*Next: [The verification oracle](verification_oracle.md)*
