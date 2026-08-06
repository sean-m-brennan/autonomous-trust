[< System Overview](overview.md)

# Native / FFI Dual Implementation

AutonomousTrust ships **two interoperable implementations of the core**:

- a **pure-Python** implementation under `autonomous_trust.core._python`, and
- a **C** implementation (`src/c`, built as `libautonomous_trust.so`) reached
  from Python through a **CFFI** binding under `autonomous_trust.core._native`,
  and also runnable as a **standalone daemon** (`at_demo`) on embedded /
  microdrone hardware.

Both speak the same wire protocol, so C nodes and Python nodes discover, admit,
and exchange encrypted group traffic with each other on the same network. This
document describes how the two are organized, how a backend is selected, the
FFI boundary and its drift guard, and the embedded/microdrone runtime.

> **Which runs where, today.** The dod_mission demo containers run **pure
> Python** (see [Gateway Reputation Tree](gateway-reputation-tree.md), "Runtime
> path / C-twin"). The C path is exercised (a) per-subsystem via CFFI when the
> native backend is selected, and (b) as the standalone `at_demo` daemon for
> embedded ARM microdrones, which interoperate on the wire with the Python
> nodes. Feature-wise the native C code currently leads Python in some areas
> (e.g. the ZTA background process, see [ZTA Python Parity](zta-python-parity.md))
> and Python leads C in others (e.g. recursive subtree reputation, see
> [Gateway Reputation Tree](gateway-reputation-tree.md), whose phase 3 is the
> C-parity half).

## 1. Backend selection

The active backend is chosen at import time of `autonomous_trust.core` from the
`AUTONOMOUS_TRUST_BACKEND` environment variable
(`core/__init__.py`):

| Value           | Behavior |
|-----------------|----------|
| `auto` (default) | Try `_native`; if `libautonomous_trust.so` or CFFI fail to load, fall back to `_python`. |
| `native`        | Force `_native` (raises `ImportError` if the C library is unavailable). |
| `python`        | Force pure Python. |

Selection installs a `_BackendRedirector` (an `importlib.abc.MetaPathFinder`)
that transparently rewrites absolute imports of the form
`autonomous_trust.core.X` → `autonomous_trust.core.<backend>.X`. Downstream code
keeps writing `from autonomous_trust.core.identity import ...` and never names a
backend.

**The native backend is a per-module overlay, not a wholesale replacement.**
The redirector tries `core._native.X` first and **falls back to `core._python.X`
per-module** when a submodule has no native counterpart yet. So selecting
`native` gives you C-backed subsystems where they exist and Python everywhere
else. `_native/__init__.py` makes this explicit: it re-exports the **Python**
`AutonomousTrust`, `Process`, `ProcMeta`, and `system` types and only swaps in
C-backed helpers where they are implemented.

`protobuf` is never redirected (generated code, shared by all backends), and
the `_python` / `_native` packages themselves are never intercepted.

## 2. Orchestration: Python process model is retained

Even under the native backend, process orchestration and IPC remain **Python
`multiprocessing.Queue`-based** (see [Process Architecture](process-architecture.md)).
The C functions are called *within* the Python subsystem processes through
CFFI; the C library is not driving the process tree. Downstream packages
(services, inspector, simulator) subclass `AutonomousTrust` and rely on the
queue-based IPC the C side does not yet provide.

`NativeAutonomousTrust` (`_native/_automate_native.py`) is a separate, low-level
wrapper around the C `run_autonomous_trust()` daemon entry point, intended for
future use when the C library is built with `-DFORK=0` (no double-fork). It is
**not** the default runtime path: the standalone C daemon is used by the
embedded build (§5), not by the in-CPython native backend.

## 3. The FFI boundary

```
autonomous_trust.core._native/
├── _ffi.py            # CFFI: ffi.cdef(...) C surface + dlopen of libautonomous_trust.so
├── _automate_native.py# NativeAutonomousTrust (C run_autonomous_trust wrapper)
├── _cap_registry.py
├── config/            # reuses Python Configuration with C-backed helpers
├── identity/          # C identity verification / canonical-form wrappers
├── network/           # _ping_native.py, message wrappers
├── reputation/        # _native_wrappers.py
├── structures/        # C data-structure bindings
├── negotiation/, processes.py, protocol.py  # mostly delegate to _python
```

`_ffi.py` holds the `ffi.cdef(...)` block declaring the C functions Python
calls, plus the `dlopen` of `libautonomous_trust.so` (exposed as `lib`). The
per-subsystem wrappers call `lib.<fn>(...)` and marshal arguments to/from C.

## 4. FFI drift guard

CFFI does **not** validate that a `cdef` prototype matches the real C arity
until call time, where a mismatch surfaces as a segfault (the C function reads a
garbage extra argument off the stack). `scripts/audit-ffi-drift.py` is the
cheap, dependency-free static check that compares the `cdef` in `_ffi.py`
against the authoritative C header prototypes in `src/c` and reports any
function whose **argument count** disagrees:

- **DANGEROUS**: drift in a function a `_native` wrapper actually calls
  (`lib.<name>(...)`): a latent segfault → exit 1.
- **LATENT**: drift in a `cdef`-only function nothing calls from Python yet:
  reported, fails only under `--strict`.

It runs without the conda env, so it is safe as a fast pre-build gate in
`scripts/ci-local.sh`.

## 5. Embedded / microdrone runtime

The embedded target runs the **standalone C daemon** (`at_demo`,
`examples/demo/src/at_demo.c`): no Python on the device.

- **Build:** `embedded/build-arm.sh` cross-compiles `at_demo` for ARM64 (and
  optionally AMD64) via `docker buildx`, producing architecture-specific
  tarballs in `embedded/dist/`. In an apt-reachable environment, the
  `Dockerfile-c` image build is preferred.
- **Provisioning / flashing / signing:** see the existing `embedded/` scripts
  (`provision.sh`, `flash.sh`, `sign-binary.sh`, `verify-binary.sh`).
- **Demo wiring:** the dod_mission demo incorporates embedded C microdrone
  nodes alongside the Python cohort (`scripts/run-demo.sh`,
  `examples/dod_mission/`).

## 6. Cross-runtime interoperability

C and Python nodes interoperate on **live UDP**. The contract they must both
honor is the **DRY canonical wire form**: a flat-dict JSON shape that is
byte-parseable by C (Python's default `ConfigJSONEncoder` form, with
`__type__`/`_uuid` markers and a base64-wrapped hex seed, is *not* parseable by
C). Identity and `Group` objects expose `to_canonical()`/`from_canonical()` for
this; see [Identity Protocol](identity-protocol.md) and
[Node Lifecycle](node-lifecycle.md).

The live interop test is `embedded/test-interop-cpython.sh`, which brings up one
C `at_demo` node and Python nodes on a shared Docker bridge and verifies:

- **C → Python:** the Python node reconstructs the C node's identity from the
  envelope `from_*` fields and admits it (`access_granted`).
- **Python → C:** the C node processes the Python node's announce and unicasts a
  `peer_caps_query` back.
- **Group-key sync:** the C node parses Python's `full_history` group payload
  (the canonical form) and **adopts the shared group key**, so it can
  decrypt/emit encrypted group traffic.
- **Membership propagation:** a later `group_key_update` (a membership update,
  distinct from the bootstrap `full_history`) is emitted by Python in the
  canonical flat form so the C co-member's `handle_group_update` can parse it.

## 7. Conformance parity

Byte-level parity between the two implementations is pinned by the conformance
corpus (`src/autonomous-trust/conformance/`, run via
`scripts/test-conformance.sh`), which exercises the same scenarios through both
a Python adapter and a C adapter. This is the mechanism that keeps the wire
forms and protocol behavior from silently diverging across the two runtimes.

[Process Architecture >](process-architecture.md)
</content>
</invoke>
