AutonomousTrust ===============

**AutonomousTrust** (AT) is a framework for cooperative computing among machines
that do not fully trust each other and cannot count on a central authority to
vouch for anyone. Peers exchange encrypted data only with peers they trust, and
only up to the level that trust allows. Trust is never granted once and kept.
Each peer starts a new relationship at zero and earns standing through observed
behavior, and that standing is re-evaluated continuously, so a peer whose
behavior changes is reclassified in real time.

Because trust is a live value rather than a one-time check, a node can meter
access along a gradient, all within the same application: 1) refuse traffic from
badly-trusted peers, to save bandwidth; 2) accept traffic but refuse compute to
weakly-trusted peers, to protect CPU; 3) offer compute but withhold data from
moderately-trusted peers, to protect data; and 4) share data with well-trusted
peers.

AT decides all of this at the node, with no round-trip to a central policy or
PKI service. That is what lets it keep working when the network is jammed,
degraded, or partitioned. Although conventional Zero Trust addresses the same
threat, it depends on reaching a central authority, so under those conditions it
falls back to either failing open or failing closed.


Quick start -----------

AutonomousTrust is developed against a **conda** environment and driven through
the `./at` launcher at the repository root.

```bash
# 1. Set up the dev environment (creates the conda env, installs the Rust
#    toolchain, checks Docker).
./at setup-dev
conda activate autonomous_trust

# 2. See it work. The multi-agency disaster-response demo runs in-process,
#    no Docker required: ten federal sensors form a trust mesh, one is
#    compromised, and the network excludes it on its own.
python -m examples.multi_agency
#    Then open the dashboard at http://localhost:8050

# 3. Run the Python test suite.
./at test-python
```

For the full multi-node demos, orchestrated over Docker, Tilt, and Minikube:

```bash
./at run-demo --variant=python        # multi-node Python cohort (default)
./at run-demo --variant=multi-agency  # disaster-response scenario
./at run-demo --variant=dod-mission   # ISR mission with a microdrone swarm
```

Run `./at help` for the full command list.


Documentation -------------

AutonomousTrust is Part II of a continuous narrative that runs from the physical
mesh layer below it up through the polity and compact tiers above. The whole
chain is entered from [the MUUDD README](../../README.md). The eight chapters
here are the AT section of it, and each links to the next at its foot.

1. [Trust as a live value](doc/concept.md): why AT exists, the adversarial
   assumption, and the access model it replaces.
2. [How a node is built](doc/architecture/overview.md): four processes, the
   cryptographic floor, the two runtimes, and startup.
3. [Becoming a peer](doc/architecture/identity-protocol.md): discovery,
   admission voting, and group formation.
4. [Getting work done](doc/architecture/negotiation.md): the distributed task
   lifecycle, and the three ways a worker says no.
5. [Earning standing](doc/architecture/reputation.md): the consensus protocol,
   decay, verifiable warm start, and quorum attestation.
6. [Standing turned into capability](doc/architecture/trust-tiers.md): the tier
   ladder, weighted transactions, and the bootstrap corpus.
7. [The human behind the machine](doc/architecture/operator-attended.md): which
   nodes have a person behind them, and whether one is there now.
8. [A worked scenario](doc/example-application.md): disaster response end to
   end, mapped back to the mechanisms above.

The reference corpus, being everything from process internals through the
security model to the whitepapers, is appendix B of the same chain and starts at
[process architecture](doc/architecture/process-architecture.md). The
[architecture index](doc/architecture/README.md) lists it by subject, and [the
API reference](doc/api.md) is the entry point for embedding AT in an
application.

Outstanding work is tracked in [`ISSUES.md`](ISSUES.md).


Zero Trust integration ----------------------

AutonomousTrust complements Zero Trust Architecture (NIST SP 800-207) rather
than replacing it. ZTA credentials gate admission, and AT behavioral reputation
governs ongoing trust once a peer is in. The overlay provides five things.

- A pluggable verifier interface, with a working X.509/OCSP backend and an OIDC
  stub.
- DDIL-aware fallback, admitting a peer at a capped reputation when verification
  infrastructure is unreachable, so the cohort still forms while disconnected.
- Revocation as a reputation event, applying a configurable penalty rather than a
  binary disconnect.
- Delegated verification, in which peers that can reach OCSP vouch for peers that
  cannot, lifting the cap without every peer needing external connectivity.
- A JSONL audit trail recording every verification, deferral, and resolution for
  later review.

See [Zero Trust integration](doc/architecture/zta-integration.md) for the full
reference. A standalone enrollment and OCSP demo lives in
[`examples/zta/`](examples/zta) (`./run.sh`).


Development setup -----------------

Dependencies are managed with **conda**, not pip or venv. Two environment files
under `config/cfg/` are authoritative.

- [`config/cfg/environment.yml`](config/cfg/environment.yml): runtime
  dependencies (symlinked from the repo-root `environment.yml`).
- [`config/cfg/devel_environ.yml`](config/cfg/devel_environ.yml): build and test
  dependencies (compilers, `pytest`, conformance tooling).

Firstly, `./at setup-dev` runs the whole setup. To do it by hand:

```bash
conda env create -f config/cfg/environment.yml
conda env update -n autonomous_trust -f config/cfg/devel_environ.yml
conda activate autonomous_trust
```

Second, when you add a dependency, declare it in the file that owns it. Runtime
deps go in `environment.yml` and test or build-only deps in `devel_environ.yml`.
The per-package `pyproject.toml` files mirror these for packaging, and the conda
env files are the source of truth for local development.

Lastly, the two runtimes build separately. The core ships two interoperable
implementations, being a pure-Python core and a formally verified C core,
selected at import time by the `AUTONOMOUS_TRUST_BACKEND` environment variable.
Build the native library with `./at build-native`. See [the dual
implementation](doc/architecture/native-ffi-dual-implementation.md).


License -------

Apache License 2.0. See [LICENSE](LICENSE).
