AutonomousTrust
===============

**AutonomousTrust** (AT) is a framework for cooperative computing among machines that do not fully trust each other and cannot count on a central authority to vouch for anyone. Peers exchange encrypted data only with peers they trust, and only up to the level that trust allows. Trust is never granted once and kept. Each peer starts a new relationship at zero and earns standing through observed behavior, and that standing is re-evaluated continuously, so a peer whose behavior changes is reclassified in real time.

Because trust is a live value rather than a one-time check, a node can meter access along a gradient, all within the same application:

1. refuse traffic from badly-trusted peers, to save bandwidth;
2. accept traffic but refuse compute to weakly-trusted peers, to protect CPU;
3. offer compute but withhold data from moderately-trusted peers, to protect data;
4. share data with well-trusted peers.

AT decides all of this at the node, with no round-trip to a central policy or PKI service. That is what lets it keep working when the network is jammed, degraded, or partitioned, the conditions under which conventional Zero Trust (which depends on reaching a central authority) falls back to either failing open or failing closed.


Quick Start
-----------

AutonomousTrust is developed against a **conda** environment and driven through the `./at` launcher at the repository root.

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

Run `./at help` for the full command list (build, test, and run targets).


Start here
----------

Read these in order; each builds on the last.

1. **[Purpose](doc/concept.md)**: why AT exists, and the access model it replaces.
2. **[Architecture](doc/architecture/README.md)**: how a node is built, from cryptographic identity through group formation, task negotiation, and reputation consensus.
3. **[Example application](doc/example-application.md)**: a disaster-response scenario walked through end to end, mapped back to the mechanisms that make it work.


Zero Trust integration
----------------------

AutonomousTrust complements Zero Trust Architecture (NIST SP 800-207) rather than replacing it. ZTA credentials gate admission; AT behavioral reputation governs ongoing trust once a peer is in. The ZTA overlay provides:

- a pluggable verifier interface, with a working X.509/OCSP backend and an OIDC stub;
- DDIL-aware fallback, admitting a peer at a capped reputation when verification infrastructure is unreachable, so the cohort still forms while disconnected;
- revocation as a reputation event, applying a configurable penalty instead of a binary disconnect;
- delegated verification, in which peers that can reach OCSP vouch for peers that cannot, lifting the cap without every peer needing external connectivity;
- a JSONL audit trail recording every verification, deferral, and resolution for later review.

See [doc/architecture/zta-integration.md](doc/architecture/zta-integration.md) for the full reference. A standalone enrollment and OCSP demo lives in [`examples/zta/`](examples/zta) (`./run.sh`).


Development setup
-----------------

Dependencies are managed with **conda**, not pip or venv. Two environment files under `config/cfg/` are authoritative:

- [`config/cfg/environment.yml`](config/cfg/environment.yml): runtime dependencies (symlinked from the repo-root `environment.yml`).
- [`config/cfg/devel_environ.yml`](config/cfg/devel_environ.yml): build and test dependencies (compilers, `pytest`, conformance tooling).

`./at setup-dev` runs the whole setup. To do it by hand:

```bash
conda env create -f config/cfg/environment.yml
conda env update -n autonomous_trust -f config/cfg/devel_environ.yml
conda activate autonomous_trust
```

When you add a dependency, declare it in the file that owns it: runtime deps in `environment.yml`, test and build-only deps in `devel_environ.yml`. The per-package `pyproject.toml` files mirror these for packaging, but the conda env files are the source of truth for local development.

The core ships two interoperable implementations of the same runtime: a pure-Python core and a formally verified C core, selected at import time by the `AUTONOMOUS_TRUST_BACKEND` environment variable. Build the native library with `./at build-native`. See [doc/architecture/native-ffi-dual-implementation.md](doc/architecture/native-ffi-dual-implementation.md).


Documentation
-------------

| Document | Description |
|----------|-------------|
| [doc/concept.md](doc/concept.md) | Purpose and access model (start here) |
| [doc/architecture/](doc/architecture/README.md) | Technical architecture: identity, networking, negotiation, reputation, ZTA, and more |
| [doc/example-application.md](doc/example-application.md) | Worked disaster-response example |
| [doc/api.md](doc/api.md) | Integration API: entrypoints for embedding AT in an app |
| [doc/security.md](doc/security.md) | Security model: properties, containment, and residual risk |
| [examples/README.md](examples/README.md) | The example suite and how to add a scenario |
| [doc/testing.md](doc/testing.md) | Testing approach |


License
-------

Apache License 2.0. See [LICENSE](LICENSE).
