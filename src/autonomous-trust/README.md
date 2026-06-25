AutonomousTrust
===============

***AutonomousTrust*** is a high-trust cooperative computing concept --- a data messaging framework that allows for dynamic composibility, requesting and serving encrypted data *only* with trusted peers and only to the extent of that fine-grained trust.
Said trust is dynamically evaluated in real time to rapidly eliminate incoming threats and even reclassify existing peers as their behavior changes and thus protect resources.
Increased risk requires a greater trust threshold.
An autonomous agent using this framework can adaptively: 1) refuse communications from severely untrusted peers, conserving bandwidth; 2) communicate with but refuse computation services to faintly trusted peers, protecting CPU time; 3) offer services but refuse data-sharing to moderately trusted peers, protecting data; _and_ 4) offer data-sharing to well trusted peers; all with a configurable gradient of access at every level, and all within the same application.

In more concrete terms, *AutonomousTrust* is an operations framework for a vast distributed system that dynamically composes numerous individual microservices into a coherent application on-demand -- with security at its core.
We follow the Unix philosophy: do one thing well, work together, use a universal (text) interface; yet implemented such that each microservice can choose its level of participation.


Architecture
------------

For technical architecture documentation, see [doc/architecture/](doc/architecture/README.md), covering:

- System overview and cryptographic foundation
- Process architecture and IPC
- Networking, identity protocol, and group formation
- Task negotiation and reputation consensus
- Space communications (DTN, orbital mechanics)
- Security hardening
- [Zero Trust Architecture (ZTA) integration](doc/architecture/zta-integration.md) -- pluggable credential verification, DDIL fallback, and compliance audit logging


Zero Trust Integration
----------------------

AutonomousTrust complements Zero Trust Architecture rather than replacing it. ZTA credentials gate admission; AT behavioral reputation governs ongoing trust. The ZTA plugin provides:

- **Pluggable verifier interface** with X.509 (OpenSSL) and OIDC (stub) backends
- **DDIL-aware fallback** -- peers are admitted with a reputation cap when verification infrastructure is unreachable, preserving network formation in disconnected environments
- **Revocation as reputation event** -- certificate revocation applies a configurable reputation penalty rather than a binary disconnect
- **Delegated verification** -- the AT group acts as a distributed PDP; peers with OCSP connectivity vouch for DDIL-admitted peers, lifting reputation caps without requiring every peer to reach external infrastructure
- **Compliance audit trail** -- every verification, deferral, and resolution is logged to JSONL for post-incident review

To build with ZTA support:

```bash
cd src/c && mkdir build && cd build
cmake .. -DAT_ZTA=ON
make -j$(nproc)
```

To run the 4-peer tactical demo (requires Docker):

```bash
cd examples/zta
./run_demo.sh
```

See [doc/architecture/zta-integration.md](doc/architecture/zta-integration.md) for the full technical reference.


QuickStart
----------

Run `tools/toolbox emulate` from a bash shell.

Requires:
  * Docker https://www.docker.com/get-started/
  * Minikube

The script downloads/installs all required software dependencies into the container(s).


Alternatively, AutonomousTrust can be built as a virtual machine instead of a container.

Run `tools/toolbox actuate` from a bash shell.

Requires:
  * QEMU https://wiki.qemu.org/Hosts

Downloads/installs (local to working dir):
  * pyNaCl
  * libffi


Development setup
-----------------

Dependencies are managed with **conda** (not pip/venv). Two environment files
under `config/cfg/` are authoritative:

  * [`config/cfg/environment.yml`](../../config/cfg/environment.yml) --- **runtime**
    dependencies.
  * [`config/cfg/devel_environ.yml`](../../config/cfg/devel_environ.yml) --- **build
    and test** dependencies (compilers, `pytest`, conformance tooling, etc.).

```bash
# runtime environment
conda env create -f config/cfg/environment.yml
# add the build/test toolchain into the same env
conda env update -n autonomous_trust -f config/cfg/devel_environ.yml
conda activate autonomous_trust
```

When you add a dependency, declare it in the appropriate file: runtime deps go
in `environment.yml`; test/build-only deps go in `devel_environ.yml`. The
per-package `pyproject.toml` files mirror these for packaging, but the conda
env files are the source of truth for local development.


Documentation
-------------

| Document | Description |
|----------|-------------|
| [doc/architecture/](doc/architecture/README.md) | Technical architecture (identity, networking, reputation, ZTA, etc.) |
| [doc/concept.md](doc/concept.md) | Conceptual overview |
| [doc/security.md](doc/security.md) | Security model |
| [doc/api.md](doc/api.md) | API reference |
| [doc/testing.md](doc/testing.md) | Testing approach |
