# System Overview

AutonomousTrust is a high-trust cooperative computing framework: a data messaging system where encrypted data is shared only with trusted peers based on fine-grained, dynamically-evaluated trust scores. It implements dynamic composability of microservices, with security built in rather than bolted on.

## Design principles

- **Zero-trust foundation**: Every peer starts untrusted. Trust is earned through consensus-based identity verification and maintained through reputation scoring.
- **Consensus-based admission**: New peers are admitted only after existing group members vote to accept them via a configurable agreement protocol (Proof of Work, Proof of Stake, or Proof of Authority).
- **Encrypted messaging**: All peer-to-peer and group communication is encrypted. Only the initial identity announcement uses an open broadcast channel.
- **Decentralized**: No central authority. Groups form organically, reputation is maintained via leaderless Byzantine Multi-Paxos, and tasks are negotiated directly between peers.

## Cryptography

AutonomousTrust uses NaCl/libsodium for all cryptographic operations:

| Operation | Algorithm | Purpose |
|-----------|-----------|---------|
| Signing | Ed25519 | Identity verification, vote signatures, message authentication |
| Encryption | X25519 + XSalsa20-Poly1305 (NaCl Box) | Peer-to-peer encrypted channels |
| Group encryption | Shared symmetric key (NaCl SecretBox) | Group broadcast encryption |

**Key principle**: Private keys are never transmitted on the wire. Identity announcements contain only the public signing key and public encryption key. Peer-to-peer encryption uses NaCl Box, which combines the sender's private key with the recipient's public key.

## Package structure

The system is organized as four Python namespace packages under `autonomous_trust`:

```
autonomous-trust (core)
  +-- autonomous-trust-services
        +-- autonomous-trust-inspector
              +-- autonomous-trust-simulator
```

The core package contains the four subsystem processes (Network, Identity, Negotiation, Reputation), the configuration system, cryptographic primitives, and data structures (DAGs, Merkle trees, agreement protocols).

**Dual implementation.** The core has two interoperable implementations: pure
Python (`autonomous_trust.core._python`) and C (`src/c`, built as
`libautonomous_trust.so` and bridged via CFFI under
`autonomous_trust.core._native`). A backend is selected at import time via the
`AUTONOMOUS_TRUST_BACKEND` environment variable (`auto`/`native`/`python`), and
C nodes interoperate on the wire with Python nodes. The embedded/microdrone
target runs the standalone C daemon (`at_demo`) with no Python on the device.
See [Native / FFI Dual Implementation](native-ffi-dual-implementation.md).

[Native / FFI Dual Implementation >](native-ffi-dual-implementation.md)
