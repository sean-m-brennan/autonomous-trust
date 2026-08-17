*Previous: [The security model](../security.md)*

# Security Hardening

AutonomousTrust operates in adversarial network environments where peers are not inherently trusted. The framework applies defense-in-depth across its C cryptographic core, Python services layer, inspector tooling, and simulator. This document describes the security design principles and the architectural decisions that enforce them.

## Threat model summary

| Subsystem | Threat | Impact if Unmitigated |
|-----------|--------|-----------------------|
| C identity library | Secret key material remains in process memory after use | Key extraction via memory dump or side-channel read |
| C JSON/Protobuf parsing | Malformed or missing fields in deserialized data | NULL-pointer dereference, undefined behavior, crashes |
| C smart pointers | Dangling reference after deallocation | Use-after-free leading to arbitrary code execution |
| Python configuration | Unrestricted class instantiation from JSON `__type__` field | Remote code execution via crafted configuration payloads |
| Python messaging | Unsigned Paxos proposals accepted without verification | Forged reputation scores, consensus poisoning |
| Inspector server | Hardcoded debug mode, open WebSocket binding | Information disclosure, cross-origin hijacking |
| Services serialization | Pickle deserialization of untrusted network data | Arbitrary code execution on unpickle |
| Services metadata | Unrestricted class resolution from qualified names | Instantiation of arbitrary classes from peer-supplied strings |
| Simulator radio model | Inverted signal comparison, silent enum fallthrough | Incorrect reachability decisions, undefined property values |

## C library memory safety

The C identity library handles NaCl/libsodium key generation and serialization. Two classes of memory safety violations are addressed: secret retention and input validation.

### Secret key erasure

Seed bytes used to derive encryption and signing keypairs are stack-allocated during initialization and generation. Without explicit clearing, these seeds persist in memory until the stack frame is reused, creating a window for extraction. The library calls `sodium_memzero()` on all seed buffers immediately after key derivation, before any subsequent operation. This applies uniformly to both `encryptor` and `signature` modules in their `_init` and `_generate` functions.

### Input validation on deserialization

The `identity_from_json` and `network_from_json` functions parse JSON objects into C structs using `json_string_value()`. When a field is absent or has a non-string type, this call returns NULL. All string extraction sites guard against NULL before calling `strncpy`, preventing undefined behavior from malformed identity or network configuration data.

The same principle applies to Protobuf deserialization: `proto_to_peer` validates the return value of `_unpack()` before accessing any fields, and uses the Protobuf-C `_free_unpacked()` function rather than a raw `free()` to correctly release nested allocations.

### Use-after-free prevention

The smart pointer system (`smrt_ptr_t`) tracks reference counts and frees memory when the count reaches zero. After deallocation, the pointer's internal state is zeroed to signal that the object is no longer live, preventing double-free and use-after-free conditions in code that retains stale references.

## Python core security

### Configuration class allowlist

The `config_json_decoder` function resolves `__type__` annotations in JSON to Python classes and instantiates them. Without restriction, an attacker who controls a configuration payload can specify any importable class (e.g., `os.system`), achieving remote code execution.

The framework maintains an allowlist of permitted configuration types. Every `Configuration` subclass registers itself automatically via `__init_subclass__`, so the allowlist grows with the codebase but never includes arbitrary external classes. The decoder rejects any `__type__` value not present in this set.

### Message authentication

Paxos proposals carry reputation scores that all peers commit to their local history upon consensus. If an adversary forges a proposal message, the group may accept fabricated scores. The `Message` class carries a `verified` field that the network layer sets after cryptographic verification. The reputation process logs a warning when processing unverified consensus messages, providing an audit trail as full signature-based authentication is integrated incrementally.

## Inspector security

The inspector provides a Dash-based web UI and WebSocket data feeds for monitoring live networks.

**Debug mode control.** The Quart application server accepts a `debug` parameter but previously ignored it in favor of a hardcoded `True`. Debug mode exposes stack traces, reloading endpoints, and internal state. The server now honors the caller-supplied debug flag, defaulting to disabled in production configurations.

**WebSocket origin validation.** The WebSocket handler validates the `Origin` header of incoming connections against an allowlist (localhost by default). Connections from disallowed origins are closed immediately. The server binds to `127.0.0.1` rather than `0.0.0.0`, restricting access to the local machine unless explicitly configured otherwise.

**Safe collection iteration.** Peer tracking structures are modified during cleanup passes. Deleting dictionary entries during iteration causes `RuntimeError` in Python and can skip entries silently in other runtimes. The cleanup pass collects keys to remove before mutating the dictionary, ensuring deterministic behavior.

## Services security

### Serialization format

The data serialization module previously offered a `fast` mode backed by Python's `pickle`. Pickle deserialization executes arbitrary code embedded in the byte stream, making it unsafe for any data received over the network. The module now uses `msgpack` exclusively for both standard and fast paths. The `fast` parameter is retained for API compatibility but has no effect on the serialization format.

### Metadata class allowlist

The `name_to_class` resolver in the metadata subsystem converts qualified class names from peer-supplied strings into Python class objects. An explicit allowlist restricts resolution to known metadata types (`TimeSource`, `PositionSource`, `Position`, and its subclasses). Additional types can be registered programmatically, but the default set is closed. Unrecognized names raise `ValueError` before any import or instantiation occurs.

## Simulator correctness

Although the simulator does not run in production, correctness in its radio model directly affects the fidelity of trust and consensus testing.

**Signal strength comparison.** Radio reachability is determined by comparing received signal strength (in dBm) against a minimum threshold. The comparison uses the correct inequality direction: a signal is reachable when its strength exceeds the minimum, not when it falls below it.

**Exhaustive enum matching.** The `Antenna` and `NetInterface` enums expose computed properties (`gain`, `rate`, `mark`) via conditional chains. Each property raises `ValueError` for unrecognized enum values, converting silent fallthrough into an immediate, diagnosable failure. This guards against enum extension without corresponding property updates.

## Summary

| Subsystem | Hardening Category | Threat Mitigated |
|-----------|--------------------|------------------|
| C identity library | Secret key erasure | Key material exposure via memory inspection |
| C identity library | NULL-guarded deserialization | Crashes from malformed JSON or Protobuf input |
| C utilities | Use-after-free prevention | Exploitable dangling pointer access |
| Python core | Configuration class allowlist | Remote code execution via crafted `__type__` |
| Python core | Message verification field | Forged Paxos proposals and consensus poisoning |
| Inspector | Debug mode parameterization | Information disclosure in production |
| Inspector | WebSocket origin validation | Cross-origin data exfiltration |
| Inspector | Safe dict iteration | Runtime errors during peer cleanup |
| Services | Pickle removal (msgpack only) | Arbitrary code execution via deserialization |
| Services | Metadata class allowlist | Arbitrary class instantiation from network input |
| Simulator | Signal comparison correction | Incorrect peer reachability in radio model |
| Simulator | Exhaustive enum matching | Silent undefined behavior on enum extension |

---

*Next: [Machine-to-machine security](../m2m_security.md)*
