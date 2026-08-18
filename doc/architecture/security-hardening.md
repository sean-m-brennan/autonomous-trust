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
| Inspector transport | Dashboard and WebSocket published off-host in plaintext with no client authentication | Live mesh state disclosure, command injection by any reachable client |
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

**WebSocket origin validation.** The WebSocket handler validates the `Origin` header of incoming connections against an allowlist (localhost by default). Connections from disallowed origins are closed immediately. The server binds to `127.0.0.1` rather than `0.0.0.0`, restricting access to the local machine unless explicitly configured otherwise — see *Bind address and advertised address* below for how that configuration works and what it requires.

**Origin validation actually running.** The allowlist above was unreachable code
under a current `websockets`. Its asyncio `ServerConnection` carries the
handshake in `request.headers` and has no `origin` attribute at all, where the
legacy server had one, so `websocket.origin` raised `AttributeError` on *every*
inbound connection — killing the handler before the allowlist could refuse
anything, before authentication could run, and before the client could register.
From outside it presented as a connection that opened and then went quiet.
`pyproject.toml` admits `websockets>=10,<15`, which spans both APIs, so
`websocket_origin()` reads whichever shape the connection has rather than pinning
one. Verified against a live listener: a disallowed `Origin` now closes with 4003
and an allowed one registers a client, neither of which the fake-socket unit tests
could have shown.

**Bind address and advertised address.** The two used to be independent values,
and they disagreed. `DashControl`'s WebSocket listener bound `127.0.0.1` while
`ws_url()` advertised the *dashboard's* host — the routable address returned by
`get_ip_addr()` — so any client not on the server's own machine was handed an
address nothing was listening on, and no server-side record of the attempt
existed because the connection never arrived. It went unnoticed because the live
dashboard's socket is the visualization server's `/ws` on the page's own origin,
leaving the system tests as this listener's only clients.

The fix is structural rather than a corrected string. `SocketExposure` owns one
address; the listener binds it and `ws_url()` advertises it, so the two cannot
drift apart again. The invariant is that **the advertised host is always one the
listener accepts on**. A wildcard bind is the single case where the advertised
value differs from the configured one — `0.0.0.0` is not somewhere a client can
connect, so the routable address is advertised instead, which stays truthful
precisely because a wildcard listener does accept there.

The default is unchanged: loopback, reachable only from the host. Moving it is a
deliberate act via `AT_INSPECTOR_WS_BIND`, and it carries deliberate
consequences. An exposed bind with **no client authentication is refused** — the
setting is new, so no existing deployment can be broken by the requirement, and
the alternative would be a knob whose only effect is publishing an
unauthenticated live feed. An exposed bind without TLS *warns* rather than
refuses, because terminating TLS in a proxy ahead of a private-network bind is a
legitimate deployment this code cannot distinguish from a careless one. Exposing
the listener also extends the `Origin` allowlist to the exposed host, since an
allowlist still naming only loopback would refuse every client the knob just made
reachable. Note that nothing in either shipped deployment publishes this port:
exposing the listener means publishing 5005 (compose) or adding a Service port
(Kubernetes) as well, which is why neither manifest does so by default.

**Transport encryption.** The `Origin` allowlist and the loopback bind above are
sufficient only while the port stays on the host. Both shipped deployments break
that assumption: `deploy/multi_agency/docker-compose.yaml` publishes `8050:8050`
and the Kubernetes Service exposes the same port, so the dashboard and its data
feed are reachable off-host. `inspector/security.py` adds server-side TLS to both
listeners — the Dash control surface with its WebSocket, and the visualization
server that serves the graph page and `/ws`. It is configured by
`AT_INSPECTOR_TLS_CERT` and `AT_INSPECTOR_TLS_KEY`, with an optional
`AT_INSPECTOR_TLS_KEY_PASSWORD` and `AT_INSPECTOR_TLS_CLIENT_CA` (a CA bundle
that turns on client-certificate verification).

The configuration is **opt-in but fail-closed**. Unset means the previous
behavior exactly — plaintext on a loopback bind, which is the right posture for a
developer machine and the one every demo relies on. *Half*-set raises
`SecurityConfigError` before any listener opens: a certificate without its key, a
path that does not resolve inside the container, a client CA with no server
certificate. Each of those would otherwise produce a plaintext listener on a port
an operator believes is encrypted, which is worse than a refusal to start. The
advertised scheme is derived from the same object that configures the listener
(`ws_url()` returns `wss://` exactly when the socket is wrapped), because a
mismatch there fails in the browser with no server-side record of the attempt.

One limit is enforced rather than hidden. The visualization server runs on Quart's
built-in server, which accepts a certificate and an unencrypted key path and has
no argument for a passphrase, nor one that makes `ca_certs` a *requirement*.
Rather than accept those two settings and drop them — the client-CA case being a
real downgrade, since the operator believes client certificates are being
verified — `VizServer.run()` refuses to start and names the setting it cannot
honor, pointing at a reverse proxy or a direct hypercorn deployment.

**Client authentication.** TLS establishes who the *server* is; it says nothing
about who connected. A shared bearer token, set in `AT_INSPECTOR_WS_TOKEN` and
compared with `hmac.compare_digest`, gates both WebSocket listeners. The token
travels as the **first frame** of the connection rather than in the URL, where
every proxy in the path would log it and the browser would keep it in history.
Absent token means no authentication, which is again the previous behavior.

The frame position is a protocol contract, not an implementation detail. When
authentication is off the server reads **nothing** before the application
protocol starts, because that first frame already belongs to the application —
`viz/js/force.js` sends a graph selector there, and the live feed sends no frame
at all. When authentication is on, the client must send its credential before the
selector; the page receives the token and the scheme rendered into it by the
server, so the client knows which of the two protocols it is speaking. A refused
connection is closed with application code **4401** (chosen over 1008 so an
operator reading a browser console can distinguish "not authenticated" from any
other policy refusal) and the browser logs the refusal unconditionally, since a
viewer whose graph is merely empty has no other way to learn it was rejected.
Server-side, refusals are logged per peer with the first attempt in full and
one line per 50 thereafter, carrying the running count: a rejected client
normally retries in a loop, and unthrottled logging would bury the very message
that explains the misconfiguration.

A shared token is deliberately the weakest of three possible schemes, and its
limits are worth stating: one secret for every viewer, no revocation short of a
restart with a new value, and no notion of *which* human is connected. It is here
because it needs no provisioning. The check sits behind an `Authenticator`
interface so the stronger mechanisms this tree already has — an `OperatorSession`
from the PIV+MFA flow ([Operator Access](operator-access.md)), or an mTLS client
certificate chaining to the configured ZTA anchors ([ZTA
Integration](zta-integration.md)) — can replace it without touching a connection
handler. Whether a credential may be embedded in a served page is asked of the
authenticator rather than assumed: a shared token may travel that way, a session
token or a client certificate may not.

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
| Inspector | Opt-in, fail-closed TLS on both listeners | Plaintext mesh state on a published port |
| Inspector | First-frame bearer token, constant-time compare | Unauthenticated viewing and control of a live fleet |
| Inspector | Single-source bind/advertise, auth required to expose | Unreachable advertised address; accidental publication of the data feed |
| Inspector | API-tolerant `Origin` read | Origin allowlist and auth gate silently never running |
| Inspector | Safe dict iteration | Runtime errors during peer cleanup |
| Services | Pickle removal (msgpack only) | Arbitrary code execution via deserialization |
| Services | Metadata class allowlist | Arbitrary class instantiation from network input |
| Simulator | Signal comparison correction | Incorrect peer reachability in radio model |
| Simulator | Exhaustive enum matching | Silent undefined behavior on enum extension |

---

*Next: [Machine-to-machine security](../m2m_security.md)*
