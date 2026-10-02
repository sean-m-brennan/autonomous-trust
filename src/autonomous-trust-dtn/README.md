# AutonomousTrust DTN

AT over a Bundle Protocol agent, for links that are down more often than up, as
a distribution separate from the core (FEATURE_SPLIT_PLAN Phase 9):

| Module | What it is |
|---|---|
| `autonomous_trust.dtn.transport` | `DTNNetworkProcess`, the network transport (C's `dtn_bp`) |
| `autonomous_trust.dtn.eid` | endpoint IDs: node, group and service EIDs, receive demux, unicast resolution |
| `autonomous_trust.dtn.backend` | the backend interface, the `stub` backend, and the choice between them |
| `autonomous_trust.dtn.aap2` | the µD3TN backend over AAP 2.0 |
| `autonomous_trust.dtn.extension` | the extension the core finds, which names the transport `dtn_bp` |

A node runs on it by naming the transport,

```
AT_TRANSPORT=autonomous_trust.dtn.transport.DTNNetworkProcess
```

or as the `dtn_bp` leg of the core's hybrid transport
(`autonomous_trust.core.network.hybrid`, configured by `hybrid_net.cfg.json`).
`AT_DTN_BACKEND` picks the agent: `stub` (the default; sends go nowhere) or
`ud3tnv2`, a µD3TN daemon at `AT_DTN_UD3TN_SOCKET` (`unix:/path` or
`tcp:host:port`, default `unix:./ud3tn.aap2.socket`). C's other two backends,
ION and AAP v1, have no Python twin.

The AAP 2.0 messages come from the vendored `aap2.proto`
(`src/c/extensions/dtn/proto/`, a link into the ud3tn submodule).
`scripts/build-py.sh proto-only` generates `aap2_pb2.py` beside the backend; the
tests generate it themselves when `protoc` is on the path.

The core finds this package through the `autonomous_trust.extensions` entry
point when installed, or through `autonomous_trust/dtn/_at_extension.py` in a
source tree (put `src/autonomous-trust-dtn` on `PYTHONPATH` beside
`src/autonomous-trust`). The C twin is `libat_dtn` (`src/c/extensions/dtn/`,
`-DAT_NET_DTN=ON`); the `dtn` conformance protocol holds the two to the same
EIDs and routing. See `doc/architecture/extensions.md` and `at-over-dtn.md`.

## Tests

```
./run-tests.sh
```
