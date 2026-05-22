# Autonomous Trust over Delay-Tolerant Networks

A speculative exploration of running the Autonomous Trust (AT) cooperative
computing framework on DTN infrastructure, and the architectural changes
this would require.

## 1. Why AT + DTN?

Autonomous Trust builds decentralized trust among peers through identity
verification, consensus-based admission, reputation scoring, and encrypted
messaging. Its design assumes peers can reach each other within seconds --
UDP datagrams, broadcast discovery, challenge-response identity protocols
with sub-second timeouts.

DTN exists precisely where those assumptions break down: space
communication links with minutes to hours of one-way light time, tactical
edge networks with intermittent connectivity, sensor meshes that meet
only when a data mule passes by, and disaster-recovery scenarios where
infrastructure is destroyed.

These are also environments where trust matters *most* -- isolated nodes
must decide whether to cooperate with a stranger when there is no central
authority to consult and no guarantee of continuous contact. AT's trust
model is designed for exactly this kind of autonomous decision-making.
DTN provides the transport substrate that makes it physically possible.

## 2. Mapping AT Subsystems to DTN Concepts

### 2.1 Naming: UUIDs to Endpoint IDs

AT identifies peers by UUID (128-bit, hex-encoded). DTN identifies
endpoints via URIs in two schemes:

```
dtn://at-node-7f3a2b/identity    -- hierarchical, human-readable
ipn:42.1                          -- compact, for constrained links
```

A natural mapping:

| AT Concept | DTN Mapping |
|-----------|-------------|
| Peer UUID | DTN node EID (e.g., `dtn://at-<uuid-prefix>/`) |
| Process name (identity, fleet, etc.) | EID demux suffix (e.g., `dtn://at-node/identity`) |
| Broadcast address | Group EID (e.g., `dtn://at-group-<hash>/~bcast`) |
| Group shared key ID | Bundle security context association |

The `ipn:` scheme fits constrained environments where AT nodes run on
embedded hardware. A registration table at each node could map
`ipn:42.1` to the identity process, `ipn:42.2` to reputation, etc.

### 2.2 The Three Channels as Convergence Layers

AT's network layer uses three logical channels:

1. **Open broadcast** (unencrypted UDP, port 27787 on broadcast address)
   -- identity announcements
2. **Encrypted peer-to-peer** (UDP/TCP, port 27787 to specific peer)
   -- NaCl Box, per-peer keys
3. **Encrypted group** (UDP, port 27788 to each member)
   -- NaCl SecretBox, shared group key

In a DTN architecture, these become routing/delivery strategies rather
than separate sockets:

| AT Channel | DTN Realization |
|-----------|----------------|
| Open broadcast | Bundle to group EID with no BPSec, flooded/epidemic routing |
| Peer-to-peer | Bundle to specific node EID, BPSec confidentiality block (bcb) using NaCl Box keys |
| Group multicast | Bundle to group EID, BPSec bcb using shared SecretBox key |

The critical insight: DTN's bundle security (BPSec, RFC 9172) operates
at the bundle layer, surviving store-carry-forward hops -- unlike TLS
which requires an end-to-end connection. AT's existing NaCl encryption
maps directly to BPSec security contexts.

### 2.3 Messages as Bundles

AT messages follow a pipe-delimited wire format:

```
process|function|data
```

Each message is a self-contained datagram (max 1 MB). This maps cleanly
to DTN bundles:

- **Primary block**: source EID, destination EID (derived from
  process name), creation timestamp, lifetime
- **Extension block**: AT function name (e.g., "request_access",
  "update vote request"), carried as a custom extension block type
- **Payload block**: the AT data payload (JSON or protobuf)
- **BPSec blocks**: confidentiality and/or integrity as needed

AT messages are already atomic and self-describing -- they do not
require connection state. This is exactly the bundle paradigm.

### 2.4 Artifact Distribution as Bundle Fragmentation

AT's fleet update system distributes binaries as 960-byte chunks with
a manifest. DTN has native fragmentation:

- **Proactive fragmentation**: The AT manifest/chunk model maps to
  BPv7 proactive fragmentation, where a large bundle is pre-split
  at the source into fragments sized for the narrowest contact window.
- **Reactive fragmentation**: If a contact window closes mid-transfer,
  the CLA can reactively fragment, and the receiving node stores what
  it has until the next contact.

A DTN-native AT would replace its custom chunked artifact transfer with
bundle fragmentation. The manifest becomes bundle metadata (extension
blocks with total size, hash, version). The convergence layer handles
segmentation automatically based on contact capacity.

## 3. Architectural Challenges

### 3.1 Timeout-Dependent Protocols

AT's identity protocol assumes fast round-trips:

- **Discovery broadcast** -> response within seconds
- **Access request** -> challenge-response within seconds
- **Peer voting** -> 5-second collection window
- **Reputation Paxos** -> pending proposals expire after 300 seconds

Over a Mars link (4-24 minute one-way), a single identity handshake
takes 8-48 minutes. Paxos round-trips take 16-96 minutes. The 5-second
vote window is meaningless.

**Adaptation strategies:**

**a) Parameterized timeouts as a function of expected RTT.**
Each AT process already has a `cadence` (500ms). This could become
link-aware:

```c
at_node_config_t cfg = {
    .link_one_way_delay = 720,  /* seconds — Mars average */
    .timeout_multiplier = 3,    /* 3x one-way delay per hop */
};
```

All protocol timeouts would scale: vote collection = `3 * RTT`,
Paxos expiry = `10 * RTT`, etc.

**b) Asynchronous protocol redesign.**
Rather than synchronous challenge-response, AT protocols could become
fully asynchronous:

- **Identity**: Broadcast credentials as a standing offer (bundle with
  long lifetime). Any peer can inspect and decide to accept without
  round-trip confirmation. Confirmation arrives whenever it arrives.
- **Reputation**: Replace synchronous Paxos with an eventually-consistent
  gossip protocol. Each node maintains its local ledger and merges
  diffs when contact occurs -- similar to CRDTs.
- **Voting**: Use pre-committed vote thresholds. A proposal carries a
  deadline (absolute time, not relative). Votes trickle in as bundles.
  The proposer evaluates quorum at the deadline.

**c) Contact-graph-aware consensus.**
If the network has predictable contact windows (as in space
communications), the AT consensus scheduler could use CGR contact
plans to determine *when* to initiate proposals, ensuring all peers
will be reachable within the voting window.

### 3.2 Trust Bootstrapping Without Real-Time Interaction

AT's current bootstrap assumes all nodes are online simultaneously:
a new node broadcasts, existing members vote, the group key is
distributed. In a DTN environment, the "group" may never all be
reachable at once.

**Possible approaches:**

- **Pre-provisioned trust**: For planned deployments (space missions,
  sensor networks), generate identity configs and group keys at
  deployment time, as AT's `provision.sh` already does. Nodes join
  with pre-shared credentials; no real-time bootstrap needed.

- **Delegated admission**: Designate certain well-connected nodes
  (e.g., ground stations) as admission authorities. A new node sends
  its credentials as a bundle; the authority responds with an
  acceptance bundle whenever it has contact. Other nodes trust the
  authority's endorsement.

- **Merkle history convergence**: AT already uses Merkle DAGs for
  reputation history. Extend this to identity history: when two
  previously-isolated clusters merge (e.g., two spacecraft enter
  communication range), they exchange history DAGs and converge on
  a unified membership.

### 3.3 Group Key Distribution

AT uses NaCl SecretBox with a shared group key for multicast messages.
Distributing new group keys requires reaching all members -- hard when
connectivity is intermittent.

**Adaptation**: Key epochs with overlap periods. A new key is
distributed as a high-priority bundle with extended lifetime. During
the overlap, nodes accept messages encrypted with either the old or
new key. The overlap duration is a function of the maximum expected
network partition time.

### 3.4 Reputation in Disconnected Partitions

If the network partitions into clusters A and B, each cluster's
reputation ledger diverges. When they reconnect:

- Conflicting Paxos sequences need reconciliation
- A node might have high reputation in cluster A and low in cluster B

**Approach**: Treat reputation as a CRDT-like structure. Each
transaction is a signed, timestamped record. On reconnection, nodes
exchange transaction logs (as bundles) and recompute reputation from
the merged history. AT's existing Merkle DAG sync provides the
mechanism; the merge semantics need to be defined for conflicting
scores.

## 4. Integration Architecture

### 4.1 Layered Approach: AT as a DTN Application

The least invasive integration: AT runs unchanged at the application
layer, with a DTN convergence layer adapter replacing UDP/TCP:

```
+--------------------------------------------------+
|  AT Application (identity, reputation, fleet)     |
+--------------------------------------------------+
|  AT Network Process (message routing)             |
+--------------------------------------------------+
|  DTN Convergence Layer Adapter                    |  <-- new
|  (translates AT messages to/from bundles)         |
+--------------------------------------------------+
|  BPv7 Bundle Protocol Agent                       |
|  (store-carry-forward, routing, fragmentation)    |
+--------------------------------------------------+
|  CLA: TCPCL | LTP | UDP | Radio | Data Mule      |
+--------------------------------------------------+
```

The CLA adapter would:
- Intercept outbound AT messages from the Network process
- Wrap each as a bundle (source EID from local identity, destination
  EID from target UUID, BPSec from AT's existing NaCl crypto)
- Submit to the local BP agent
- Receive inbound bundles and deliver them as AT messages to the
  appropriate process queue

**Advantage**: Minimal changes to AT core.
**Limitation**: AT's timeout-dependent protocols still break over
long-delay links without the adaptations described in section 3.1.

### 4.2 Deep Integration: AT-Native DTN

A more ambitious approach: redesign AT's network layer to be
DTN-native from the ground up.

- **Replace UDP/TCP sockets with a BP library** (e.g., ION's `bp_send`
  / `bp_receive`, or uD3TN's BPA API)
- **Map AT process names to EID service demux** -- each AT process
  registers as a DTN application endpoint
- **Use BPSec natively** -- AT's NaCl encryption becomes BPSec
  security contexts, eliminating double encryption
- **Leverage DTN routing** -- CGR or epidemic routing replaces AT's
  current assumption of direct UDP reachability
- **Use bundle lifetime + custody** as the reliability mechanism
  instead of AT's application-layer retransmission

```c
/* AT process registers as DTN endpoint */
bp_endpoint_t eid;
bp_open("dtn://at-node/identity", &eid);

/* Send identity announcement as a bundle */
bp_bundle_t bundle;
bp_bundle_create(&bundle);
bp_bundle_set_destination(&bundle, "dtn://~bcast/identity");
bp_bundle_set_lifetime(&bundle, 86400);  /* 24h */
bp_bundle_set_payload(&bundle, announcement, len);
bp_send(&eid, &bundle);
```

**Advantage**: Full DTN capabilities (store-carry-forward,
fragmentation, custody, routing) available to every AT protocol.
**Cost**: Significant rearchitecture of the network layer.

### 4.3 Hybrid: DTN Where Needed, IP Where Available

The pragmatic approach for real deployments:

```
  Ground Cluster          Space Link           Orbital Cluster
+----------------+                           +----------------+
| AT nodes       |    DTN (LTP/bundles)      | AT nodes       |
| (UDP, LAN)     |<========================>| (UDP, LAN)     |
| Normal AT      |    store-carry-forward    | Normal AT      |
+-------+--------+                           +--------+-------+
        |                                             |
   DTN Gateway                                   DTN Gateway
   (AT msg <-> bundle)                           (bundle <-> AT msg)
```

Within each cluster, AT runs normally over UDP/TCP (low latency,
full connectivity). The DTN gateway at each cluster boundary converts
AT messages to bundles for inter-cluster communication. The gateway
handles timeout adaptation, message buffering during link outages,
and protocol translation.

This mirrors how DTN is deployed on the ISS today: IP networking
aboard the station, DTN for the space-to-ground link.

## 5. Specific Use Cases

### 5.1 Space Mission Fleet Management

A constellation of satellites, each running an AT node. Ground
stations are also AT nodes. The fleet update system distributes
new binaries:

- Ground proposes update via `fleet_propose_update()`
- Proposal bundles propagate through DTN to all satellites
- Each satellite votes (bundles carrying votes traverse the network)
- On acceptance, artifact bundles (pre-fragmented) are distributed
  via DTN store-carry-forward -- satellites relay to each other
  during inter-satellite contact windows
- Each satellite applies the update autonomously when complete

The DTN contact graph ensures bundles reach all nodes even with
limited contact windows. AT's reputation system ensures only
trusted nodes can propose updates.

### 5.2 Disaster Recovery Mesh

After a natural disaster, first responders deploy AT nodes on
portable hardware. Connectivity is intermittent -- nodes move,
relays fail, bandwidth varies:

- Nodes discover each other opportunistically (DTN beacon bundles)
- Trust is established via pre-provisioned credentials (issued
  before deployment) or delegated admission from a command node
- Situational data flows as bundles, stored and forwarded by any
  node with contact
- AT's reputation system deprioritizes unreliable nodes (e.g., a
  node with a failing radio that corrupts data)
- Fleet updates push new software to the mesh as connectivity allows

### 5.3 Autonomous Vehicle Convoy

Vehicles in a convoy run AT nodes. Communication between vehicles
is direct (V2V radio, low latency). Communication with base is
intermittent (cellular coverage gaps, satellite backhaul):

- Intra-convoy: standard AT over UDP (fast, reliable)
- Convoy-to-base: DTN bundles, store-carry-forward
- Reputation governs which vehicles are trusted for relay
- A vehicle leaving convoy range carries bundles (data mule)
  and delivers them when it reaches base connectivity

## 6. Open Questions

- **Consensus latency tolerance**: What is the practical upper bound
  on RTT before AT's consensus protocols become unusable, even with
  parameterized timeouts? At what point must we switch from
  synchronous Paxos to eventually-consistent gossip?

- **Bundle security context mapping**: Can AT's NaCl Box/SecretBox
  be registered as BPSec security contexts, or does AT need to
  adopt BPSec's own cipher suites? The former preserves AT's
  existing crypto infrastructure; the latter avoids double encryption.

- **Reputation CRDT semantics**: How exactly should conflicting
  reputation scores merge after a network partition? Simple
  last-writer-wins is insufficient; AT's cooperative/tit-for-tat
  strategy selection depends on score trajectory, not just current
  value.

- **Contact-aware scheduling**: Should AT protocol events (votes,
  proposals, key rotations) be scheduled to align with predicted
  contact windows? This requires integration between AT and the
  DTN routing layer's contact graph.

- **Bundle lifetime vs. AT message freshness**: A stale identity
  announcement or reputation update could be misleading. How should
  AT validate message freshness when bundles may have been in
  store-carry-forward for hours or days?

- **Resource constraints**: DTN nodes in space or on embedded
  hardware have limited persistent storage. AT's bundle buffering
  must respect storage quotas -- which bundles get priority when
  storage is scarce? Trust-related bundles (identity, reputation)
  should likely outrank data bundles.

## 7. Conclusion

AT and DTN are complementary systems addressing different layers of
the same problem: how do autonomous agents cooperate reliably in
hostile, disconnected environments?

DTN provides the *transport* -- getting messages from A to B when
there is no continuous path. AT provides the *trust* -- deciding
whether A and B should cooperate at all, and how much to rely on
each other's contributions.

The most practical path forward is the hybrid gateway approach
(section 4.3): AT runs unmodified within connected clusters, DTN
bridges the gaps. This requires only a convergence layer adapter
and timeout parameterization, not a full rearchitecture.

The deeper integration (section 4.2) becomes worthwhile for
environments where *every* link is disrupted -- deep space
constellations, long-duration autonomous missions, or networks
of mobile sensors with no persistent infrastructure.

## References

- RFC 9171 -- Bundle Protocol Version 7 (BPv7), 2022
- RFC 9172 -- Bundle Protocol Security (BPSec), 2022
- RFC 9174 -- TCPCLv4, 2022
- RFC 5326 -- Licklider Transmission Protocol (LTP), 2008
- K. Fall, "A Delay-Tolerant Network Architecture for Challenged
  Internets," SIGCOMM '03, 2003
- S. Burleigh, "Contact Graph Routing," draft-burleigh-dtnrg-cgr
- A. Lindgren et al., "Probabilistic Routing in Intermittently
  Connected Networks," ACM SIGMOBILE, 2003
- L. Lamport, "Paxos Made Simple," ACM SIGACT News, 2001
  (foundation for AT's consensus protocol)
- M. Shapiro et al., "Conflict-free Replicated Data Types," SSS
  2011 (relevant to reputation merge after partition)
- NASA, "DTN on the International Space Station" --
  https://www.nasa.gov/directorates/heo/scan/engineering/technology/disruption-tolerant-networking/
- AT Architecture Documentation --
  doc/architecture/ (overview, networking, identity-protocol,
  reputation, space-communications)
