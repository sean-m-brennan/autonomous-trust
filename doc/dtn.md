*Previous: [Space communications](architecture/space-communications.md)*

# Delay Tolerant Networks (DTN): Technical Summary

## 1. Overview

Delay Tolerant Networks (DTN) provide reliable data transfer across networks
that suffer from **intermittent connectivity**, **long or variable delays**, and
**frequent partitioning**. Traditional internet protocols assume a continuous
end-to-end path between source and destination; DTN relaxes this assumption
entirely.

DTN was originally motivated by deep-space communication (the Interplanetary
Internet concept), where one-way light delays can exceed 20 minutes and link
availability is governed by orbital mechanics. The architecture has since proven
applicable to any environment where end-to-end connectivity cannot be
guaranteed:

- **Space communication**, Earth-to-spacecraft, relay satellite constellations, lunar/Mars surface networks
- **Tactical military networks**, mobile units with sporadic radio contact
- **Disaster recovery**, infrastructure-damaged regions with intermittent links
- **Remote sensor networks**, wildlife tracking, environmental monitoring, rural IoT
- **Developing regions**, networks relying on data mules (vehicles carrying data between disconnected sites)

The core problem: in all these environments, no instantaneous end-to-end path
may exist at any given moment. Data must be **stored at intermediate nodes**,
**carried** through physical or scheduled movement, and **forwarded** when a
link to the next hop becomes available.

## 2. Architecture and Protocols

### The Bundle Protocol

The foundational protocol of DTN is the **Bundle Protocol (BP)**. It operates as
an overlay network layer that sits **above** the transport layer (or any
underlying protocol), treating diverse link technologies as interchangeable
substrates.

```
+---------------------+
|    Application      |
+---------------------+
|   Bundle Protocol   |   <-- overlay "bundle layer"
+---------------------+
| Convergence Layer   |   <-- adapts BP to underlying transport
+---------------------+
| Transport (TCP/UDP) |   (or LTP, Bluetooth, RF link, etc.)
+---------------------+
|    Network/Link     |
+---------------------+
```

**Key RFCs.**

| Standard | RFC | Year | Description |
|----------|-----|------|-------------|
| BPv6 | RFC 5050 | 2007 | Original Bundle Protocol (Experimental) |
| **BPv7** | **RFC 9171** | **2022** | Current Bundle Protocol version (Standards Track) |
| BPSec | RFC 9172 | 2022 | Bundle Protocol Security |
| TCPCLv4 | RFC 9174 | 2022 | TCP Convergence Layer v4 |
| LTP | RFC 5326 | 2008 | Licklider Transmission Protocol |

BPv7 (RFC 9171) is the current standard and represents a significant
simplification and modernization over BPv6.

### Bundles

The fundamental data unit is a **bundle**, a self-contained, self-describing
message composed of a sequence of **blocks**:

- **Primary Block**, contains source/destination endpoint IDs, creation timestamp, lifetime, and processing flags. Exactly one per bundle.
- **Payload Block**, carries the application data. Exactly one per bundle.
- **Extension Blocks**, zero or more blocks providing additional metadata (e.g., Previous Node, Bundle Age, Hop Count).

Bundles are designed to be **atomic units of store-carry-forward**: each bundle
contains all addressing and metadata needed for independent routing and
delivery.

### Store-Carry-Forward

Unlike IP's store-and-forward (which assumes the next hop is immediately
reachable), DTN uses **store-carry-forward**:

1. **Store**, A node receives a bundle and persists it to stable storage (disk, flash). Bundles may be stored for seconds, hours, or days.
2. **Carry**, The node retains the bundle while waiting for a contact opportunity. In data-mule scenarios, the node physically moves.
3. **Forward**, When a link to the next hop (or destination) becomes available, the bundle is transmitted.

This model requires **persistent storage** at intermediate nodes, a fundamental
departure from IP routers that buffer packets only transiently in memory.

### Convergence Layers

Convergence Layer Adapters (CLAs) bridge the Bundle Protocol to specific
underlying transport protocols. They handle the mechanics of actually
transmitting bundle bytes over a particular link type.

**Major CLAs.**

- **TCPCLv4 (RFC 9174)**, Runs over TCP/IP. Provides reliable, bidirectional bundle transfer with TLS support. The primary CLA for terrestrial/IP-connected segments.
- **LTP (RFC 5326)**, Licklider Transmission Protocol. Designed for long-delay, single-hop links (e.g., deep-space). Provides optional reliability with red/green data segments. Typically runs over UDP or directly over a link-layer protocol.
- **UDP CLA**, Lightweight, connectionless. Suitable for local or low-overhead transfers where TCP's connection setup is undesirable.
- **STCP**, Simple TCP CLA, a minimal framing protocol used in some implementations.
- Other CLAs exist or are in development for Bluetooth, LoRa, serial links, and other media.

### Contact Graph Routing

In scheduled networks (e.g., space networks with known orbital mechanics),
**Contact Graph Routing (CGR)** uses a time-varying graph of predicted link
availability to compute optimal forwarding paths. Each "contact" specifies a
time window, a pair of nodes, and a data rate.

For opportunistic networks, epidemic routing, spray-and-wait, and PRoPHET are
among the strategies used.

## 3. Key Features

### Endpoint IDs and Naming

DTN uses **Endpoint IDs (EIDs)** to identify bundle sources and destinations.
BPv7 defines two URI schemes:

- **`dtn:` scheme**, hierarchical, human-readable names:
  ```
  dtn://sensor-node-42/temperature
  dtn://mars-relay/science-downlink
  dtn:none                            (null endpoint, for anonymous sources)
  ```
- **`ipn:` scheme**, compact numeric addressing optimized for constrained environments:
  ```
  ipn:13.1    (node 13, service 1)
  ipn:2.0     (node 2, administrative endpoint)
  ```

The `ipn:` scheme uses CBOR encoding for compactness; the `dtn:` scheme is more
expressive. Both are first-class citizens in BPv7.

### Late Binding

DTN performs **late binding** of names to addresses. A bundle's destination EID
is resolved to a next-hop CLA address only when a forwarding opportunity arises,
not at the time of creation. This decouples naming from routing and is essential
when the network topology is unknown or changing.

### Custody Transfer (BPv6) and Bundle Reliability

In BPv6, **custody transfer** allowed a receiving node to accept responsibility
for a bundle, relieving the sender of storage obligations. This provided
hop-by-hop reliability without end-to-end acknowledgment.

BPv7 removed custody transfer from the core protocol to simplify the
specification. Reliability in BPv7 is expected to be handled through:

- Convergence layer reliability (e.g., TCPCLv4's transfer acknowledgments)
- Application-layer acknowledgments
- The **Bundle Protocol Care-of-Transfer (BPCOT)** extension, which is being developed to restore custody semantics as an optional feature

### Fragmentation and Reassembly

BP supports two forms of fragmentation:

- **Proactive fragmentation**, The source pre-fragments a large bundle into smaller bundles before transmission, when the maximum transfer size of a link is known.
- **Reactive fragmentation**, An intermediate node fragments a partially-transmitted bundle when a contact ends before the full bundle is sent. The transmitted portion becomes one fragment; the remainder becomes another.

Each fragment is a valid bundle with offset and total-payload-length fields in
its primary block, enabling independent routing and reassembly at the
destination.

### Bundle Status Reports

BPv7 defines **administrative records** including bundle status reports. A
bundle's source can request status reports for these events:

- **Received**, bundle was received by a node
- **Forwarded**, bundle was forwarded to the next hop
- **Delivered**, bundle was delivered to the destination application
- **Deleted**, bundle was deleted (with a reason code)

Status reports are themselves bundles, sent to the bundle's **report-to** EID.

### Extension Blocks

BPv7 defines a flexible extension block mechanism. Standard extension blocks
include:

- **Previous Node Block**, records the EID of the last forwarding node
- **Bundle Age Block**, tracks elapsed time since creation (critical when nodes lack synchronized clocks)
- **Hop Count Block**, limits the number of forwarding hops to prevent routing loops

Additional extension blocks can be defined for custom metadata,
quality-of-service parameters, or application-specific data.

## 4. Recent Developments

### BPv7 Standardization (2022)

The publication of **RFC 9171 (BPv7)**, **RFC 9172 (BPSec)**, and **RFC 9174
(TCPCLv4)** in 2022 marked DTN's transition from Experimental to **Standards
Track** status at the IETF. Key changes from BPv6:

- CBOR (RFC 8949) encoding replaces SDNV-based binary format
- Simplified block structure
- Custody transfer removed from core spec
- CRC integrity checks added to all blocks
- Clearer extension block processing rules

### BPSec, Bundle Protocol Security (RFC 9172)

BPSec provides **hop-by-hop and end-to-end security** for bundles through two
security block types:

- **Block Integrity Block (BIB)**, provides integrity protection (e.g., HMAC-SHA256) for a target block. The target block remains in plaintext.
- **Block Confidentiality Block (BCB)**, provides confidentiality (encryption) for a target block's data.

Security contexts define the specific cryptographic algorithms and key
management approaches. BPSec is designed to allow intermediate nodes to verify
integrity without decrypting confidential payload, supporting the
store-carry-forward model where intermediate nodes must make routing decisions
on blocks they cannot read.

### DTNMA, DTN Management Architecture

The **DTN Management Architecture (DTNMA)** addresses network management in
disruption-tolerant environments where traditional SNMP-style polling is
infeasible. Key components:

- **Asynchronous Management Model (AMM)**, defines managed objects and management operations
- **Autonomous management**, nodes can execute pre-configured management policies without real-time operator interaction
- **AMP (DTNMA Management Protocol)**, the protocol for exchanging management information as bundles

DTNMA is under active development in the IETF DTN working group.

### Major Implementations

| Implementation | Origin | Language | Notes |
|---------------|--------|----------|-------|
| **ION** | NASA JPL | C | Reference implementation. Flight-qualified. Used on ISS. Supports BPv7, LTP, CGR. |
| **HDTN** | NASA Glenn | C++ | High-rate DTN. Optimized for high throughput (100+ Gbps target). BPv7. |
| **DTN7** | D. Brecht et al. | Go / Rust | Lightweight research implementations. BPv7. |
| **uD3TN** | D-Space (formerly TU Dresden) | C / Python | Designed for embedded/microcontroller targets. BPv7. POSIX and FreeRTOS support. |
| **IBR-DTN** | TU Braunschweig | C++ | Mature BPv6 implementation. Widely used in research but largely superseded by BPv7 implementations. |
| **DTNME** | MITRE | C++ | Fork of DTN2 reference. Government/military focus. |

### IETF DTN Working Group

The IETF DTN WG continues active work on:

- BPCOT (custody transfer for BPv7)
- TCPCLv4 extensions
- BPSec security contexts
- DTNMA specifications
- Default security contexts for BPSec (RFC 9173)
- DTN routing protocols

The Consultative Committee for Space Data Systems (CCSDS) maintains parallel
specifications for space-network use of BP, ensuring interoperability between
IETF and space-agency standards.

## 5. Interfacing with TCP/IP Networks

### The Overlay Relationship

DTN operates as an **overlay network** on top of TCP/IP (and other protocol
suites). This means:

- DTN nodes **can simultaneously be IP endpoints**. A server might run both a web server and a bundle agent.
- Bundles are transported **inside** TCP connections, UDP datagrams, or other IP-based transports via convergence layers.
- The DTN "network" is a logical topology layered over potentially heterogeneous underlying networks.

```
  DTN Node A                    DTN Node B                    DTN Node C
  (Earth station)               (Relay satellite)             (Mars rover)
  +-----------+                 +-----------+                 +-----------+
  | Bundle    |                 | Bundle    |                 | Bundle    |
  | Protocol  |                 | Protocol  |                 | Protocol  |
  +-----------+                 +-----------+                 +-----------+
  | TCPCLv4   |---TCP/IP link---| LTP/UDP   |---RF/LTP link--| LTP       |
  +-----------+                 +-----------+                 +-----------+
```

### TCPCL as the Bridge

**TCPCLv4 (RFC 9174)** is the primary mechanism for transporting bundles over
TCP/IP networks:

- Establishes a TCP connection between two DTN nodes
- Performs a session negotiation (transfer MTU, keepalive interval)
- Supports **TLS 1.3** for link-level encryption and authentication
- Provides **transfer acknowledgments**, the receiving node confirms complete reception of each bundle
- Supports **transfer refusal**, a node can decline a bundle (e.g., due to storage constraints)

From the IP network's perspective, TCPCL traffic is just TCP on a configured
port (default 4556). Standard IP routing, firewalling, and QoS can be applied.

### DTN Gateways and Proxies

In hybrid networks, **DTN gateways** bridge between DTN-aware and DTN-unaware
segments:

- A gateway node terminates both IP-based and disruption-prone links
- It accepts bundles via TCPCL from the IP side, stores them, and forwards via LTP (or other CLA) when the disrupted link is available
- For legacy applications, a **DTN proxy** can encapsulate IP traffic (e.g., HTTP requests) into bundles for transport across a disrupted segment, then de-encapsulate at the far end

This pattern is used in space networks where ground stations act as gateways
between the terrestrial internet and deep-space links.

### Practical Topologies

**Space-to-Ground.**
```
Mission Control --[TCP/IP]--> Ground Station --[DTN/LTP]--> Relay Orbiter --[DTN/LTP]--> Rover
                  (reliable)    (DTN gateway)   (scheduled)                  (scheduled)
```
Bundles traverse the terrestrial internet via TCPCL, are stored at the ground
station until a communication window opens, then forwarded via LTP over the
space link.

**Tactical Military.**
```
HQ --[TCP/IP]--> Forward Base --[DTN/RF]--> Patrol Unit --[DTN/RF]--> Dismounted Soldier
      (stable)    (DTN gateway)  (intermittent)            (opportunistic)
```
The forward base stores bundles during communication blackouts and forwards when
radio contact resumes.

**Disaster Recovery.**
```
Relief Coord. --[TCP/IP]--> Edge Router --[DTN/WiFi]--> Mobile Relay (vehicle) --[DTN]--> Field Teams
                             (DTN gateway)                (data mule)
```
Vehicles physically carry bundles between disconnected network segments.

**IoT/Sensor Networks.**
```
Cloud Backend --[TCP/IP]--> Base Station --[DTN/LoRa]--> Sensor Node Cluster
                             (DTN gateway)  (intermittent, low-power)
```
Sensor nodes bundle readings and transmit during scheduled or opportunistic
contacts with the base station.

### Bundle Flow Across Hybrid Networks

A typical bundle traversal through a hybrid DTN/IP network:

1. Source application submits data to the local bundle agent with destination EID `ipn:42.3`
2. Bundle agent creates a bundle, consults routing tables, determines next hop is reachable via TCPCL
3. TCPCLv4 transmits the bundle over a TCP connection to the next DTN node
4. Intermediate DTN node (gateway) receives the bundle, stores it, determines next hop requires LTP over a scheduled space link
5. When the contact window opens, LTP transmits the bundle over the space link
6. Destination node receives the bundle, delivers the payload to the application registered for service `3`

The bundle itself is unchanged across these hops. Only the convergence layer and
underlying transport vary per link segment.

## 6. Comparison with TCP/IP

### Why TCP Fails in Disrupted Environments

TCP was designed with assumptions that do not hold in DTN environments:

| Assumption | TCP/IP Reality | DTN Environment |
|-----------|---------------|-----------------|
| **End-to-end path exists** | Required for connection establishment | Path may never exist simultaneously end-to-end |
| **Round-trip time** | Milliseconds to low seconds | Seconds to hours (e.g., Mars: 4-24 min one-way) |
| **Packet loss = congestion** | TCP interprets loss as congestion signal | Loss is often due to link unavailability, not congestion |
| **Symmetric bandwidth** | Generally assumed | Space links are often highly asymmetric |
| **Continuous connectivity** | Required to maintain connection state | Links may be available for minutes per day |

Specific failure modes of TCP in disrupted networks:

- **Three-way handshake**, SYN-ACK round trip may exceed timeout thresholds. A 20-minute one-way delay means 40+ minutes for handshake completion, assuming no loss.
- **Retransmission timers**, TCP's RTO calculations (RFC 6298) produce retransmit intervals that are meaningless when the link won't be available for hours.
- **Congestion window**, TCP backs off exponentially on perceived loss, throttling throughput to near-zero when losses are due to link disruption rather than congestion.
- **Connection state**, TCP maintains per-connection state in kernel memory. This state is lost on timeout, requiring full reconnection for every disruption.
- **Buffer requirements**, TCP's bandwidth-delay product (BDP) for a high-delay link demands enormous buffer sizes. A 1 Gbps link with 20-minute RTT requires ~150 GB of buffer.

### Fundamental Paradigm Differences

| Aspect | TCP/IP | DTN |
|--------|--------|-----|
| **Forwarding model** | Store-and-forward (transient memory) | Store-carry-forward (persistent storage) |
| **Reliability scope** | End-to-end (TCP) | Hop-by-hop (CLA) + optional end-to-end |
| **Naming** | IP addresses bound at send time | EIDs with late binding |
| **Data unit** | Packets/segments (small, stateless) | Bundles (potentially large, self-describing) |
| **Error handling** | Retransmit from source | Retransmit from last custodian/storing node |
| **State location** | Endpoints (TCP connection state) | Network (bundles stored at intermediate nodes) |
| **Routing** | Instantaneous topology | Time-varying topology (contact plans) |
| **Security** | TLS per connection | BPSec per bundle (survives store-carry-forward) |

### Complementary, Not Competing

DTN does not replace TCP/IP. It operates **over** TCP/IP where IP connectivity
exists and **bridges gaps** where it does not. The convergence layer
architecture allows a single bundle to traverse TCP/IP segments, space links,
radio links, and data mules in a single end-to-end transfer, something no single
transport protocol can achieve.

---

## References

- RFC 9171, Bundle Protocol Version 7 (2022)
- RFC 9172, Bundle Protocol Security (BPSec) (2022)
- RFC 9173, Default Security Contexts for BPSec (2022)
- RFC 9174, Delay-Tolerant Networking TCP Convergence-Layer Protocol Version 4 (2022)
- RFC 5326, Licklider Transmission Protocol (2008)
- RFC 4838, Delay-Tolerant Networking Architecture (2007)
- RFC 5050, Bundle Protocol Specification (BPv6, Experimental) (2007)
- RFC 6298, Computing TCP's Retransmission Timer (2011)
- CCSDS 734.2-B-1, CCSDS Bundle Protocol Specification (2015)
- IETF DTN Working Group, https://datatracker.ietf.org/wg/dtn/about/

## Further Reading

### Foundational Papers

- K. Fall, "A Delay-Tolerant Network Architecture for Challenged Internets," *SIGCOMM '03*, 2003. The original DTN paper that introduced the architecture.
- V. Cerf et al., "Delay-Tolerant Networking Architecture," RFC 4838, 2007. The architectural RFC that formalized DTN concepts.
- S. Burleigh et al., "Delay-Tolerant Networking: An Approach to Interplanetary Internet," *IEEE Communications Magazine*, 41(6), 2003. Motivating DTN from the space communications perspective.

### Protocol Specifications

- S. Burleigh, K. Fall, E. Birrane, "Bundle Protocol Version 7," RFC 9171, January 2022. https://www.rfc-editor.org/rfc/rfc9171
- E. Birrane, K. McKeever, "Bundle Protocol Security (BPSec)," RFC 9172, January 2022. https://www.rfc-editor.org/rfc/rfc9172
- B. Sipos et al., "Delay-Tolerant Networking TCP Convergence-Layer Protocol Version 4," RFC 9174, January 2022. https://www.rfc-editor.org/rfc/rfc9174
- S. Burleigh et al., "Licklider Transmission Protocol, Specification," RFC 5326, 2008. https://www.rfc-editor.org/rfc/rfc5326
- E. Birrane, "DTN Management Architecture (DTNMA)," draft-ietf-dtn-dtnma, IETF (work in progress). https://datatracker.ietf.org/doc/draft-ietf-dtn-dtnma/

### Implementations

- **ION** (Interplanetary Overlay Network), JPL's reference implementation, flight-proven on ISS. https://sourceforge.net/projects/ion-dtn/
- **HDTN** (High-rate Delay Tolerant Network), NASA Glenn's high-throughput implementation in C++. https://github.com/nasa/HDTN
- **DTN7**, Modern Go implementation of BPv7. https://github.com/dtn7
- **uD3TN** (micro Disruption-tolerant Networking), Lightweight BPv7 for embedded/IoT in C. https://gitlab.com/d3tn/ud3tn
- **Serval Project**, DTN for mobile ad-hoc networks, mesh-based. https://www.servalproject.org/

### Routing & Contact Planning

- S. Burleigh, "Contact Graph Routing," draft-burleigh-dtnrg-cgr, IRTF. The dominant routing algorithm for scheduled-contact DTNs.
- A. Lindgren et al., "Probabilistic Routing in Intermittently Connected Networks," *ACM SIGMOBILE*, 2003. PRoPHET protocol for opportunistic routing.
- J. Burgess et al., "MaxProp: Routing for Vehicle-Based Disruption-Tolerant Networks," *IEEE INFOCOM*, 2006. Routing for mobile DTN nodes.

### Surveys & Overviews

- Y. Cao, Z. Sun, "Routing in Delay/Disruption Tolerant Networks: A Taxonomy, Survey and Challenges," *IEEE Communications Surveys & Tutorials*, 15(2), 2013. Comprehensive routing survey.
- A. McMahon, S. Farrell, "Delay- and Disruption-Tolerant Networking," *IEEE Internet Computing*, 13(6), 2009. Accessible overview of DTN for networking practitioners.
- CCSDS, "Rationale, Scenarios, and Requirements for DTN in Space," CCSDS 734.0-G-1 (Green Book), 2010. https://public.ccsds.org/

### DTN in Practice

- NASA, "DTN on the International Space Station." ISS has used DTN (ION) operationally since 2016 for store-and-forward data relay. https://www.nasa.gov/directorates/heo/scan/engineering/technology/disruption-tolerant-networking/
- W. Ivancic et al., "Experience with Delay-Tolerant Networking from Orbit," *AIAA SpaceOps*, 2010. Early operational DTN results.
- G. Araniti et al., "Contact Graph Routing in DTN Space Networks: Overview, Enhancements and Performance," *IEEE Communications Magazine*, 53(3), 2015. Practical CGR performance in space.

---

*Next: [AutonomousTrust over DTN](at-over-dtn.md)*
