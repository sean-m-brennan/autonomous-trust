*Previous: [AutonomousTrust over DTN](at-over-dtn.md)*

# Autonomous Trust as an Internet Traffic Substrate

Speculative exploration: could AT carry conventional internet traffic (web
browsing, video streaming, general TCP/IP) as an overlay network? What would
that look like, and what problems would it solve?

## 1. Why Would You Want This?

The internet's trust model is broken at several layers:

- **Routing trust.** BGP hijacking allows any AS to announce routes
 for prefixes it doesn't own. There is no cryptographic verification
 that a route is legitimate (RPKI adoption remains partial).
- **Transit trust.** ISPs and transit providers can inspect, throttle,
 or modify traffic. End users have no choice in path selection.
- **Identity trust.** IP addresses say nothing about the identity or
 trustworthiness of the endpoint. DNS can be poisoned. TLS
 certificates verify domain ownership, not intent.
- **Service trust.** CDNs and cloud providers are trusted implicitly.
 A compromised CDN node can serve malicious content to millions.

AT provides *earned, dynamic, consensus-based trust* between peers. If internet
traffic flowed through an AT mesh, nodes could make routing and forwarding
decisions based on peer reputation rather than static configuration.

## 2. Architecture: AT as an Overlay Network

### 2.1 The Basic Model

```
+--------------------------------------------------+
|  Application (browser, video player, etc.)        |
+--------------------------------------------------+
|  SOCKS5 / HTTP Proxy / TUN interface              |  <-- entry point
+--------------------------------------------------+
|  AT Overlay Router                                |
|  - Accepts IP packets or TCP streams              |
|  - Encapsulates in AT messages                    |
|  - Routes through AT peer mesh                    |
|  - Selects next hop based on reputation + latency |
+--------------------------------------------------+
|  AT Node (identity, reputation, negotiation)      |
+--------------------------------------------------+
|  Underlay: UDP/TCP over the normal internet       |
+--------------------------------------------------+
```

Applications connect to a local proxy (SOCKS5, HTTP CONNECT, or a TUN/TAP
virtual interface). The proxy hands packets to the AT overlay router, which
encapsulates them in AT messages and forwards through the mesh. Exit nodes
decapsulate and forward to the destination.

This is structurally similar to Tor, I2P, or a VPN mesh -- but with the AT
dynamic trust model replacing static relay selection.

### 2.2 Encapsulation

AT messages are datagrams up to 1 MB. Two encapsulation strategies:

**a) Packet-level tunneling (L3)**

Each IP packet becomes an AT message payload:

```
AT Message:
  process: "tunnel"
  function: "forward"
  data: { "dst": "93.184.216.34", "proto": 6, "payload": "<base64 IP packet>" }
```

Simple, preserves IP semantics. But small packets (TCP ACKs, DNS queries) waste
overhead in the AT framing.

**b) Stream-level proxying (L4/L7)**

The entry node terminates TCP, buffers application data, and sends larger AT
messages:

```
AT Message:
  process: "tunnel"
  function: "stream_data"
  data: { "stream_id": "a1b2c3", "seq": 42, "payload": "<base64 chunk>" }
```

Better efficiency for streaming (video, large downloads). The AT overlay manages
its own flow control between hops.

For video streaming (YouTube), stream-level proxying is far more practical: the
entry node fetches via HTTP, transcodes the response into AT stream messages,
and the exit node (or caching peer) serves the content.

### 2.3 Routing Through the Mesh

Traditional overlay routing (Tor, VPN) selects a fixed circuit. AT adds a trust
dimension:

```
Entry Node --[reputation > 0.8]--> Relay A --[reputation > 0.8]--> Exit Node
                                      |
                                      v (reputation dropped to 0.5)
                                   Relay B (avoided)
```

**Route selection criteria.**
- **Peer reputation.** Only route through peers above a configurable
 trust threshold. A node caught tampering with traffic (detectable
 via integrity checks) loses reputation and is routed around.
- **Capability matching.** The AT negotiation system lets nodes
 advertise capabilities: "I have 100 Mbps exit bandwidth," "I can
 reach the 93.184.0.0/16 subnet." Route selection considers these.
- **Latency/throughput.** AT could track per-peer performance metrics
 as part of the reputation signal, enabling quality-aware routing.
- **Path diversity.** Avoid concentrating traffic through a single
 high-reputation node (load balancing + resilience).

### 2.4 Exit Nodes

Traffic must eventually leave the AT overlay and reach the public internet. Exit
nodes are AT peers that:

- Accept encapsulated traffic from the mesh
- Decapsulate and forward to the destination (like a NAT gateway)
- Return responses back through the overlay

Exit nodes take on legal and resource risk. The AT reputation and negotiation
systems provide natural mechanisms:

- Exit nodes can **negotiate compensation** (AT task negotiation)
 for bandwidth provided
- the reputation system **rates exit node reliability**
 -- an exit that drops connections or injects ads loses reputation
- Exit node **selection is trust-weighted**, so a malicious exit
 that modifies content is detected (e.g., TLS certificate
 mismatch at the application layer) and demoted

## 3. The YouTube Problem: Streaming Video

YouTube (and video streaming generally) is the hardest case: high bandwidth, low
latency, sustained throughput. Let's reason through it concretely.

### 3.1 Direct Proxying

The simplest model: the entry node's AT proxy establishes an HTTPS connection to
YouTube, retrieves the video stream, and tunnels it back through the AT mesh to
the client.

**Bandwidth.** A 1080p YouTube stream is ~5 Mbps. AT messages up to 1 MB. At 5
Mbps, that's ~0.6 messages/second -- easily within AT's messaging capacity.

**Latency.** Video streaming is tolerant of initial buffering (2-5 seconds). AT
overlay adds per-hop latency (encryption, routing, network process cadence).
With 2-3 hops at ~50ms each, total added latency is ~150ms -- acceptable for
streaming, though not for real-time video calls.

**Problem.** All traffic flows through one exit node. If that node is slow or
drops, the stream stutters.

### 3.2 Distributed Caching

A more interesting model: AT nodes cache popular content and serve it to peers.

```
Client -> Entry Node -> Cache Peer (has video segment) -> Client
                    \-> Exit Node -> YouTube (cache miss) -> ...
```

The AT fleet artifact distribution already implements chunked, hash-verified
content distribution. Video segments are content-addressable (hash of each
segment). A requesting node can:

1. Ask the mesh "who has segment X of video Y?"
2. Multiple peers may respond (content discovery via AT negotiation)
3. Download segments from multiple peers in parallel
4. Verify integrity via hash

This is essentially **BitTorrent semantics over an AT trust mesh**. The trust
layer adds:

- **Content integrity.** Peers that serve corrupted segments lose
 reputation
- **Availability incentives.** Peers that cache and serve content
 earn reputation (cooperative behavior rewarded)
- **Access control.** The group can decide what content to cache
 (policy enforcement without a central authority)

### 3.3 Adaptive Bitrate with Trust

Modern video streaming uses adaptive bitrate (ABR): the client picks quality
based on available bandwidth. In an AT mesh:

- The client's AT node monitors throughput to each relay
- Reputation scores correlate with reliability (high-reputation
 peers deliver consistent throughput)
- The ABR algorithm factors in the trust-weighted available
 bandwidth of the current path
- If a relay's reputation drops (indicating degraded service),
 the stream re-routes through a different path before the user
 notices quality degradation

## 4. What AT Adds Over Existing Overlay Networks

### 4.1 Compared to Tor

| Aspect | Tor | AT Overlay |
|--------|-----|-----------|
| **Trust model** | Directory authorities (centralized) | Decentralized reputation consensus |
| **Relay selection** | Random (with guard/exit flags) | Reputation-weighted |
| **Bad relay detection** | Manual flagging, consensus vote | Automated reputation demotion |
| **Incentive** | Volunteer-only | Task negotiation (compensation possible) |
| **Privacy** | Onion routing (strong anonymity) | Encrypted peer-to-peer (not anonymity-focused) |
| **Performance** | Often slow (volunteer bandwidth) | Trust-weighted path selection optimizes throughput |

AT is not an anonymity network. It's a *trust* network. The threat model is
different: Tor protects against surveillance; AT protects against unreliable or
malicious peers in a cooperative system.

### 4.2 Compared to VPN Meshes (WireGuard, Tailscale)

| Aspect | VPN Mesh | AT Overlay |
|--------|----------|-----------|
| **Peer admission** | Manual key exchange or central coordinator | Consensus-based admission with voting |
| **Routing** | Static (IP-based) or coordinator-assigned | Dynamic, reputation-aware |
| **Peer quality** | Assumed good after admission | Continuously evaluated via reputation |
| **Misbehavior** | Manual removal | Automatic demotion and routing bypass |

### 4.3 Compared to IPFS/libp2p

| Aspect | IPFS/libp2p | AT Overlay |
|--------|-------------|-----------|
| **Content addressing** | Yes (CID) | Could use artifact hash (blake2b-256) |
| **Trust** | None (any peer can serve any content) | Reputation-gated content serving |
| **Incentive** | Filecoin (separate token economy) | AT reputation + negotiation (no token) |
| **Routing** | DHT (Kademlia) | Reputation-weighted mesh |

## 5. Technical Challenges

### 5.1 Throughput

The current AT network process runs at 500ms cadence with 1 MB max message size.
Theoretical maximum: ~2 MB/s = 16 Mbps per hop. This is sufficient for a single
1080p stream but not for 4K (20+ Mbps) or multiple concurrent streams.

**Adaptations needed.**
- Increase `NET_MSG_MAX_DATA` or support message chaining
- Reduce cadence for the tunnel process (dedicated high-frequency
 forwarding loop, separate from the 500ms AT process cadence)
- Use TCP CLAs for sustained throughput (AT already supports TCP
 for large messages)

### 5.2 Encryption Overhead

AT encrypts every peer-to-peer message with NaCl Box (Curve25519 +
XSalsa20-Poly1305). At 5 Mbps, that's ~625 KB/s of data to encrypt/decrypt per
hop. NaCl crypto is fast (~1 GB/s on modern hardware), so this is not a
bottleneck. But multi-hop paths multiply the overhead: 3 hops = 3x
encrypt/decrypt cycles.

For bulk data (video), a session key negotiated once (via AT's existing NaCl Box
handshake) and used with a stream cipher would reduce per-message overhead.

### 5.3 NAT Traversal

AT currently uses direct UDP/TCP between peers, which requires either public IPs
or NAT traversal. For a general-purpose overlay:

- **STUN/TURN integration.** AT peers behind NAT use STUN to
 discover their external address and TURN relays as fallback
- **Relay-as-capability.** AT nodes with public IPs advertise
 relay capability; NAT'd nodes negotiate relay service via AT's
 task system
- **UDP hole punching.** Peers behind symmetric NATs use a
 rendezvous server (an AT peer with public IP) to establish
 direct connections

### 5.4 DNS and Service Discovery

For the overlay to be transparent to applications, it needs to handle DNS:

- DNS queries can be tunneled through the overlay (like Tor's
 DNS resolution via exit nodes)
- Alternatively, AT nodes could run a distributed DNS cache,
 with reputation protecting against poisoning
- For AT-internal services, EID-based naming replaces DNS entirely

### 5.5 Real-Time Traffic

Video streaming works (buffering tolerates latency). But real-time applications
(VoIP, video conferencing, gaming) need <100ms end-to-end latency:

- the AT 500ms cadence is too slow for real-time
- A dedicated "fast path" tunnel process with sub-millisecond
 forwarding (bypass the general message queue) would be needed
- Reputation-based path selection could prioritize low-latency
 peers for real-time traffic (QoS by trust class)

## 6. A Practical Starting Point

Rather than carrying all internet traffic, a pragmatic first step:

**AT-protected content distribution.** Use the existing AT artifact distribution
system (chunked, hash-verified, reputation-gated) to serve static content
(software updates, media files, datasets) within a trusted mesh. This requires
no protocol changes -- it's what the fleet update system already does,
generalized beyond binaries.

**Evolution path.**
1. Static content distribution (fleet artifacts) -- *exists today*
2. Content-addressable caching (video segments, web assets)
3. Stream proxying (live video, web browsing)
4. Full tunnel (TUN interface, arbitrary IP traffic)

Each step adds complexity but builds on the previous one. The trust and
reputation infrastructure is the constant -- it's what makes the AT approach
different from "just another overlay network."

## 7. Conclusion

AT can carry internet traffic, but it's not the right question. The right
question is: *what traffic benefits from trust-aware routing?*

- **Software distribution.** High value. Integrity and
 source verification matter. The existing AT fleet system is
 already this.
- **Content delivery.** Medium-high value. Cache poisoning and
 CDN compromise are real threats. Reputation-gated caching
 addresses this.
- **Web browsing.** Medium value. Useful for circumventing
 censorship or routing around unreliable ISPs, but competes
 with VPNs and Tor.
- **Bulk streaming (YouTube).** Low-medium value. The main benefit
 is distributed caching and resilient multi-path delivery, not
 trust per se.
- **Real-time communication.** Low value for trust, high cost
 in latency. Better served by direct connections with AT
 providing the trust handshake at connection setup, not
 per-packet routing.

The sweet spot is applications where *who you're getting data from matters as
much as getting it at all* -- and that's a broader category than it first
appears.

## References

- R. Dingledine, N. Mathewson, P. Syverson, "Tor: The Second-Generation
 Onion Router," USENIX Security, 2004
- J. Benet, "IPFS -- Content Addressed, Versioned, P2P File System,"
 arXiv:1407.3561, 2014
- B. Cohen, "Incentives Build Robustness in BitTorrent," Workshop on
 Economics of Peer-to-Peer Systems, 2003
- J. A. Donenfeld, "WireGuard: Next Generation Kernel Network Tunnel,"
 NDSS, 2017
- A. Narayanan, V. Shmatikov, "De-anonymizing Social Networks," IEEE
 S&P, 2009 (relevant to overlay privacy limitations)
- AT Architecture Documentation -- doc/architecture/ (networking,
 negotiation, reputation)

---

*Next: [The integration API](api.md)*
