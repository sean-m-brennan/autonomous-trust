# DAF27TZ01-DV002: Cyber Resiliency for Fog and Edge Computing Devices

Transcribed on 2026-10-23 from the DSIP topics app (public API, topic id
`125b6b1f1e1c4a41a3f1456356d6af7c_86703`) and from the DAF D2P2 instructions
(`DAF_STTR_27TZ_D2P2_R1.pdf`, pp. DAF-23 and DAF-24), which carry the full
description. The Q&A is reproduced as posted.

| Field | Value |
|---|---|
| Program | STTR, Direct to Phase II (D2P2) |
| Solicitation | DoW STTR 2027 BAA (27.TZ), Release 1 |
| Component / command | USAF / AFMC |
| Status at transcription | Pre-release; Q&A completed |
| Pre-release (direct TPOC contact) | 2026-10-07 08:00 ET to 2026-10-28 08:00 ET |
| Topic Q&A closes | 2026-11-11 12:00 ET |
| Proposals due | 2026-11-25 12:00 ET |
| CMMC | Level 2 (Self) |
| ITAR | Yes |
| TPOCs | Erik Blasch (USAF, 703-835-2309); Khanh Pham (USSF, 505-331-6995) |
| Technology areas | Electronics; Information Systems |
| Focus area | Advanced Computing and Software |
| Keywords | Cyber Resiliency, Cyber Security, Fog and Edge Computing, Internet of Things, Avionics Systems, Space Systems |
| Critical technology area | Advanced Computing and Software |
| Award ceiling / duration | $2,000,000 / 24 months (DAF topic index) |
| Technical volume limit | 35 pages (DAF topic index) |
| Component instructions | `DAF_STTR_27TZ_D2P2_R1.pdf` |

## Objective

Develop a capability to prevent and/or mitigate cyber-attacks on fog and edge
computing (FEC) devices and associated networks to provide mission assurance in
highly contested environments.

## Description

The Air Force Critical Technology Areas [1] include the ability to optimize
advanced battle management systems (ABMS), develop next-generation platforms for
air dominance, and provide resilient space-based services as well as air and
space communications in a contested environment. In order to achieve these
objectives, next-generation Artificial Intelligence (AI) based FEC devices [2]
and networks require cyber resiliency to provide mission assurance. Cyber
threats include advanced persistent threats introduced via the supply chain
[3-4], remote system exploitation via wireless communication channels, physical
access attacks on in-theater acquired (downed) or otherwise compromised devices,
or attacks on the internal AI algorithms used on these devices. Challenges
associated with the design and development of cyber resiliency for FEC devices
include (1) cost, size, weight, and power (C-SWaP), which limits the ability to
host processor-intensive and memory-intensive cyber protections or deploy
expensive add-on trusted hardware; (2) the ability to scale to a large number
(i.e., 100s-1000s) of edge-nodes, and (3) the ability to detect and respond to
threats autonomously, which is particularly important for remote air and ground
assets operating in a harsh environment where human-personnel are limited, or
space-based assets where the response latencies must be minimized to avoid
compromise.

In order to provide cyber resiliency to FEC devices, previous solutions have
proposed to utilize hardware-based obfuscation, redundancy, and network
partitioning to mitigate attacks. However, these solutions require hardware
components, such as FPGAs or custom processors, that may not be in widespread
use on FEC devices or are too expensive relative to the overall cost of the
aircraft; special-purpose compilers which impede adoption of the technologies;
solutions that don't scale well with the number of fog/edge-nodes; or
network-based solutions that don't defend the fog/edge-nodes which could be the
target of a supply chain attack and circumvent perimeter defenses.

The goal of this topic is to develop cyber protection solutions that address the
above limitations and can be widely deployed across different classes of FEC
devices. These devices include, but are limited to, small, unmanned aircraft
systems (sUAS), miniaturized satellites, and Internet of Battle Things (IoBT)
[5]. The cyber defense mechanisms must adapt to changing circumstances and work
autonomously with limited reliance on support and maintenance services.
Particular classes of cyber-attacks of concern include supply chain attacks,
remote exploits that lead to advanced persistent threats, and AI algorithm
exploitation. The ability of the FEC devices to fight through a cyber-attack by
responding to threats in real-time to accomplish the mission is an essential
outcome of this research.

## Phase I

No Phase I proposals or awards. Offerors demonstrate Phase I-type feasibility
through prior research, development, laboratory validation, commercial
development or operational demonstration performed outside the SBIR/STTR
program. The feasibility study should include an approach, architecture and
previous demonstration of a limited-scope prototype with the ability to prevent
or mitigate a single class of cyber-attacks on an edge-node device, embedded
device, or a similar device. The approach should be capable of scaling to a
large number of edge-nodes and have the ability to autonomously detect and
respond to an attack.

## Phase II

The D2P2 effort should expand on previous work to increase the robustness of the
cyber protection and the classes of threats addressed, specifically improving
detection and response. It should also demonstrate the ability of the FEC
devices to fight through a supply-chain or remote-exploit attack to accomplish
mission objectives.

## Phase III

Commercial and military avionics and space-system applications, and a broad
class of commercial applications including IoT, the Internet of Battle Things
(IoBT) and the Internet of Space Things (IoST).

## References

1. https://www.cto.mil/cta/
2. Iftikhar, S., et al. "AI-based fog and edge computing: A systematic review,
   taxonomy and future directions." *Internet of Things* (2022): 100674.
3. Javed, S. H., et al. "An intelligent system to detect advanced persistent
   threats in industrial internet of things (I-IoT)." *Electronics* 11.5
   (2022): 742.
4. Carpenter, B. "How the IoT Intensifies Software Supply Chain Risks,"
   CyberArk blog, Dec. 2, 2022.
5. Kott, A., Swami, A., and West, B. J. "The Internet of Battle Things."
   *Computer* 49.12 (2016): 70-75.
6. "Internet of Things." Wikipedia, accessed March 28, 2023.
7. Internet of Space Things, Georgia Tech licensing, accessed March 28, 2023.

## Q&A

**Q1.** Does preventing execution of unauthenticated or tampered firmware,
updates or commands (supply-chain and remote-exploit classes) through
cryptographic verification count as preventing a "single class of
cyber-attack" on an edge node? Must the feasibility prototype include
autonomous detection and response, or is automated prevention with logging
acceptable?

**A1 (as posted).** "Yes, the ability to respond to all types of attacks would
be beneficial. Assuming autonomous (with human oversight) and automation (human
oversight); then there is the goal to have autonomous detection and autonomous
responses presented to a human for course of action decision selection."
