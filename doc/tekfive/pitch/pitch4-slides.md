---
marp: true
theme: uncover
size: 16:9
math: mathjax
paginate: true
footer: "TekFive - AutonomousTrust"
style: |
    section {
        font-size: 30px;
        text-align: left;
    }

    section h1 {
        text-align: center;
        font-size: 50px;
    }

    section h2 {
        text-align: center;
        font-size: 40px;
    }

    section.title {
        --title-height: 130px;
        --subtitle-height: 70px;

        overflow: visible;
        display: grid;
        grid-template-columns: 1fr;
        grid-template-rows: 1fr var(--title-height) var(--subtitle-height) 1fr;
        grid-template-areas: "." "title" "subtitle" ".";
    }

    section.title h1,
    section.title h2 {
        margin: 0;
        padding: 0;
        text-align: center;
        height: var(--area-height);
        line-height: var(--area-height);
        font-size: calc(var(--area-height) * 0.7);

        /* border: 1px dashed gray; debug */
    }

    section.title h1 {
        grid-area: title;
        --area-height: var(--title-height);
    }

    section.title h2 {
        grid-area: subtitle;
        --area-height: var(--subtitle-height);
    }

    section.small {
        font-size: 24px;
    }

    section.split {
        overflow: visible;
        display: grid;
        grid-template-columns: 500px 500px;
        grid-template-rows: 100px auto;
        grid-template-areas:
            "slideheading slideheading"
            "leftpanel rightpanel";
    }
    /* debug
    section.split h3,
    section.split .ldiv,
    section.split .rdiv { border: 1.5pt dashed dimgray; }
    section.split h3 {
        grid-area: slideheading;
        font-size: 50px;
    }
    section.split .ldiv { grid-area: leftpanel; }
    section.split .rdiv { grid-area: rightpanel; }*/
---
<!-- _class: title -->
<!-- _footer: "" -->
<!-- _paginate: false -->
![bg left:40% 80%](./t5logo.png)
# **AutonomousTrust** <!--fit-->

## Machines that earn, evaluate, and enforce trust with each other <!--fit-->

---
# Problem Statement

Machine-to-machine cybersecurity is brittle and non-scalable.

**Target domain:** Industrial Internet of Things (IIoT)
* resource constrained (power, bandwidth)
* massive scale (billions of devices)
* autonomous/independent operation
* in-situ sensing/controlling (edge vs cloud)
* software vulnerabilities now risk **human safety**

Solutions here apply broadly — IoT represents the computational extremes.

---
# Why Zero Trust Falls Short

The industry standard for M2M security:

* **identity** — service accounts, workload IDs
* **authentication** — mTLS, certificates, API keys
* **session length** — per-request or short-lived tokens
* **authorization** — service health, image signature, network path

Assumes a consumerist paradigm. Lacks dynamic response, difficult to scale, and configuration is brittle — fundamentally non-scalable against evolving topologies and threat vectors.

---
# Proposed Solution

Dynamic machine cooperation, enabled by:

* real-time distributed **reputation** tracking
   * trust metric based on immutable interaction scores
   * **contract** negotiation protocols govern interactions
      * work definition
      * work confirmation / **reality testing**
   * bootstrapping / fallback
* remote service discovery
* directly affects network topology
* adjustable max-risk evaluation

---
# The Product

A system-engineering framework — more like running containerized services than linking a library.

**Services:**
* reputation distributed ledger and protocols
* contract negotiation protocol
* hierarchical social mechanisms

**Development tools:**
* knowledge domain encoding toolset
* reality testing framework
* zk-STARK/rollup toolset

Open source framework; our commodity is expertise in building these networks.

---
# Deployment

Depending on desired level of control:

* **Cloud cluster:** ingress/egress control plus micro-service support
* **Edge host:** kernel drivers plus active services

Development toolsets for both. Deployment as relocatable containers, VMs, or monolithic embedded kernels.

---
# Technical Details

* identity: unique, immutable, tied to reputation
* trust scores on a distributed ledger
* interaction scores: $R_x = \sum\limits_{i=1}^n \frac{S_x^i R_i^\prime}{n}$ where $R_i^\prime$ is the previous $R_i$ ($S$ is individual score, $R$ is accumulated reputation)
* bootstrap when $R_x^\prime \lt 0.5$:  $R_x = R_x^{\prime\prime}$ where $R_x^{\prime\prime}$ is the TFT sum
* **computable** data verified via zk-STARKs and zk-rollups
* **observable** data validated via coincident multi-modal consensus
* socially-determined hierarchical networking/routing

---
# Use Cases

* **Sensor Networks**
   * in-situ inputs, flexible controls, environmental response
   * collective action despite prolific failures and attacks
   * original inspiration — ground-truth is inherently difficult

* **AI Safety and Knowledge Integrity**
   * verify data provenance, resist adversarial inputs at scale
   * maintain knowledge-base quality amid active sabotage

* **Defense**
   * multi-modal sensors, situational awareness in contested environments
   * vet and winnow datastreams — cut through the fog of war

---
# Open Questions

* resilience to **network attacks** (DoS, partitioning, selective dropping)
* resilience to **epistemic attacks** (data poisoning, coordinated false consensus)
* **social/Sybil attacks** (identity fabrication, collusion, isolation, turncoats)
* knowledge domain failures
* contractual failures
* **fault tolerance limits** — can a small cadre detect truth within overwhelming error?

---
# Market Competitors

<!-- _class: small -->

No products approximate our full approach, but some address certain facets:

* **Proofpoint Dynamic Reputation** — ML content classification with reputation scores for email connections
* **Microsoft Defender Threat Intelligence** — per-machine reputation scores (0-100) via ML and algorithms
* **Bitdefender Reputation Threat Intelligence** — real-time M2M threat APIs for files/IPs, reputation-based
* **OpenText Threat Intelligence (BrightCloud)** — ML plus reputation scoring for websites, files, IPs
* **DeepTrust** — real-time detection of AI threats (deepfakes, voice phishing)

Academic: **M2M-REP** — distributed trustworthiness for autonomous IoT without central authority

---
# Prototype Demo

