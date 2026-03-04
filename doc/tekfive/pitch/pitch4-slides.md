---
marp: true
theme: uncover
size: 16:9
math: mathjax
paginate: true
footer: "TakFive - AutonomousTrust"
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

## Machine-to-Machine Security <!--fit-->

---
# Problem Statement

Target domain: Industrial Internet of Things (IIoT)

* resource constrained
* large scale
* autonomous/independent
* in-situ sensoring/controlling (edge vs cloud)

Cybersecurity is therefore extra challenging, and imperative.

However, solutions here should (ideally) apply elsewhere.

---
# Industry Standard
## Machine-to-Machine Zero Trust

Centered around service APIs - assumes consumerist paradigm

* **identity** - service account / workload id
* **authentication** - mTLS, digital certificates, API keys
* **session length** - per-request or very short-lived tokens
* **authorization** - service health, image signature, network path

Lacking dynamic response, difficult to scale, and configuration is brittle

---
# Proposed Solution

Dynamic machine cooperation, enabled by:

* real-time distributed reputation tracking
   * trust metric based on immutable interaction scores
   * contract negotiation protocols govern interactions
      * work definition
      * work confirmation / reality testing
   * bootstrapping / fallback
* remote service discovery
* directly affects network topology
* adjustable max-risk evaluation

---
# Details

* identity: unique, immutable, tied to reputation
* trust scores on a distributed ledger
* interaction scores: $R_x = \sum\limits_{i=1}^n \frac{S_x^i R_i^\prime}{n}$ where $R_i^\prime$ is the previous $R_i$ ($S$ is individual score, $R$ is accumulated reputation)
* bootstrap when $R_x^\prime \lt 0.5$:  $R_x = R_x^{\prime\prime}$ where $R_x^{\prime\prime}$ is the TFT sum
* work confirmation via zk-STARKs, zk-rollups, and/or coincident multi-modal validation
* socially-determined hierarchical networking/routing

---
# The Product

Tightly interdependent subsystems:

Services:
* reputation distributed ledger and protocols
* contract negotiation protocol
* hierarchical social mechanisms

Development tools:
* knowledge domain encoding toolset
* reality testing framework
* zk-stark/rollup toolset

---
# Deployment

Depending on desired level of control:

* Cloud cluster: ingress/egress control plus micro-service support
* Edge host: kernel drivers plus active services 

Development toolsets for both

---
# Use-cases

* Industrial instrumentation
   * emphasis on flexible controls and environmental response
   * in-situ inputs, limited outputs
   * mostly communal action

* AI safety
   * emphasis on data correctness and context
   * widely varying global inputs

* Robotics
   * emphasis on multi-modal sensors and situational awareness
   * in-situ inputs, varying outputs
   * mostly independent action

---
# Unknowns

* resilience to network attacks (DoS, Sybils)
* resilience to epistemic attacks (data poisoning, noise injection)
* novel social attacks (isolation, turncoats)
* knowledge domain failures
* contractual failures

---
# Market Competitors

<!-- _class: small -->

No products approximate our solution, but some approach certain facets:

* Proofpoint Dynamic Reputation
   email connection management using ML content classification with a reputation score

* Microsoft Defender Threat Intelligence
   per machine reputation scores determined by ML and other algorithms

* Bitdefender Reputation Threat Intelligence
   real-time threat APIs for files/IPs, also reputation-based

* OpenText Threat Intelligence (BrightCloud)
   ML plus reputation scoring for websites, files, IPs

* DeepTrust
   real-time detection of AI threats (deepfakes, voice phishing)

---
# Prototype Demo
