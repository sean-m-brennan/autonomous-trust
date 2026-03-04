# Automating Machine Trust

## Problem statement

Cybersecurity vulnerabilities present a major risk in machine-to-machine supersystems such as Cloud services and AI collaboration. This is especially pernicious for Internet of Things (IoT), Industrial IoT (IIoT), and smart infrastructure due to tighter compute and bandwidth constraints, increased scale, increased autonomy, and subsequent difficulty in security administration. With the crossover into online physical controllers, software vulnerabilities can (and do) now risk human safety.

### Machine to Machine

We focus on IoT challenges and solutions because of the computational extremes they represent in terms of scale (billions of devices) and restrictions (on power and bandwidth), and a corresponding need for simplicity and autonomy. The security lessons-learned here apply broadly, however. Note that Zero Trust techniques for machines: service accounts, keys and certificates, short-lived tokens, etc. are, by themselves, fundamentally non-scalable both in terms of a rapidly evolving network topology and dynamic threat vectors.


## Proposed Solution

We contend that security mitigation is insufficient. If physical deployment scales linearly, interaction complexity scales exponentially. Anywhere a human is in the loop making security decisions is going to be moving in slow motion, resulting in delayed, necessarily reactive responses, and actually increases risk. This calls for a proactive, rapid-fire, machine-led approach.

Therefore, as opposed to relying on growing authorization lists and numerous software patches, we propose a dynamic inter-machine trust metric and machine-social protocols that regulate this metric to ensure secure communications, tasking and cooperation. 

### Approach

To facilitate such cooperation, a community of systems can track participant reputation to guide interactions. At a technical level, this is implemented with a distributed ledger of interaction scores which are combined via a formula akin to PageRank.

Arriving at interaction scores then is a key component, both to the functionality of the reputation system and to bootstrapping a reputation to begin with. Negotiating a domain-specific contract may specify the parameters of this score, but how do we ensure the contract is useful?

In answering this, let's refer to the participants of the contract as the producer and the consumer. The consumer needs to be able to determine if the producer's data is true, and preferably quantify it's level of truth (or non-faultiness). Let's divide the data received by the consumer into two natural types: computable and observable. Most data is likely to be a hybrid of the two.

Purely computable data can be proven and verified through zk-STARKS (zero-knowledge Scalable Transparent Argument of Knowledge) protocol. This protocol allows the consumer to verify that the producer's data is correct (per the contract) using a short proof without any trusted setup or secret knowledge. This approach works for this data type because the executed function code is an embedded part of the STARK.

Data derived from sources that themselves utilize zk-STARKS can be efficiently proven collectively through a zk-rollup.

Observable data is rather different, however. While a producer's handling of observations in code can be covered by a STARK, so very many potential faults in the hardware and external environment are either unobservable, or equally require validation themselves. The key here is to remember that we are not limited to just one producer and one consumer. Multi-modal validation aims to utilize time and space coincidence across numerous sensing modalities to confirm the presence and parameters of a phenomenon. We can apply this context-based concept beyond mere sensory detection to a variety of knowledge inputs, and arrive at data-source consensus under most domains. In the AI realm, this may be called the ground-truth dataset.

But what do we do when honest sources are out-numbered - when the truth is scarce?


### Goals

We believe that the solution to this problem of determining the truth of a statement involves a two-pronged approach: individualized reality testing and machine-social cooperation. Our goal is to demonstrate the feasibility of this approach to eliminate useless or even harmful chaff from dynamic datasets.

For reality testing, we postulate a case-based reasoning (CBR) approach, enhanced by machine-learning flexibility and alternative-solution fitting. Classic CBR runs a four-step process on stored rulesets (namely retrieve, reuse, revise, and retain) to determine responses to novel-but-related situations. In contrast, our reasoning approach will use domain-specific machine learning (ML) to select multiple situational signatures (in the form of knowledge graphs) from memory, fit them against the current situation, and derive a truth metric on the current input (a hybrid of transductive and inductive methods).

Machine-social cooperation consists of sharing both data and conclusions concisely and verifiably. Using zk-STARKS and reputation as outlined above, full attribution and accountability can be maintained in the building blocks of the knowledge base of both component systems and the system-of-systems as a whole. These two prongs together, we hypothesize, will yield a mechanism for collective knowledge hygiene wherein flawed or inaccurate data is winnowed away, and faulty or malignant sub-systems are excluded. We intend to demonstrate this capability by introducing both poor data and troublesome participants in a model of a networked system. We will also test the extent of this fault tolerance in the face of massively widespread faults - can a very small cadre detect truth within overwhelming error? If so, where are the limits?


## The Product

We are endeavoring to create a new highly-networked computational system-engineering framework that directly addresses security and knowledge acquisition head-on. From a developer's point of view, incorporating this framework is more akin to running containerized services than merely linking in a library. Developers would define a custom knowledge domain, decision-making callbacks, and input-disseminating code, all plugged into our multiprocessing scaffold that configurably handles networking, encryption, identity, reputation and negotiation. Deployment can be in the form of relocatable containers or virtual machines, or monolithic embedded kernels tied to specific hardware.

This is intended as distributed, decentralized, independent system-of-systems, so command and control (more like suggest and request) requires trusted interface nodes. Our code base includes facilities for users to visualize and interact with the overall system through such entry points. Each (human) user is also peer on the network with a trust rating, thus different users automatically have different reach into the network based on their trustworthiness. There are no backdoors, all trust must be earned through honest interaction.

## Steps to Product Realization

The road to creating this product involves engineering challenges to efficiently implement the following tightly interdependent sub-systems (none of these are COTS components):
* reputation distributed ledger and protocols
* knowledge domain encoding toolset
* contract negotiation protocol
* zk-stark/rollup toolset
* reality testing framework
* hierarchical social mechanisms

Note the strong dependencies: reputation tracking is required for any socialization, knowledge encoding is required for contracts and validation, etc. We intend to publish our code that implements the above modules as open source. This code is really just a framework, or toolset with which to construct a necessarily custom solution tailored to a customer's specific needs. Our saleable commodity, therefore, is our unique expertise and support in building these extremely complex networks.

## Potential Market

The two examples mentioned, namely AI learning and in-situ sensing, can clearly benefit from this product. The latter example is the original domain that inspired our work, due to the inherent and pervasive difficulty in establishing ground-truth. Contrary to the current state-of-the-art, our product would allow sensor networks to collectively provide more and better information despite prolific communication, sensing and computation failures, and physical and network attacks, without expensive hardware redundancy.

In the case of the former example, our proposed system could be centralized, but virtually distributed by spawning a new subsystem for every new data source encountered, to stand or fall on its own merits. In this way, a growing AI could safely be set loose on the Internet, even interacting with random humans, continually maintaining the quality of its own knowledge base even in the midst of active sabotage.

While many fields might benefit from the fully autonomous security of our product, the most arduous and demanding arena is that of the deployed warfighter. On the increasingly electronics-enhanced battlefield, access alone guarantees neither a good dataset nor a friendly one, and assessing the meaning and value of incoming information must be lightning fast. As always, the fog of war is not a dearth of information, but an overabundance, much of it irrelevant or false, such that meaning is lost. As a companion for the warfighter, our proposed system would vet and winnow datastreams to those that are the most accurate and relevant, while not necessarily discarding conflicting information. Additionally, as secure uplinks are available, more datastreams and resources can be automatically incorporated. This would yield a coherent, agile, multi-modal view of the changeful battlefield in real time, maximizing warfighter decision-making and response capabilities.

## Market Competitors

There are no products that approximate our approach, but there are products that utilize some aspects:

1. Proofpoint® Dynamic Reputation (PDR)

   An email reputation and connection management service that uses machine-learning driven content classification to determine which IP addresses may be malicious (part of a botnet) for the purpose of blocking or delaying connections.

   Relevance: This is a clear example of using a dynamic reputation score calculated by machines (machine learning) to determine the trustworthiness (security) of another machine (an IP sending email) in a network communication paradigm.

2. Microsoft Defender Threat Intelligence (Defender TI)

   A comprehensive security solution that provides proprietary reputation scores (from 0 to 100) for hosts, domains, and IP addresses based on a series of algorithms and machine learning rules to quantify security risk.

   Relevance: This is a commercially available system that dynamically assesses the trustworthiness of entities (which are effectively machines/infrastructure) using a reputation score based on observed malicious activity and machine learning

3. Bitdefender Reputation Threat Intelligence Services 

   Offers various real-time threat intelligence feeds and APIs (including IP Reputation and File Reputation) that are explicitly designed for M2M (machine-to-machine) integration and leverage data from a massive global sensor network.

4. OpenText™ Threat Intelligence (BrightCloud)

   A service that uses machine learning and reputation scoring to assess websites, files, and IP addresses for malicious activity, offering real-time threat blocking capabilities.


5. DeepTrust

   real-time protection against AI-driven threats, specifically focusing on deepfakes, voice phishing (vishing), and social engineering


In the academic realm, at least one paper describes a similar system:  

1. M2M-REP

   calculate the "trustworthiness" of autonomous IoT devices without relying on a central authority and while protecting the privacy of the participants who provide feedback.

