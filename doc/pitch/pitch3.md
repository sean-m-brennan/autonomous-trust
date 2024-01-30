# Automating Machine Trust

## Problem statement

When any two networked systems interact, there is a strong implicit question of trustworthiness.
As we rely more heavily on distributed computing, this question becomes increasingly imperative, and explicit, but is largely unsolved for autonomous systems-of-systems.

Two examples illustrate the issue:

 - First, continuously-improving Machine Learning/Artificial Intelligence systems ingest inputs from a massive variety of external sources - probably *most* of which are untrustworthy - with no automatic means of determining suitability.
Even when not under attack, this often yields an AI that is continuously degrading instead.

 - Second, autonomous in-field sensors - even when physically secure - are subjected to conditions that can seriously hamper their observation, computation, and communication capabilities.
The degree of faulty or untimely data is not readily apparent to human operators, much less an autonomous system.

Even the controlled environment of the laboratory can yield the unexpected, so how do we arm computing platforms to face the hostile world?

## Research Approach

A system-of-systems must have a minimum level of cooperation among its components to function - full paranoia leads to component isolation.
To facilitate such cooperation, a community of systems can track participant reputation to guide interactions.
At a technical level, this tracking can be implemented with a distributed ledger of interaction scores which are combined via a formula akin to PageRank.

Arriving at interaction scores then is a key component, both to the functionality of the reputation system and to bootstrapping an initial reputation.
Negotiating a domain-specific interaction contract may specify the parameters of this score, but how do we ensure the contract is useful?

In answering this, let's refer to the participants of the contract as the producer and the consumer.
The consumer needs to be able to determine if the producer's data is true, and preferably quantify it's level of truth (or non-faultiness).
Let's divide the data received by the consumer into two natural types: computable and observable.
Most data is likely to be a hybrid of the two.

Purely computable data can be proven and verified through a zk-STARK (zero-knowledge Scalable Transparent Argument of Knowledge) protocol.
This protocol allows the consumer to verify that the producer's data is correct (per the contract) using a short proof without any trusted setup or secret knowledge.
This approach works for this data type because the executed function code is an embedded part of the zk-STARK.
Data derived from sources that themselves utilize zk-STARKs can be efficiently proven collectively through an abbreviated construct known as a zk-rollup.

Observable data is rather different, however.
While a producer's handling of observations in code can be covered by a zk-STARK, so very many potential faults in the hardware and external environment are either unobservable, or equally require validation themselves.

The key here is to remember that we are not limited to just one producer and one consumer.
The technique of multi-modal validation aims to utilize time and space coincidence across numerous sensing modalities to confirm the presence and parameters of a phenomenon.
We can apply this context-based concept beyond mere sensory detection to a variety of knowledge inputs, and arrive at data-source consensus under most domains.
In the AI realm, this may be called the ground-truth dataset.

But what do we do when honest sources are out-numbered - when the truth is scarce? 

## Research Goal

We believe that the solution to this problem of determining the truth of a statement involves a two-pronged approach: individualized reality testing and machine-social cooperation. 
Our goal is to demonstrate the feasibility of this approach to eliminate useless or even harmful chaff from dynamic datasets.

For reality testing, we postulate a case-based reasoning (CBR) approach, enhanced by machine-learning flexibility and alternative-solution fitting.
Classic CBR runs a four-step process on stored rulesets (namely retrieve, reuse, revise, and retain) to determine responses to novel-but-related situations.
In contrast, our reasoning approach will use domain-specific machine learning (ML) to select multiple situational signatures (in the form of knowledge graphs) from memory, fit them against the current situation, and derive a truth metric on the current input.
This is a hybrid of transductive and inductive methods.

Machine-social cooperation consists of sharing both data and conclusions concisely and verifiably.
Using zk-STARKs and reputation as outlined above, full attribution and accountability can be maintained in the building blocks of the knowledge base of both component systems and the system-of-systems as a whole.

These two prongs together, we hypothesize, will yield a mechanism for collective knowledge hygiene wherein flawed or inaccurate data is winnowed away, and faulty or malignant sub-systems are excluded.
We intend to demonstrate this capability by introducing both poor data and troublesome participants in a model of a networked system.
We will also test the extent of this fault tolerance in the face of massively widespread faults - can a very small cadre detect truth within overwhelming error?
If so, where are the limits?

If our hypothesis is correct, we anticipate that reality-testing refinement will be the subject of ongoing research and development.
We will also be continuously exploring mitigations for machine-social deception as well as more classic security vulnerabilities. 

## The Product

We are endeavoring to create a new highly-networked computational-system engineering framework that directly addresses security and knowledge acquisition head-on.
The three key features our framework enables are:
 - reputation-staked distributed consensus
 - negotiated, contractual services
 - reality-testing with qualitative divergence detection

These features form the basis of a distributed operating system, a substrate which allows individual apps to dynamically form up a coalition, execute a task, and disband.   

From a developer's point of view, incorporating this framework is more akin to running containerized services rather than merely linking in a library. 
Developers would define a custom knowledge domain, decision-making callbacks, and input-disseminating code, all plugged into our multiprocessing scaffold that configurably handles networking, encryption, identity, reputation and negotiation.
Deployment can be in the form of relocatable containers or virtual machines, or monolithic embedded kernels tied to specific hardware.

This is intended as distributed, decentralized, independent system-of-systems, so command and control (more like suggest and request) requires trusted interface nodes. 
Our code base includes facilities for users to visualize and interact with the overall system through such entry points.
Each (human) user is also peer on the network with a trust rating, thus different users automatically have different reach into the network based on their trustworthiness.
There are no backdoors, all trust must be earned through interaction.

Note that despite the potential presence of users, this is primarily a machine-social network.

## Steps to Product Realization

The road to creating this product involves engineering challenges to efficiently implement the following tightly interdependent sub-systems (none of these are COTS components):
 - reputation distributed ledger and protocols
 - knowledge domain encoding toolset
 - contract negotiation protocol
 - zk-STARK/rollup toolset
 - reality testing framework
 - hierarchical social mechanisms

Note the strong dependencies: reputation tracking is required for any socialization, knowledge encoding is required for contracts and validation, etc. 

We intend to publish our code that implements the above modules as open source. 
As noted previously, this code is a framework, or toolset with which to construct a *necessarily* custom solution tailored to a customer's specific needs.
Our saleable commodity, therefore, is our unique expertise and support in building these extremely complex networks.

## Potential Market

The two examples mentioned, namely AI learning and in-situ sensing, can clearly benefit from this product.
The latter example is the original domain that inspired our work, due to the inherent and pervasive difficulty in establishing ground-truth.
Contrary to the current state-of-the-art, our product would allow sensor networks to collectively provide more and better information despite prolific communication, sensing and computation failures, and physical and network attacks, without expensive hardware redundancy. 

In the case of the former example, our proposed system could be centralized, but virtually distributed by spawning a new subsystem for every new data source encountered, to stand or fall on its own merits.
This would allow a growing AI to safely use arbitrary Internet sources, even interacting with random humans, while continually maintaining the quality of its own knowledge base, even in the midst of active sabotage.

While many fields might benefit from the fully autonomous security of our product, the most arduous and demanding arena is that of the deployed warfighter.
On the increasingly electronics-enhanced battlefield, access alone guarantees neither a good dataset nor a friendly one, and assessing the meaning and value of incoming information must be lightning fast.
The modern fog of war is an overabundance of information (rather than a lack of it), much of it irrelevant or false, such that meaning is lost.
As a companion for the warfighter, our proposed system would vet and filter datastreams to those that are the most accurate and relevant, while not necessarily discarding conflicting information.
Additionally, as secure uplinks are available, more datastreams and resources can be automatically incorporated.
This would yield a coherent, agile, multi-modal view of the changeful battlefield in real time, maximizing warfighter decision-making and response capabilities.

## Market Competitors

None.
While some individual portions of this system are apparent in recent scientific literature, there is no product anywhere that provides our combination of reputation-based consensus, negotiated contracts, and divergence detection.

