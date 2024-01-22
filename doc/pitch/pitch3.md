Problem statement
-----------------

When any two computing systems interact, there is a strong implicit question of trustworthiness.
As we rely more heavily on such systems, this question becomes increasingly imperative, and explicit, but is largely unsolved for autonomous systems of systems.

Two examples illustrate the issue:

 - First, continuously-improving Machine Learning/Artificial Intelligence systems ingest inputs from a massive variety of sources - probably *most* of which are untrustworthy - with no automatic means of determining suitability.
Even when not under attack, this often yields an AI that is continuously degrading instead.

 - Second, in-field sensors - even when secure - are subjected to conditions that can seriously hamper their observation, computation, and communication capabilities.
The degree of faulty or untimely data is not readily apparent to human operators, much less autonomous systems.

When even the controlled environment of the laboratory can yield the unexpected, how do we arm computing platforms to face the hostile world?

Research Approach
-----------------

A system of systems assumes a minimum level of cooperation - clearly, full paranoia leads to system isolation.
To facilitate such cooperation, a community of systems can track participant reputation to guide interactions.
At a technical level, this is implemented with a distributed ledger of interaction scores which are combined via a formula akin to PageRank.

Arriving at interaction scores then is a key component, both to the functionality of the reputation system and to bootstrapping a reputation to begin with.
Negotiating a domain-specific contract may specify the parameters of this score, but how do we ensure the contract is useful?

In answering this, let's refer to the participants of the contract as the producer and the consumer.
The consumer needs to be able to determine if the producer's data is true, and preferably quantify it's level of truth (or non-faultiness).
Let's divide the data received by the consumer into two natural types: computable and observable.
Most data is likely to be a hybrid of the two.

Purely computable data can be proven and verified through zk-STARKS (zero-knowledge Scalable Transparent Argument of Knowledge) protocol.
This protocol allows the consumer to verify that the producer's data is correct (per the contract) using a short proof without any trusted setup or secret knowledge.
This approach works for this data type because the executed function code is an embedded part of the STARK.

Data derived from sources that themselves utilize zk-STARKS can be efficiently proven through a zk-rollup.

Observable data is rather different, however.
While a producer's handling of observations in code can be covered by a STARK, so very many potential faults in the hardware and external environment are either unobservable themselves or we recurse back to the original problem of validating observables.

The key here is to remember that we are not limited to just one producer and one consumer.
Multi-modal validation aims to utilize time and space coincidence across numerous sensing modalities to confirm the presence and parameters of a phenomenon.
We can apply this context-based concept beyond mere sensory detection to a variety of knowledge inputs, and arrive at data-source consensus under most domains.
In the AI realm, this may be called the ground-truth dataset.

But what do we do when honest sources are out-numbered - when the truth is scarce? 

Research Goal
-------------

We believe that the solution to this problem of determining the truth of a statement involves a two-pronged approach: individualized reality testing and machine-social cooperation. 
Our goal is to demonstrate the feasibility of this approach to eliminate useless or even harmful chaff from dynamics datasets.

For reality testing, we postulate a case-based reasoning (CBR) approach, enhanced by machine-learning flexibility and alternative-solution fitting.
Classic CBR runs a four-step process on stored rulesets (namely retrieve, reuse, revise, and retain) to determine responses to novel-but-related situations.
In contrast, our reasoning approach will use domain-specific machine learning (ML) to select multiple situational signatures from memory, fit them against the current situation, and derive a truth metric on the current input (a hybrid of transductive and inductive methods).

Machine-social cooperation consists of sharing both data and **

These components together, we hypothesize, will yield ** 

The Product
-----------

We are endeavoring to create a new computational system that **

Steps to Product Realization
----------------------------

The road to creating this product involves engineering challenges to efficiently implement the following tightly interdependent sub-systems (none of these are COTS components):
 - reputation distributed ledger and protocols
 - knowledge domain encoding toolset
 - contract negotiation protocol
 - zk-stark/rollup toolset
 - reality testing framework
 - hierarchical social mechanisms

Note the strong dependencies: reputation tracking is required for any socialization, knowledge encoding is required for contracts and validation, etc. 

We intend to publish our code that implements the above modules as open source. 
This code is really just a framework, or toolset with which to construct a *necessarily* custom solution tailored to a customer's specific needs.
Our product, therefore, is effectively our expertise and support in building these extremely complex networks.

Potential Market
----------------

**
