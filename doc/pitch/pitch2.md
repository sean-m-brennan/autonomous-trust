Technical Innovation
--------------------

We are interested in secure distributed computing systems that scale nationally, and even globally.
Autonomous Trust is akin to a distributed operating system: it is a computational framework (runtime environment, APIs, messaging protocols) that ensures scalable security (resistant to incursion, resource loss, data leaks) through communities of cooperative processes.
Utilizing a variety of distributed consensus algorithms, Autonomous Trust automatically handles the different machine-social phases such as bootstrapping, haggling for services, confirming work completed, and remote service discovery.
Processes compute not only their primary service, but also their relationships with their peers.
AutonomousTrust is different in that after development, deployed processes are fully autonomous.
Similar to how Kubernetes manages Docker containers in the Cloud, our environment consists of virtual machines running unikernel apps.
These apps publish protocols that define the services they provide and the conditions for accessing those services. 
Some processes may act as frontends offering user interfaces, but most will be backend service providers and consumers - but all processes will be subject to the trust metric.
Cooperation is enforced through decentralized, public reputation tracking.
Anti-social behavior is rapidly detected and excluded from the machine-social network.

Much like in human society, AutonomousTrust machine-society tracks trustworthiness through reputation.
Individual transactions are immutably scored by both participants and the scores are recorded in a public ledger.
When deciding whether to transact with a peer, a process computes a reputation for that peer.
A given process' reputation is computed by averaging all peer scores for that process, weighted by that peer's reputation.
Processes use this metric to evaluate risk, and are free to refuse service if that risk is too high.
If peer reputation falls too low (or for peers that initially have little or no reputation), an alternate mode of interaction engages - each individual transaction (inherently high risk) is make-or-break and that peer must be on its best behavior.
Further reputation decrease may result in that peer being kicked off the network entirely.
This requires process identity to be immutable of course.
While any process can join a cohort, building reputation is a long, expensive process.
Clearly, active and continual self-defense-in-depth is a critical component of this system.
Our API gives developers every opportunity to shut down detrimental interactions.

AutonomousTrust is unique in that no process has inherent trust - even if it is on the same machine, comes from the same vendor, or is run by the same user.
All interactions are vetted.
Yet, while the overhead of this protection is minimal, the benefit is community-wide.
Peers may lie, but because the reputation scoring algorithm doubts the truth of each transaction score, such lies are discoverable and themselves become public knowledge.
Large groups of peers may falsify transactions - fooling the reputation system.
Protecting against this problem is one of the most interesting research questions with respect to AutonomousTrust.
We believe that a very large scale hierarchy can guard against that scenario, but there are nuances to explore. 


Technical Objectives and Challenges
-----------------------------------

Security is our core focus with AutonomousTrust.
Therefore, we will primarily be establishing the systems' robustness against attacks.
As mentioned in the previous section, multi-participant attacks (conspiracies) are the most likely attacks to succeed - at least on paper.
In small machine-social groups this is likely true, but large groups require ever greater effort to maintain a conspiracy - tweaks and adjustments to reputation may be required.

As Bitcoin has found, singular transaction ledgers are not particularly scalable, and scalability is our secondary focus.
Sharding ledgers through the use of snarks is the cutting-edge for cryptocoins - but our transactions are self-validating (both participants must sign), so the full, expensive power of zero-knowledge proofs is not required.
We can likely get away with nested Merkle-trees that track chained hashes of transaction summaries and are validatable to multiple levels even down to an original transaction.

Our third objective is to implement a coherent demonstration with which to guide potential customers through the utility and features of AutonomousTrust.
To that end, the battlefield is the ultimate environment where security, adaptability and rapid determination of trust is the difference between success and failure.
In the combat scenario, an elite squad is tasked with finding and destroying an elusive mobile enemy asset.
A large reconnaissance and communications drone circles out of sight above the team, a handful of micro-drones precede the team in the treetops, and LEO satellites provide an emergency comm uplink.
A Predator-class drone is set to come in at the last minute to engage the target, so that the squad (operating behind enemy lines) is never exposed.
Additionally, other on-site sensory/computing systems, either planted or hacked, may provide helpful intel.
All the tech described is running AutonomousTrust.
Coordinating all these disparate piece of tech dynamically would normally be extremely difficult especially given the time constraints, and especially is the hardware crosses boundaries between military branches.
Under this scenario, as the mission proceeds, everything goes wrong.
The Predator arrives early and is acting erratically; conclusion: it ground-control link is compromised, and the recon drone uses constant electronic countermeasures to neutralize its threat potential before it is even fully in range.
The on-site systems yield inconsistent sensory data; some of these systems are clearly captured and don't even enter the network, but others are more subtly tainted and it's not clear which.
Using known-trustable real-time observables from the accompanying micro-drones as a test comparator, the overall system is able to weed out the untrustworthy participants and conclusively identify the target.
A focused sat call brings a piloted jet fighter; and in a single looping pass, target data is transmitted, weapons engaged, and the asset destroyed.
The combat squad on the ground never directly engaged the enemy.
This scenario is impossible to implement in today's DoD, and for good reason: current techniques to achieve such results would open gaping security holes.
We intend to show that AutonomousTrust can facilitate the rapid-fire decision-making and eerily fast but secure communications embodied in the above scenario.


Market Opportunity
------------------

Clearly the DoD scenario above is well suited for SOCOM (joint-branch) missions, wherein heterogeneous hardware, software, procedures, etc. can be amalgamated without loss of autonomy and ownership. 
The same not-invented-here attitude is endemic throughout the federal agencies (many such cases in DOE, for example), but AutonomousTrust can be a means by which inter- and intra-agency cooperation can be achieved securely, scalably, and efficiently without violating institutional stovepipes.

This fostering of cooperation while respecting boundaries is also readily applicable in business-to-business relationships.
Consider the 2019-20 SunBurst software supply chain attack via the SolarWinds Orion network administration tool; in this hack, the primary security hurdle was in gaining access to the SolarWinds developer network.
The subsequent binary injection into the Orion codebase, and release to customers went undetected for a year - and was only discovered by a security research firm.
AutonomousTrust running the development tools would not have allowed the injection, and would have identified the presence of a bad actor.
A client of SolarWinds' that was running AutonomousTrust would have noticed and shut down the attempts by the modified Orion software to phone home and upload private data.

Commerce requires cooperation, but often digital trust must be just assumed.
Merely verifying an identity only goes so far, attested to by the explosion of KYC.
Is this really my customer/bank/vendor?
They promised X, but will they really deliver?
If AutonomousTrust can take the guesswork and uncertainty out of transactions, the potential market for our product is enormous. 


Company and Team
----------------

Founded in 2007, TekFive is a veteran-owned, veteran centric, innovative and agile services company.
We provide comprehensive federal IT domain experience, while offering the latest commercial industry insight, a highly motivated full-stack development team and a network of successful industry partners to rapidly respond to your enterprise IT challenges.

Sean Brennan is the principal investigator for this effort.
He has over 20 years of research and engineering experience, specializing in large-scale, resource-constrained networks and software correctness.
He has been involved in 12 DOE-funded projects related to nuclear nonproliferation, and was the technical lead for five of these.
Dr. Brennan received a Ph.D. in Computer Science from the University of New Mexico, and is an author on 15 published papers.

Corey Baswell is TekFive's Chief Technology Officer.
He has over 20 years of enterprise IT experience as a full stack engineer in the areas of application development, enterprise architecture, and platform development.
He has developed numerous enterprise software services including the NASA OpenESB, the NASA and VA DevSecOps pipeline, the NASA and VA Pulse app analytics, and the NASA Application Portfolio Management tool.
Mr. Baswell received a Bachelor of Science degree in Computer Engineering from Auburn University where he graduated summa cum laude.


